package build

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/konflux-ci/e2e-tests/pkg/framework"
	"github.com/konflux-ci/e2e-tests/pkg/utils/build"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/openshift/library-go/pkg/image/reference"
	tektonpipeline "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

const konfluxInfoNamespace = "konflux-info"
const clusterConfigConfigMapName = "cluster-config"

func IsSigstoreDeployed(c crclient.Client) bool {
	var sigstoreServices = []crclient.ObjectKey{
		{Namespace: "fulcio-system", Name: "fulcio-server"},
		{Namespace: "rekor-system", Name: "rekor-server"},
		{Namespace: "tuf-system", Name: "tuf-server"},
	}

	for _, key := range sigstoreServices {
		if err := c.Get(context.Background(), key, &corev1.Service{}); err != nil {
			GinkgoWriter.Printf("sigstore service %s/%s is not available: %v\n", key.Namespace, key.Name, err)
			return false
		}
	}
	return true
}

func getClusterOIDCIssuer(f *framework.Framework) string {
	path := "/.well-known/openid-configuration"
	raw, err := f.AsKubeAdmin.CommonController.KubeInterface().Discovery().RESTClient().Get().AbsPath(path).DoRaw(context.Background())
	Expect(err).ShouldNot(HaveOccurred())

	var issuer string
	err = json.Unmarshal(raw, &issuer)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(issuer).ShouldNot(BeEmpty())
	return issuer
}

func konfluxCR() *unstructured.Unstructured {
	cr := &unstructured.Unstructured{}
	cr.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "konflux.konflux-ci.dev",
		Version: "v1alpha1",
		Kind:    "Konflux",
	})
	cr.SetName("konflux")
	return cr
}

func EnableKeylessSigning(c crclient.Client) {
	setKeylessSigning(c, true)
	GinkgoWriter.Printf("Keyless signing enabled\n")
}

func DisableKeylessSigning(c crclient.Client) {
	setKeylessSigning(c, false)
	GinkgoWriter.Printf("Keyless signing disabled\n")
}

func setKeylessSigning(c crclient.Client, enabled bool) {
	patch, err := json.Marshal(map[string]any{
		"spec": map[string]any{
			"info": map[string]any{
				"spec": map[string]any{
					"clusterConfig": map[string]any{
						"data": map[string]any{
							"enableKeylessSigning": enabled,
						},
					},
				},
			},
		},
	})
	Expect(err).ShouldNot(HaveOccurred())
	err = c.Patch(context.Background(), konfluxCR(), crclient.RawPatch(types.MergePatchType, patch))
	Expect(err).ShouldNot(HaveOccurred())

	want := strconv.FormatBool(enabled)
	key := crclient.ObjectKey{Namespace: konfluxInfoNamespace, Name: clusterConfigConfigMapName}
	Eventually(func(g Gomega) {
		configMap := &corev1.ConfigMap{}
		g.Expect(c.Get(context.Background(), key, configMap)).To(Succeed())
		g.Expect(configMap.Data).To(HaveKeyWithValue("enableKeylessSigning", want))
	}, 3*time.Minute, 5*time.Second).Should(Succeed())
}

func runCosign(env []string, args ...string) {
	cmd := exec.Command("cosign", args...)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	GinkgoWriter.Printf("[cmd]: cosign %s", strings.Join(args, " "))
	Expect(err).ShouldNot(HaveOccurred())
	GinkgoWriter.Printf("[output]: %s", output)
}

type cosignArtifacts struct {
	digestRef   string
	signature   string
	attestation string
}

func getCosignArtifacts(pr *tektonpipeline.PipelineRun) cosignArtifacts {
	binaryImage := build.GetBinaryImage(pr)
	Expect(binaryImage).ShouldNot(BeEmpty())

	binaryImageRef, err := reference.Parse(binaryImage)
	Expect(err).ShouldNot(HaveOccurred())

	tagInfo, err := build.GetImageTag(binaryImageRef.Namespace, binaryImageRef.Name, binaryImageRef.Tag)
	Expect(err).ShouldNot(HaveOccurred())

	digestTag := strings.Replace(tagInfo.ManifestDigest, ":", "-", 1)
	refFor := func(suffix string) string {
		return reference.DockerImageReference{
			Registry:  binaryImageRef.Registry,
			Namespace: binaryImageRef.Namespace,
			Name:      binaryImageRef.Name,
			Tag:       digestTag + suffix,
		}.String()
	}
	digestRef := fmt.Sprintf("%s/%s/%s@%s", binaryImageRef.Registry, binaryImageRef.Namespace, binaryImageRef.Name, tagInfo.ManifestDigest)
	return cosignArtifacts{
		digestRef:   digestRef,
		signature:   refFor(".sig"),
		attestation: refFor(".att"),
	}
}

// serviceProxy exposes an in-cluster Service on a local port. The sigstore services have
// no ingress, so this is the only way for a cosign running outside the cluster to reach
// Rekor and TUF. konflux-ci's integrations/sigstore/verify.sh uses `kubectl port-forward`
// for this, here the requests are proxied through the API server's service proxy instead,
// which keeps the test image free of a kubectl binary.
type serviceProxy struct {
	server *http.Server
	port   int
}

func (p *serviceProxy) url() string {
	return fmt.Sprintf("http://localhost:%d", p.port)
}

func (p *serviceProxy) stop() {
	if p == nil || p.server == nil {
		return
	}
	_ = p.server.Close()
}

func startServiceProxy(namespace, service string, servicePort int) *serviceProxy {
	clusterConfig, err := config.GetConfig()
	Expect(err).ShouldNot(HaveOccurred())

	// The transport carries the API server credentials, the local listener is plain HTTP.
	transport, err := rest.TransportFor(clusterConfig)
	Expect(err).ShouldNot(HaveOccurred())

	target, err := url.Parse(fmt.Sprintf("%s/api/v1/namespaces/%s/services/%s:%d/proxy",
		strings.TrimSuffix(clusterConfig.Host, "/"), namespace, service, servicePort))
	Expect(err).ShouldNot(HaveOccurred())

	listener, err := net.Listen("tcp", "localhost:0")
	Expect(err).ShouldNot(HaveOccurred())

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = target.Path + req.URL.Path
			req.Host = target.Host
		},
	}

	server := &http.Server{Handler: proxy, ReadHeaderTimeout: 30 * time.Second}
	go func() {
		defer GinkgoRecover()
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			GinkgoWriter.Printf("the proxy for %s/%s stopped: %v\n", namespace, service, err)
		}
	}()

	forward := &serviceProxy{server: server, port: listener.Addr().(*net.TCPAddr).Port}

	Eventually(func() error {
		response, err := http.Get(forward.url())
		if err != nil {
			return err
		}
		return response.Body.Close()
	}, time.Minute, 2*time.Second).Should(Succeed())

	return forward
}

// VerifyKeylessSignature cryptographically verifies the image signature and the SBOM
// attestation the buildah task produced, against the in-cluster Rekor and TUF.
//
// It performs the first two checks of konflux-ci's integrations/sigstore/verify.sh. The
// third one, the SLSA provenance, is out of scope here: it is produced and signed by
// Tekton Chains, which this suite deliberately leaves on its x509 key.
func VerifyKeylessSignature(f *framework.Framework, pr *tektonpipeline.PipelineRun, namespace string) {
	artifacts := getCosignArtifacts(pr)
	oidcIssuer := getClusterOIDCIssuer(f)
	// The build pipeline signs with its own service account, so the certificate identity
	// is that account, in this scenario's namespace.
	identityRegexp := fmt.Sprintf(`^https://kubernetes\.io/namespaces/%s/serviceaccounts/build-pipeline-[a-z0-9-]+$`,
		regexp.QuoteMeta(namespace))

	rekor := startServiceProxy("rekor-system", "rekor-server", 80)
	defer rekor.stop()
	tuf := startServiceProxy("tuf-system", "tuf-server", 80)
	defer tuf.stop()

	// cosign keeps the initialized trust root in TUF_ROOT, keep it out of the home directory.
	tufRoot, err := os.MkdirTemp("", "cosign-tuf")
	Expect(err).ShouldNot(HaveOccurred())
	defer os.RemoveAll(tufRoot)
	env := append(os.Environ(), "TUF_ROOT="+tufRoot)

	runCosign(env, "initialize", "--mirror="+tuf.url(), "--root="+tuf.url()+"/root.json")

	commonArgs := []string{
		"--rekor-url=" + rekor.url(),
		"--certificate-identity-regexp=" + identityRegexp,
		"--certificate-oidc-issuer=" + oidcIssuer,
	}

	verifyArgs := append([]string{"verify"}, commonArgs...)
	runCosign(env, append(verifyArgs, artifacts.digestRef)...)

	attestArgs := append([]string{"verify-attestation", "--type=spdxjson"}, commonArgs...)
	runCosign(env, append(attestArgs, artifacts.digestRef)...)
}

func ExpectImageIsSigned(pr *tektonpipeline.PipelineRun) {
	artifacts := getCosignArtifacts(pr)
	for _, artifact := range []string{artifacts.signature, artifacts.attestation} {
		Eventually(func() (bool, error) {
			return build.DoesTagExistsInQuay(artifact)
		}, 2*time.Minute, 10*time.Second).Should(BeTrue())
	}
}
