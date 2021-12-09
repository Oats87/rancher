package planner

import (
	"fmt"
	"strings"

	rkev1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	"github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1/plan"
	rancherruntime "github.com/rancher/rancher/pkg/provisioningv2/rke2/runtime"
	"github.com/rancher/wrangler/pkg/data/convert"
	capi "sigs.k8s.io/cluster-api/api/v1alpha4"
)

var allProbes = map[string]plan.Probe{
	"calico": {
		InitialDelaySeconds: 1,
		TimeoutSeconds:      5,
		SuccessThreshold:    1,
		FailureThreshold:    2,
		HTTPGetAction: plan.HTTPGetAction{
			URL: "http://127.0.0.1:9099/liveness",
		},
	},
	"etcd": {
		InitialDelaySeconds: 1,
		TimeoutSeconds:      5,
		SuccessThreshold:    1,
		FailureThreshold:    2,
		HTTPGetAction: plan.HTTPGetAction{
			URL: "http://127.0.0.1:2381/health",
		},
	},
	"kube-apiserver": {
		InitialDelaySeconds: 1,
		TimeoutSeconds:      5,
		SuccessThreshold:    1,
		FailureThreshold:    2,
		HTTPGetAction: plan.HTTPGetAction{
			URL:        "https://127.0.0.1:6443/readyz",
			CACert:     "/var/lib/rancher/%s/server/tls/server-ca.crt",
			ClientCert: "/var/lib/rancher/%s/server/tls/client-kube-apiserver.crt",
			ClientKey:  "/var/lib/rancher/%s/server/tls/client-kube-apiserver.key",
		},
	},
	"kube-scheduler": {
		InitialDelaySeconds: 1,
		TimeoutSeconds:      5,
		SuccessThreshold:    1,
		FailureThreshold:    2,
		HTTPGetAction: plan.HTTPGetAction{
			URL: "https://127.0.0.1:%s/healthz",
		},
	},
	"kube-controller-manager": {
		InitialDelaySeconds: 1,
		TimeoutSeconds:      5,
		SuccessThreshold:    1,
		FailureThreshold:    2,
		HTTPGetAction: plan.HTTPGetAction{
			URL: "https://127.0.0.1:%s/healthz",
		},
	},
	"kubelet": {
		InitialDelaySeconds: 1,
		TimeoutSeconds:      5,
		SuccessThreshold:    1,
		FailureThreshold:    2,
		HTTPGetAction: plan.HTTPGetAction{
			URL: "http://127.0.0.1:10248/healthz",
		},
	},
}

func isCalico(controlPlane *rkev1.RKEControlPlane, runtime string) bool {
	if runtime != rancherruntime.RuntimeRKE2 {
		return false
	}
	cni := convert.ToString(controlPlane.Spec.MachineGlobalConfig.Data["cni"])
	return cni == "" ||
		cni == "calico" ||
		cni == "calico+multus"
}

func renderSecureProbe(arg interface{}, rawProbe plan.Probe, runtime string, defaultSecurePort string, defaultCert string, defaultCertDir string) (plan.Probe, error) {
	securePort := getArgValue(arg, SecurePortArgument, "=")
	if securePort == "" {
		securePort = defaultSecurePort
	}
	TLSCert := getArgValue(arg, TLSCertFileArgument, "=")
	if TLSCert == "" {
		certDir := getArgValue(arg, CertDirArgument, "=")
		if certDir == "" {
			certDir = fmt.Sprintf(defaultCertDir, runtime)
		}
		TLSCert = certDir + "/" + defaultCert
	}
	return replaceCACertAndPortForProbes(rawProbe, TLSCert, securePort)
}

func (p *Planner) addProbes(nodePlan plan.NodePlan, controlPlane *rkev1.RKEControlPlane, machine *capi.Machine, config map[string]interface{}) (plan.NodePlan, error) {
	var (
		runtime    = rancherruntime.GetRuntime(controlPlane.Spec.KubernetesVersion)
		probeNames []string
	)

	nodePlan.Probes = map[string]plan.Probe{}

	if runtime != rancherruntime.RuntimeK3S && isEtcd(machine) {
		probeNames = append(probeNames, "etcd")
	}
	if isControlPlane(machine) {
		probeNames = append(probeNames, "kube-apiserver")
		probeNames = append(probeNames, "kube-controller-manager")
		probeNames = append(probeNames, "kube-scheduler")
	}
	if !(IsOnlyEtcd(machine) && runtime == rancherruntime.RuntimeK3S) {
		// k3s doesn't run the kubelet on etcd only nodes
		probeNames = append(probeNames, "kubelet")
	}
	if !IsOnlyEtcd(machine) && isCalico(controlPlane, runtime) {
		probeNames = append(probeNames, "calico")
	}

	for _, probeName := range probeNames {
		nodePlan.Probes[probeName] = allProbes[probeName]
	}

	nodePlan.Probes = replaceRuntimeForProbes(nodePlan.Probes, runtime)

	if isControlPlane(machine) {
		kcmProbe, err := renderSecureProbe(config[KubeControllerManagerArg], nodePlan.Probes["kube-controller-manager"], rancherruntime.GetRuntime(controlPlane.Spec.KubernetesVersion), DefaultKubeControllerManagerCert, DefaultKubeControllerManagerDefaultSecurePort, DefaultKubeControllerManagerCertDir)
		if err != nil {
			return nodePlan, err
		}
		nodePlan.Probes["kube-controller-manager"] = kcmProbe

		ksProbe, err := renderSecureProbe(config[KubeSchedulerArg], nodePlan.Probes["kube-scheduler"], rancherruntime.GetRuntime(controlPlane.Spec.KubernetesVersion), DefaultKubeSchedulerCert, DefaultKubeSchedulerDefaultSecurePort, DefaultKubeSchedulerCertDir)
		if err != nil {
			return nodePlan, err
		}
		nodePlan.Probes["kube-scheduler"] = ksProbe
	}
	return nodePlan, nil
}

func replaceCACertAndPortForProbes(probe plan.Probe, cert, port string) (plan.Probe, error) {
	if cert == "" || port == "" {
		return plan.Probe{}, fmt.Errorf("cert (%s) or port (%s) not defined properly", cert, port)
	}
	probe.HTTPGetAction.CACert = cert
	probe.HTTPGetAction.URL = fmt.Sprintf(probe.HTTPGetAction.URL, port)
	return probe, nil
}

func replaceRuntimeForProbes(probes map[string]plan.Probe, runtime string) map[string]plan.Probe {
	result := map[string]plan.Probe{}
	for k, v := range probes {
		v.HTTPGetAction.CACert = replaceRuntime(v.HTTPGetAction.CACert, runtime)
		v.HTTPGetAction.ClientCert = replaceRuntime(v.HTTPGetAction.ClientCert, runtime)
		v.HTTPGetAction.ClientKey = replaceRuntime(v.HTTPGetAction.ClientKey, runtime)
		result[k] = v
	}
	return result
}

func replaceRuntime(str string, runtime string) string {
	if !strings.Contains(str, "%s") {
		return str
	}
	return fmt.Sprintf(str, runtime)
}
