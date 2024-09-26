package configserverresolver

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/rancher/pkg/tls"
	"net/http"
	"strings"

	"github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/capr/configserver"
	mgmtcontroller "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	rkecontroller "github.com/rancher/rancher/pkg/generated/controllers/rke.cattle.io/v1"
	"github.com/rancher/rancher/pkg/wrangler"
	corecontrollers "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

var (
	tokenIndex = "tokenIndex"
)

type RancherResolver struct {
	configserver.Resolver
	clusterTokenCache    mgmtcontroller.ClusterRegistrationTokenCache
	secretsCache         corecontrollers.SecretCache
	secrets              corecontrollers.SecretController
	bootstrapCache       rkecontroller.RKEBootstrapCache
	serviceAccountsCache corecontrollers.ServiceAccountCache
}

func New(clients *wrangler.Context) *RancherResolver {
	clients.Core.Secret().Cache().AddIndexer(tokenIndex, func(obj *corev1.Secret) ([]string, error) {
		if obj.Type == corev1.SecretTypeServiceAccountToken {
			hash := sha256.Sum256(obj.Data["token"])
			return []string{base64.URLEncoding.EncodeToString(hash[:])}, nil
		}
		return nil, nil
	})

	clients.Mgmt.ClusterRegistrationToken().Cache().AddIndexer(tokenIndex,
		func(obj *v3.ClusterRegistrationToken) ([]string, error) {
			return []string{obj.Status.Token}, nil
		})
	return &RancherResolver{
		clusterTokenCache:    clients.Mgmt.ClusterRegistrationToken().Cache(),
		serviceAccountsCache: clients.Core.ServiceAccount().Cache(),
		secretsCache:         clients.Core.Secret().Cache(),
		secrets:              clients.Core.Secret(),
		bootstrapCache:       clients.RKE.RKEBootstrap().Cache(),
	}
}

func (r *RancherResolver) GetCorrespondingMachineByRequest(req *http.Request) (string, string, error) {
	machineNamespace, machineName, err := r.findMachineByProvisioningSA(req)
	if err != nil {
		return "", "", err
	}
	logrus.Debugf("[rke2configserver] Got %s/%s machine from provisioning SA", machineNamespace, machineName)
	if machineName == "" {
		machineNamespace, machineName, err = r.findMachineByClusterToken(req)
		if err != nil {
			return "", "", err
		}
		logrus.Debugf("[rke2configserver] Got %s/%s machine from cluster token", machineNamespace, machineName)
	}
	return "", "", fmt.Errorf("machine not found by request")
}

func (r *RancherResolver) GetServerURLAndCertificateByRequest(req *http.Request) (string, []byte) {
	var ca []byte
	url, pem := settings.ServerURL.Get(), settings.CACerts.Get()
	if strings.TrimSpace(pem) != "" {
		ca = []byte(pem)
	}

	if url == "" {
		pem = settings.InternalCACerts.Get()
		if req.Host != "" {
			url = fmt.Sprintf("https://%s", req.Host)
			if strings.TrimSpace(pem) != "" {
				ca = []byte(pem)
			}
		}
	} else if v, ok := req.Context().Value(tls.InternalAPI).(bool); ok && v {
		pem = settings.InternalCACerts.Get()
		if strings.TrimSpace(pem) != "" {
			ca = []byte(pem)
		}
	}
	return url, ca
}
