package steve

import (
	"context"
	"net/http"

	gmux "github.com/gorilla/mux"
	"github.com/rancher/rancher/pkg/api/steve/aggregation"
	"github.com/rancher/rancher/pkg/api/steve/catalog"
	"github.com/rancher/rancher/pkg/api/steve/github"
	"github.com/rancher/rancher/pkg/api/steve/health"
	"github.com/rancher/rancher/pkg/api/steve/projects"
	"github.com/rancher/rancher/pkg/api/steve/proxy"
	rancherconfigserver "github.com/rancher/rancher/pkg/capr-rancher/configserver"
	rancherconfigserverresolver "github.com/rancher/rancher/pkg/capr-rancher/configserverresolver"
	caprconfigserver "github.com/rancher/rancher/pkg/capr/configserver"
	"github.com/rancher/rancher/pkg/capr/installer"
	caprsettings "github.com/rancher/rancher/pkg/capr/settings"
	"github.com/rancher/rancher/pkg/features"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/rancher/pkg/wrangler"
	steve "github.com/rancher/steve/pkg/server"
	"k8s.io/client-go/tools/cache"
)

func cAPRSetting(setting settings.Setting) caprsettings.Setting {
	return caprsettings.NewSetting(setting.Get, setting.Default)
}

func AdditionalAPIsPreMCM(config *wrangler.Context) func(http.Handler) http.Handler {
	if features.RKE2.Enabled() {
		rancherConfigServerResolver := rancherconfigserverresolver.New(config)
		informers := map[string]cache.SharedIndexInformer{
			"secrets":                   config.Core.Secret().Informer(),
			"clusterregistrationtokens": config.Mgmt.ClusterRegistrationToken().Informer(),
		}
		caprConfigServer := caprconfigserver.New(config, rancherConfigServerResolver, informers)
		rancherConfigServer := rancherconfigserver.New(config, rancherConfigServerResolver, informers)
		mux := gmux.NewRouter()
		mux.UseEncodedPath()
		mux.Handle(caprconfigserver.ConnectAgent, caprConfigServer)
		mux.Handle(rancherconfigserver.ConnectConfigYamlPath, rancherConfigServer)
		mux.Handle(rancherconfigserver.ConnectClusterInfo, rancherConfigServer)
		i := installer.NewInstaller(map[string]caprsettings.Setting{
			"ServerURL":                cAPRSetting(settings.ServerURL),
			"WinsAgentInstallScript":   cAPRSetting(settings.WinsAgentInstallScript),
			"AgentTLSMode":             cAPRSetting(settings.AgentTLSMode),
			"SystemAgentVersion":       cAPRSetting(settings.SystemAgentVersion),
			"SystemAgentInstallScript": cAPRSetting(settings.SystemAgentInstallScript),
			"UIPath":                   cAPRSetting(settings.UIPath),
			"WinsAgentVersion":         cAPRSetting(settings.WinsAgentVersion),
			"CSIProxyAgentURL":         cAPRSetting(settings.CSIProxyAgentURL),
			"CSIProxyAgentVersion":     cAPRSetting(settings.CSIProxyAgentVersion),
		})
		mux.Handle(installer.SystemAgentInstallPath, i)
		mux.Handle(installer.WindowsRke2InstallPath, i)
		return func(next http.Handler) http.Handler {
			mux.NotFoundHandler = next
			return mux
		}
	}

	return func(next http.Handler) http.Handler {
		return next
	}
}

func AdditionalAPIs(ctx context.Context, config *wrangler.Context, steve *steve.Server) (func(http.Handler) http.Handler, error) {
	clusterAPI, err := projects.Projects(ctx, config, steve)
	if err != nil {
		return nil, err
	}

	githubHandler, err := github.NewProxy(config.Core.Secret().Cache(),
		settings.GithubProxyAPIURL.Get(),
		"cattle-system",
		"github")
	if err != nil {
		return nil, err
	}

	mux := gmux.NewRouter()
	mux.UseEncodedPath()
	if features.UIExtension.Enabled() {
		catalog.RegisterUIPluginHandlers(mux)
	}
	mux.Handle("/v1/github{path:.*}", githubHandler)
	mux.Handle("/v3/connect", Tunnel(config))

	health.Register(mux)

	return func(next http.Handler) http.Handler {
		mux.NotFoundHandler = clusterAPI(next)
		return mux
	}, nil
}

func Tunnel(config *wrangler.Context) http.Handler {
	config.TunnelAuthorizer.Add(proxy.NewAuthorizer(config))
	config.TunnelAuthorizer.Add(aggregation.New(config))
	return config.TunnelServer
}
