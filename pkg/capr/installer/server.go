package installer

import (
	"github.com/rancher/rancher/pkg/capr/settings"
	"net/http"
)

type Installer struct {
	settings map[string]settings.Setting
}

func NewInstaller(s map[string]settings.Setting) *Installer {
	return &Installer{
		settings: s,
	}
}

func (i *Installer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var err error
	var content []byte
	switch req.URL.Path {
	case SystemAgentInstallPath:
		content, err = i.LinuxInstallScript(req.Context(), "", nil, req.Host, "")
	case WindowsRke2InstallPath:
		content, err = i.WindowsInstallScript(req.Context(), "", nil, req.Host, "")
	}

	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/plain")
	rw.Write(content)
}
