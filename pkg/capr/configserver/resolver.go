package configserver

import "net/http"

type Resolver interface {
	GetCorrespondingMachineByRequest(req *http.Request) (string, string, error)
	GetServerURLAndCertificateByRequest(req *http.Request) (string, []byte)
}
