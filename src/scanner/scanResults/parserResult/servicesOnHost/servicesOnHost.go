package servicesOnHost

import (
	"VulnScanner/src/api/v1"
	"VulnScanner/src/scanner/scanResults/parserResult/vulnerability"
	"fmt"
	"github.com/Ullaakut/nmap/v2"
)

// Записываем основные харектеристики служб
func GetServicesOnHost(host *nmap.Host) *[]*api.Service {
	servicesOnHost := []*api.Service{}
	for _, port := range host.Ports {

		servicesOnHost = append(servicesOnHost, &api.Service{
			Name:    fmt.Sprintf("%v", port.Service),
			Version: fmt.Sprintf("%v", port.Service.Product),
			TcpPort: int32(port.ID),
			Vulns:   *vulnerability.GetVulnerability(&port),
		})
	}
	return &servicesOnHost
}
