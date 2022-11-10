package servicesOnHost

import (
	"VulnScanner/pkg/api/v1"
	"VulnScanner/pkg/logging"
	"VulnScanner/pkg/scannerNmap/parser/vulnerability"
	"fmt"
	"github.com/Ullaakut/nmap/v2"
	"github.com/sirupsen/logrus"
)

// Записываем основные харектеристики служб
func GetServicesOnHost(host *nmap.Host) *[]*api.Service {
	servicesOnHost := []*api.Service{}
	for _, port := range host.Ports {
		logging.Ent.WithFields(logrus.Fields{"service": port.Service, "version": port.Service.Product, "TcpPort": port.ID}).Trace("parse service")
		servicesOnHost = append(servicesOnHost, &api.Service{
			Name:    fmt.Sprintf("%v", port.Service.Name),
			Version: fmt.Sprintf("%v", port.Service.Product),
			TcpPort: int32(port.ID),
			Vulns:   *vulnerability.GetVulnerability(&port),
		})
	}
	return &servicesOnHost
}
