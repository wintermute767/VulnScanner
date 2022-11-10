package parser

import (
	"VulnScanner/pkg/api/v1"
	"VulnScanner/pkg/logging"
	"VulnScanner/pkg/scannerNmap/parser/servicesOnHost"
	"fmt"
	"github.com/Ullaakut/nmap/v2"
	"github.com/sirupsen/logrus"
)

func ParseResultScanToGrpcResponce(resultScan *nmap.Run) *api.CheckVulnResponse {
	logging.Ent.Debug("start parsing results")
	resp := api.CheckVulnResponse{}
	//Записываем результаты по очердно по одному хосту
	for _, host := range resultScan.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}
		logging.Ent.WithFields(logrus.Fields{"host": host.Addresses}).Trace("parse host")
		resp.Results = append(resp.Results, &api.TargetsReuslt{
			Target:   fmt.Sprintf("%v", host.Addresses),
			Services: *servicesOnHost.GetServicesOnHost(&host),
		})

	}
	return &resp
}
