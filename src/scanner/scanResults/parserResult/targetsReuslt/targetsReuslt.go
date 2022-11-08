package targetsReuslt

import (
	"VulnScanner/src/api/v1"
	"VulnScanner/src/scanner/scanResults/parserResult/servicesOnHost"
	"fmt"
	"github.com/Ullaakut/nmap/v2"
)

// Получаем готовый результат для ответа gRPC сервера
func GetTargetsReuslt(result *nmap.Run) *api.CheckVulnResponse {
	resp := api.CheckVulnResponse{}
	//Записываем результаты по очердно по одному хосту
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}
		resp.Results = append(resp.Results, &api.TargetsReuslt{
			Target:   fmt.Sprintf("%v", host.Addresses[0]),
			Services: *servicesOnHost.GetServicesOnHost(&host),
		})

	}
	return &resp
}
