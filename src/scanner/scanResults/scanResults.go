package scanResults

import (
	"VulnScanner/src/api/v1"
	"log"

	"github.com/Ullaakut/nmap/v2"

	"VulnScanner/src/scanner/scanResults/parserResult/targetsReuslt"
)

func ParsingScanResults(resultBytes *[]byte) (*api.CheckVulnResponse, error) {
	//Запускаем парсер для получения результатов сканирования из битовой последовтельности
	result, err := nmap.Parse(*resultBytes)
	if err != nil {
		log.Fatal(err)
	}

	//Запускаем функцию парсинга результатов сканирования в формат ответа gRPC сервера
	resp := targetsReuslt.GetTargetsReuslt(result)

	return resp, err
}
