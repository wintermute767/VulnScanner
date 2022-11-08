package scanner

import (
	"VulnScanner/src/api/v1"
	"VulnScanner/src/scanner/asyncScanning"
	"VulnScanner/src/scanner/newScannerWithOpt"
	"VulnScanner/src/scanner/scanResults"
	"log"
)

//Функция сканирования и парсинга результатов, установленной в ОС программы Nmap
func GetResultOfHostScanning(targets []string, tcpPort []int32) (*api.CheckVulnResponse, error) {
	//Создаем новый сканер Nmap
	scn, err := newScannerWithOpt.CreateNewScanNmap(&targets, &tcpPort)
	if err := scn.RunAsync(); err != nil {
		log.Fatal(err)
	}

	//Задаем асинхронное сканирование хостов
	resultBytes, err := asyncScanning.Scanning(scn)
	if err := scn.RunAsync(); err != nil {
		log.Fatal(err)
	}

	//Парсим результаты в требуемый формат ответа gRPC сервера
	resp, err := scanResults.ParsingScanResults(resultBytes)
	if err := scn.RunAsync(); err != nil {
		log.Fatal(err)
	}

	return resp, err
}
