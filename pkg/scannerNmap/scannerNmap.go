package scannerNmap

import (
	"VulnScanner/pkg/api/v1"
	"VulnScanner/pkg/logging"
	"VulnScanner/pkg/scannerNmap/parser"
	"VulnScanner/pkg/scannerNmap/scanner/asyncScanning"
	"VulnScanner/pkg/scannerNmap/scanner/newScannerWithOpt"
	"github.com/Ullaakut/nmap/v2"
	"github.com/sirupsen/logrus"
)

type ScannerNmap struct {
	Targets *[]string
	TcpPort *[]int32
}

func NewScannerNmap(targets *[]string, tcpPort *[]int32) *ScannerNmap {
	return &ScannerNmap{Targets: targets, TcpPort: tcpPort}
}

// Функция сканирования и парсинга результатов, установленной в ОС программы Nmap
func (s *ScannerNmap) ScanResulToResponsGrpcServer() *api.CheckVulnResponse {
	logging.Ent.WithFields(logrus.Fields{"targets": s.Targets, "TcpPort": s.TcpPort}).Debug("scanner got parameters Targets and TcpPort")
	//Создаем новый сканер Nmap
	scn := newScannerWithOpt.CreateNewScanNmap(s.Targets, s.TcpPort)

	logging.Ent.WithFields(logrus.Fields{"targets": s.Targets, "TcpPort": s.TcpPort}).Debug("scanner got parameters Targets and TcpPort")
	//Задаем асинхронное сканирование хостов
	resultBytes, err := asyncScanning.Scanning(scn)
	if err := scn.RunAsync(); err != nil {
		logging.Ent.WithFields(logrus.Fields{"error": err}).Error("error scanning nmap")
	}

	//Запускаем парсер для получения результатов сканирования из битовой последовтельности
	resultScan, err := nmap.Parse(*resultBytes)
	if err != nil {
		logging.Ent.WithFields(logrus.Fields{"error": err}).Error("error parse results")
	}

	resp := parser.ParseResultScanToGrpcResponce(resultScan)
	logging.Ent.Debug("ending scanning and sending the result")
	return resp
}
