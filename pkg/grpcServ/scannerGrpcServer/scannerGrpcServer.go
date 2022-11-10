package scannerGrpcServer

import "VulnScanner/pkg/api/v1"

// Указываем интерфейс для различных реализаций сканеров

type ScannerGrpcServer interface {
	ScanResulToResponsGrpcServer() *api.CheckVulnResponse
}
