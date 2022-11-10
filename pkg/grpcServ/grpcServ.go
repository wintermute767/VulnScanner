package grpcServ

import (
	api "VulnScanner/pkg/api/v1"
	"VulnScanner/pkg/grpcServ/scannerGrpcServer"
	"VulnScanner/pkg/logging"
	"VulnScanner/pkg/scannerNmap"
	"context"
)

// Задаем структуру сервера на основе автосгенерированного кода указанного ./pkg/api/v1/*
// указываем пустую структуру будующих функций
type GRPCServer struct {
	api.UnimplementedNetVulnServiceServer
}

// Указываем основную функцию gRPC
func (s *GRPCServer) CheckVuln(_ context.Context, req *api.CheckVulnRequest) (*api.CheckVulnResponse, error) {
	logging.Ent.Info("server began searching for vulnerabilities")
	//Задаем новый сканер и указываем что в данном случае будем использовать сканер nmap
	var newScanner scannerGrpcServer.ScannerGrpcServer = scannerNmap.NewScannerNmap(&req.Targets, &req.TcpPort)

	logging.Ent.Info("server got the result of scanning and began parsing")
	//Проводим сканирование и получаем результ для ответа gRPC сервера
	resp := newScanner.ScanResulToResponsGrpcServer()

	return resp, nil
}
