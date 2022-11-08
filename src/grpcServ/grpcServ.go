package grpcServ

import (
	api "VulnScanner/src/api/v1"
	"VulnScanner/src/scanner"
	"context"
	"log"
)

// Задаем структуру сервера на основе автосгенерированного кода указанного ./src/api/v1/*
// указываем пустую структуру будующих функций
type GRPCServer struct {
	api.UnimplementedNetVulnServiceServer
}

// Указываем основную функцию gRPC
func (s *GRPCServer) CheckVuln(cnt context.Context, req *api.CheckVulnRequest) (*api.CheckVulnResponse, error) {
	resp, err := scanner.GetResultOfHostScanning(req.Targets, req.TcpPort)
	if err != nil {
		log.Fatal(err)
	}
	return resp, err
}
