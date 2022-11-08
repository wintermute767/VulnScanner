package main

import (
	"VulnScanner/src/api/v1"
	"VulnScanner/src/grpcServ"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"log"
	"net"
	"os"
)

func main() {
	//Задаем параметры из окружения для последущего использования в docker контейнере
	address := os.Getenv("ADDRESS")
	if address == "" {
		address = "127.0.0.1"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "10500"
	}

	//Задаем службу для прослушивания порта
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", address, port))
	if err != nil {
		log.Fatal(err)
	}

	//Создаем новый gRPC сервер
	grpcServer := grpc.NewServer()

	//Запускаем отражение на стороне клиента
	reflection.Register(grpcServer)

	//Регистрируем собственную конфигурацию сервера и заем ее прослушивающей службе
	api.RegisterNetVulnServiceServer(grpcServer, &grpcServ.GRPCServer{})
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatal(err)
	}

}
