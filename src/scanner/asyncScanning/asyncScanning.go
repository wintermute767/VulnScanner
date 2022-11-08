package asyncScanning

import (
	"github.com/Ullaakut/nmap/v2"
	"log"
)

func Scanning(scn *nmap.Scanner) (*[]byte, error) {
	var resultBytes []byte

	//Задаем асинхронность
	if err := scn.RunAsync(); err != nil {
		log.Fatal(err)
	}

	//Подключаемся к выводу сканера Nmap
	stdout := scn.GetStdout()

	//Запускаем гарунтину для просмотра результатов в режиме реального времени
	//необходимо для логирования
	go func() {
		for stdout.Scan() {
			resultBytes = append(resultBytes, stdout.Bytes()...)
		}
	}()

	//Блокируем завершение программы до окончания сканирования
	err := scn.Wait()
	if err != nil {
		panic(err)
	}

	return &resultBytes, err
}
