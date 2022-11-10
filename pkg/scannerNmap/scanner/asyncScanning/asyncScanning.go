package asyncScanning

import (
	"VulnScanner/pkg/logging"
	"github.com/Ullaakut/nmap/v2"
	"github.com/sirupsen/logrus"
)

func Scanning(scn *nmap.Scanner) (*[]byte, error) {
	logging.Ent.Debug("start scanning")
	var (
		resultBytes []byte
		errorBytes  []byte
	)

	//Задаем асинхронность
	if err := scn.RunAsync(); err != nil {
		logging.Ent.WithFields(logrus.Fields{"error": err}).Error("error async scanning")
	}

	//Подключаемся к выводу сканера Nmap
	stdout := scn.GetStdout()
	stderr := scn.GetStderr()
	//Запускаем гарунтину для просмотра результатов в режиме реального времени
	//необходимо для логирования
	go func() {
		for stdout.Scan() {
			resultBytes = append(resultBytes, stdout.Bytes()...)
			logging.Ent.Tracef("scanning result: %s", string(stdout.Bytes()))
		}
	}()
	go func() {
		for stderr.Scan() {
			errorBytes = append(errorBytes, stderr.Bytes()...)
			logging.Ent.Tracef("scanning error: %s", string(stdout.Bytes()))
		}
	}()

	//Блокируем завершение программы до окончания сканирования
	err := scn.Wait()
	if err != nil {
		logging.Ent.WithFields(logrus.Fields{"error": err}).Error("error queue of scanning")
	}

	return &resultBytes, err
}
