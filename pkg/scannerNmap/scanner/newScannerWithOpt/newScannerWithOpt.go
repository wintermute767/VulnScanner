package newScannerWithOpt

import (
	"VulnScanner/pkg/logging"
	"github.com/Ullaakut/nmap/v2"
	"github.com/sirupsen/logrus"
	"strconv"
)

func CreateNewScanNmap(targets *[]string, tcpPortInt *[]int32) *nmap.Scanner {
	logging.Ent.Debug("creating new scanner Nmap")
	//Переводим полученный от клиента gRPC формат tcp портов из float32 в string
	//Если порты не заданы берем все стандартные
	tcpPortStr := []string{}
	if len(*tcpPortInt) > 0 {
		for i := range *tcpPortInt {
			n := (*tcpPortInt)[i]
			t := strconv.FormatInt(int64(n), 10)
			tcpPortStr = append(tcpPortStr, t)
		}
	} else {
		tcpPortStr = []string{"1-1023"}
	}

	//Задаем параметры сканера:
	//указываем хосты, порты, параметр определения служб на портах,
	//скрипт определения уязвимостей и аргумент скрипта для получения всех уровней угроз уязвимостей
	scn, err := nmap.NewScanner(
		nmap.WithTargets(*targets...),
		nmap.WithPorts(tcpPortStr...),
		nmap.WithCustomArguments("-sV"),
		nmap.WithScripts("vulners"),
		nmap.WithScriptArguments(map[string]string{"mincvss=0": ""}),
	)
	if err != nil {
		logging.Ent.WithFields(logrus.Fields{"error": err}).Error("error create new scanner")
	}

	return scn
}
