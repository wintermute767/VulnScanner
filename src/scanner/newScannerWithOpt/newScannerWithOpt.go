package newScannerWithOpt

import (
	"github.com/Ullaakut/nmap/v2"
	"log"
	"strconv"
)

func CreateNewScanNmap(targets *[]string, tcpPortInt *[]int32) (*nmap.Scanner, error) {
	//Переводим полученный от клиента gRPC формат tcp портов из float32 в string
	tcpPortStr := []string{}
	for i := range *tcpPortInt {
		n := (*tcpPortInt)[i]
		t := strconv.FormatInt(int64(n), 10)
		tcpPortStr = append(tcpPortStr, t)
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
		log.Fatalf("unable to create nmap scanner: %v", err)
	}
	return scn, err
}
