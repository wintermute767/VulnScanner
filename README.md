# VulnScanner
В данном репозитории представлена программа на языке Golang сервера с функцией сканирования удаленных хостов на предмет обнаружения уязвимостей доступных служб по баннеру .

Доступ к серверу осуществляется через систему удаленного вызова процедур gRPC. Структура запроса и ответа указаны в файле "netvuln.proto".

Для сканирования используется библиотека go: https://github.com/Ullaakut/nmap и установленная на ОС предполагаемого сервера программа Nmap.
Для определения типа уязвимости используется скрипт https://github.com/vulnersCom/nmap-vulners.

Принцип работы заключен в следующем:
 - удаленный клиент делает gRPC запрос с указанием адреса или имени сетевого хоста, а также проверяемые tcp порты;
 - в ответ от сервера получает сведения о доступном tcp порте, службе и версии на нем, тип выявленной уязвимости для каждого порта и уровень угрозы данной уязвимости;
 - логирование всех действий происходит в файл в паке logs, а также с выводом на экран.

Переменные окружения:
- LOGLEVEL указывает уровень логирования ("panic", "fatal", "error","warn", "warning","info", "debug", "trace" -выбран по дефолту);
- PORT указывает какой порт будет слушать сервер (10501 -выбран по дефолту).
