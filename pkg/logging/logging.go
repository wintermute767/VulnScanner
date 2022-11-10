package logging

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"os"
	"path"
	"runtime"
)

// Представление по которому будет производится логирование
var Ent *logrus.Entry

// Структура необходима для отправки любого количества Writer любое количество LogLevels
type writerHook struct {
	Writer    []io.Writer
	LogLevels []logrus.Level
}

// Функция записи в файл
func (hook *writerHook) Fire(entry *logrus.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}
	for _, w := range hook.Writer {
		w.Write([]byte(line))
	}
	return err
}

// Функция возвращает
func (hook *writerHook) Levels() []logrus.Level {
	return hook.LogLevels
}

// Задаем параметры нового логера
func init() {
	l := logrus.New()
	l.SetReportCaller(true)
	//задаем формат строки лога
	l.Formatter = &logrus.TextFormatter{
		CallerPrettyfier: func(frame *runtime.Frame) (function string, file string) {
			filename := path.Base(frame.File)
			return fmt.Sprintf("%s()", frame.Function), fmt.Sprintf("%s:%d", filename, frame.Line)
		},
		DisableColors: false,
		FullTimestamp: true,
	}

	//Создаем папку для логов
	err := os.MkdirAll("logs", 0666)
	if err != nil {
		panic(err)
	}

	allFile, err := os.OpenFile("logs/all.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		panic(err)
	}

	//блокируем стандартынй вывод logrus
	l.SetOutput(io.Discard)

	//Указываем куда мы будем отправлять логи: в вывод на экрани и запись в файл лога
	l.AddHook(&writerHook{
		Writer:    []io.Writer{allFile, os.Stdout},
		LogLevels: logrus.AllLevels,
	})
	//указываем какой уровень логов хотим видеть
	var lvl logrus.Level
	switch os.Getenv("LOGLEVEL") {
	case "panic":
		lvl = logrus.PanicLevel
	case "fatal":
		lvl = logrus.FatalLevel
	case "error":
		lvl = logrus.ErrorLevel
	case "warn", "warning":
		lvl = logrus.WarnLevel
	case "info":
		lvl = logrus.InfoLevel
	case "debug":
		lvl = logrus.DebugLevel
	case "trace":
		lvl = logrus.TraceLevel
	default:
		lvl = logrus.TraceLevel
	}

	l.SetLevel(lvl)

	Ent = logrus.NewEntry(l)
}
