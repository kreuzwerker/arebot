package core

import (
	"os"

	"github.com/kreuzwerker/arebot/config"
	"github.com/Sirupsen/logrus"
)

var (
	Cfg *config.Config
	Log = newLogger()
)

func newLogger() *logrus.Logger {
	_log := logrus.New()
	_log.Out = os.Stdout
	_log.Formatter = &logrus.TextFormatter{FullTimestamp: true}
	_log.Level = logrus.DebugLevel
	return _log
}
