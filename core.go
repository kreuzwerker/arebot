package core

/*  This file is part of AreBOT.

    AreBOT is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    AreBOT is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with AreBOT.  If not, see <http://www.gnu.org/licenses/>.
*/

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
