package ldap

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
	"fmt"
	"gopkg.in/ldap.v2"
	"github.com/Sirupsen/logrus"
	"os"
)

var (
	Log = newLogger()
)

func newLogger() *logrus.Logger {
	_log := logrus.New()
	_log.Out = os.Stdout
	_log.Formatter = &logrus.TextFormatter{FullTimestamp: true}
	_log.Level = logrus.DebugLevel
	return _log
}

func LdapLookup(ldaphost string, ldapport int,
	bindusername string, bindpassword string,
	searchbase string, filter string, attributes []string) (*ldap.SearchResult, error) {

	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldaphost, ldapport))
	if err != nil {
		Log.Warn(err.Error())
		return nil, err
	}
	Log.Warn("Dial successful")
	defer l.Close()
	// First bind with a read only user
	Log.Warnf("unam: %s, pwd: %s", bindusername, bindpassword)
	err = l.Bind(bindusername, bindpassword)
	if err != nil {
		Log.Warn(err.Error())
		return nil, err
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		searchbase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, attributes,
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		Log.Warn(err.Error())
		return nil, err
	}

	if len(sr.Entries) != 1 {
		Log.Warn("User does not exist or too many entries returned")
	}

	return sr, nil
}
