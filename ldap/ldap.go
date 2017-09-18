package ldap

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
