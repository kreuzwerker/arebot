package httpserver

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
	"log"
	"net/http"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/kreuzwerker/arebot/resource/securitygroup"
	"github.com/kreuzwerker/arebot/storeresults/filesystem"
)

var (
	// Log Logger for this package
	Log = newLogger()
)

func newLogger() *logrus.Logger {
	_log := logrus.New()
	_log.Out = os.Stdout
	_log.Formatter = &logrus.TextFormatter{FullTimestamp: true}
	_log.Level = logrus.DebugLevel
	return _log
}

func Http_server(port string) {
	log.Println("Opening port", port, "for health checking")

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", handler)
	router.HandleFunc("/findAll", findAllSecGroups)
	router.HandleFunc("/status/{id}", stateHandler)

	err := http.ListenAndServe(":" + port, router)

	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte{})
}

func stateHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	key := vars["id"]
	grp, err := filesystem.GetState(key)
	if err != nil {
		fmt.Fprintf(w, "Error while looking for SG state: %s", err)
		return
	}
	secGrp := securitygroup.NewSecurityGroup(&grp)
	fmt.Fprint(w, secGrp)
}

func findAllSecGroups(w http.ResponseWriter, r *http.Request) {
	var result []string
	groups, err := securitygroup.FindAllSecGroupsWithTag("AreBOT.ComplianceNotMet", "")
	if err != nil {
		Log.Errorf("Error while fetching security grops: %s", err.Error())
	}
	for _, grp := range groups {
		result = append(result, *grp.State.GroupId)
	}
	fmt.Fprint(w, result)
}
