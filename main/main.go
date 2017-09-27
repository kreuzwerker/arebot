package main

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
	"flag"
	"io/ioutil"
	"os"

	"github.com/Sirupsen/logrus"

	core "github.com/kreuzwerker/arebot"
	"github.com/kreuzwerker/arebot/action"
	"github.com/kreuzwerker/arebot/cloudwatch"
	"github.com/kreuzwerker/arebot/config"
	"github.com/kreuzwerker/arebot/httpserver"
	"github.com/kreuzwerker/arebot/resource/ec2"
	"github.com/kreuzwerker/arebot/resource/securitygroup"
	"github.com/kreuzwerker/arebot/sqsworker"
	"github.com/kreuzwerker/arebot/storeresults"
	"github.com/kreuzwerker/arebot/util"
)

var (
	build    string
	version  string
	cfgFile  string
	logLevel int
	cfg      *config.Config
	accounts map[string]*config.Account
	log      *logrus.Logger
)

func init() {
	flag.StringVar(&cfgFile, "config", "wall-e.cfg", "Configuration file")
	flag.IntVar(&logLevel, "loglevel", 4, "Log ouput level 0 - 5 (PanicLevel, FatalLevel, ErrorLevel, WarnLevel, InfoLevel, DebugLevel")
}

func main() {
	flag.Parse()
	log = newLogger()

	core.Log = log
	sqsworker.Log = log
	config.Log = log
	securitygroup.Log = log
	httpserver.Log = log
	cloudwatch.Log = log
	action.Log = log

	log.Println("Starting AreBot", version, build)
	accounts := make(map[string]*config.Account)

	configFile, err := ioutil.ReadFile(cfgFile)
	if err != nil {
		log.Error(err)
		log.Errorf("Terminate Arebot execution")
		os.Exit(1)
		// panic(err)
	}
	cfg, err = config.ParseConfig(string(configFile[:]))
	if err != nil {
		log.Error(err)
		log.Errorf("Terminate Arebot execution")
		os.Exit(1)
	}
	core.Cfg = cfg
	securitygroup.Cfg = cfg
	ec2instance.Cfg = cfg
	util.Cfg = cfg
	cloudwatch.Cfg = cfg
	action.Cfg = cfg

	storeresults.InitVars(log, cfg)


	port := "8080"
	go httpserver.Http_server(port)

	for _, account := range cfg.Account {
		accounts[account.AccountID] = &account

		// create the new client and return the url
		log.Printf("Connecting to queue: %s account: %s", account.AllEventsQueue, account.AccountID)

		// Create service client value configured for credentials
		// from assumed role.
		cfg := util.GetAWSConfig(account.AccountID)
		svc, url := sqsworker.NewSQSClient(account.AllEventsQueue, cfg)
		// set the queue url
		//sqsworker.QueueURL = url
		// start the worker
		go sqsworker.Start(svc, url, sqsworker.HandlerFunc(core.HandleEvent))
	}
	log.Println(accounts)


	/* ACTION TRIGGERs */
	// set-up the action triggers defined into each compliance policy to run in independent goroutines
	for _, secgroup := range cfg.SecurityGroupPolicy {
		action.SetActionTrigger(secgroup)
	}
	for _, ec2 := range cfg.EC2Policy {
		action.SetActionTrigger(ec2)
	}
	for _, s3 := range cfg.S3Policy {
		action.SetActionTrigger(s3)
	}
	select {}
}

func newLogger() *logrus.Logger {
	_log := logrus.New()
	_log.Out = os.Stdout
	_log.Formatter = &logrus.TextFormatter{FullTimestamp: true}
	if logLevel > len(logrus.AllLevels)-1 {
		logLevel = len(logrus.AllLevels) - 1
	}
	_log.Level = logrus.AllLevels[logLevel]
	return _log
}
