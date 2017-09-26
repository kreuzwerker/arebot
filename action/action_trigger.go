package action

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
	"errors"
	"time"
	"strings"

	"github.com/robfig/cron"

	"github.com/kreuzwerker/arebot/config"
	"github.com/kreuzwerker/arebot/storeresults"
	"github.com/kreuzwerker/arebot/resource/securitygroup"
	"github.com/kreuzwerker/arebot/util"
	"github.com/kreuzwerker/arebot/resource/ec2"
)

/* 		ACTION_TRIGGER IMPLEMENTATION: overview
	*******************************************************************************
	- Create a new ticker T based for each action_trigger AT definition provided in the configuration file.
	- Configure T using the cron-like definition provided in the configuration file
   	- Every time the ticker T of AT fires, a function reads all the stored states files,
		- looking for non-compliant checks NCC that are associated with the same actions triggered by AT
		- append such NCC objects to a slice S_NCC
		- once scanned through all the non-compliant checks, then it runs all the NCC into S_NCC
*/
func SetActionTrigger(cp config.CompliancePolicy) {
	c := cron.New()

	for _, trigger := range cp.ActionTrigger {
		trigger := trigger

		c.AddFunc(trigger.Schedule, func() {
			checksToTrigger, err := fetchChecksToTrigger(cp.Name, trigger)
			if err != nil {
				Log.Errorf("Set-up periodic check failed: %s.", err)
				return
			}
			handleTriggeredCompliantChecks(trigger, checksToTrigger)
		})
		Log.Debugf("Action trigger %s has been scheduled.", trigger.Name)
	}
	c.Start()
}

// retrieve all the compliant checks that trigger the actions defined in the passed ActionTrigger object
func fetchChecksToTrigger(policyName string, t config.ActionTrigger) ([]config.CompliantCheckResult, error) {
	Log.Debugf("Action trigger %s: triggered by action: %s every %s.\n", t.Name, t.Action, t.Schedule)

	// the CompliantCheck objects to trigger
	var checksToTrigger []config.CompliantCheckResult
	var fetchedChecks []config.CompliantCheckResult

	for _, actionName := range t.Action {
		checks, err := storeresults.GetCheckResultsByActionAndPolicyName(actionName, policyName)
		if err != nil {
			return nil, errors.New("Periodic check error: " + err.Error())
		}
		if len(*checks) == 0 {
			return nil, nil
		}
		// verify time conditions and return only those check results that satisfy them
		checks = evaluateTimeConditions(policyName, actionName, checks)

		fetchedChecks = append(fetchedChecks, *checks...)
	}

	// eliminate duplicates
	hasIpPermissionsCheck := false
	hasSGTagsCheck := false

	CheckDuplicates:
	for _ , check := range fetchedChecks {
		for _, ctt := range checksToTrigger {
			if check.IsIpPermissionsCheck() && hasIpPermissionsCheck {
				continue CheckDuplicates
			}
			if strings.HasPrefix(check.Check.Name, "Tag.") && hasSGTagsCheck {
				continue CheckDuplicates
			}
			if check.IsSameCheck(ctt) {
				continue CheckDuplicates
			}
		}
		checksToTrigger = append(checksToTrigger, check)
		if !hasIpPermissionsCheck && check.IsIpPermissionsCheck() {
			hasIpPermissionsCheck = true
		}
		if strings.HasPrefix(check.Check.Name, "Tag.") {
			hasSGTagsCheck = true
		}
	}

	// run all the CompliantCheck saved in checksToTrigger
	return checksToTrigger, nil
}

func evaluateTimeConditions(policyName string, actionName string, checks *[]config.CompliantCheckResult) *[]config.CompliantCheckResult {
	var results []config.CompliantCheckResult

	expiredResults := make(map[string][]config.CompliantCheckResult)

	action := Cfg.GetActionByIdAndPolicyName(actionName, policyName)

	for _, res := range *checks {
		isToReExecute := true
		isToRemove := false

		for _, condition := range action.Condition {
			switch condition.Type {
			case "stop_after":
				// if the time specified in the condition value is elapsed since the result creation
				// then the check should be removed from the state
				isToRemove = time.Now().After(res.CreationDate.Add(condition.ValueDuration))

			case "start_after":
				// if the time specified in the condition value is elapsed since the result creation
				// then set the new result has to be scheduled for re-execution
				isToReExecute = time.Now().After(res.CreationDate.Add(condition.ValueDuration))
			}
		}

		if isToRemove {
			Log.Debugf("Stored check result soon to be removed because of expired time condition: %v ", res)
			expiredResults[res.ResourceId] = append(expiredResults[res.ResourceId], res)
		} else if isToReExecute {
			// append the CompliantCheck (no duplicates) to the slice of checks to check later
			results = append(results, res)
		}
	}

	// remove all the expired check results
	for resourceId, resList := range expiredResults {
		storeresults.DeleteCheckResultsByResourceIdAndResultsList(resourceId, resList)
	}

	return &results
}

func handleTriggeredCompliantChecks(trigger config.ActionTrigger, resultsToRun []config.CompliantCheckResult) {
	for _, rtr := range resultsToRun {
		resourcePrefix := strings.Split(rtr.ResourceId, "-")[0]
		var apicallCfgs []config.APICall
		var resource util.AwsResourceType

		switch resourcePrefix {
			case "sg":
				sg, err := securitygroup.NewSecurityGroupWithStatus(rtr.ResourceId, rtr.EventUser.AccountId)
				if err != nil {
					Log.Debugf("Failed re-execution of the compliant check '%s'. Cannot find the security group '%s'. Err: ", rtr.Check.Name, rtr.ResourceId, err.Error())
					continue
				}
				_, apicallCfgs = Cfg.GetAPICallConfigs(rtr.EventType, rtr.EventUser.AccountId, *sg.State.VpcId, "security_group")
				resource = &sg

			case "i":
				ei, err := ec2instance.NewEC2WithStatus(rtr.ResourceId, rtr.EventUser.AccountId)
				if err != nil {
					Log.Debugf("Failed re-execution of the compliant check '%s'. Cannot find the EC2 instance '%s'. Err: ", rtr.Check.Name, rtr.ResourceId, err.Error())
					continue
				}
				_, apicallCfgs = Cfg.GetAPICallConfigs(rtr.EventType, rtr.EventUser.AccountId, *ei.State.VpcId, "ec2")
				resource = &ei

			case "vol":
				v, err := ec2instance.NewVolumeWithStatus(rtr.ResourceId, rtr.EventUser.AccountId)
				if err != nil {
					Log.Debugf("Failed re-execution of the compliant check '%s'. Cannot find the Volume instance '%s'. Err: ", rtr.Check.Name, rtr.ResourceId, err.Error())
					continue
				}
				_, apicallCfgs = Cfg.GetAPICallConfigs(rtr.EventType, rtr.EventUser.AccountId, "", "ec2")
				resource = &v

			case "snap":
				s, err := ec2instance.NewSnapshotWithStatus(rtr.ResourceId, rtr.EventUser.AccountId)
				if err != nil {
					Log.Debugf("Failed re-execution of the compliant check '%s'. Cannot find the Snapshot instance '%s'. Err: ", rtr.Check.Name, rtr.ResourceId, err.Error())
					continue
				}
				_, apicallCfgs = Cfg.GetAPICallConfigs(rtr.EventType, rtr.EventUser.AccountId, "", "ec2")
				resource = &s

		}

		reexecCompliantChecks(resource, apicallCfgs, rtr)

	}
}

func reexecCompliantChecks(resource util.AwsResourceType, apicallCfgs []config.APICall, check config.CompliantCheckResult) {
	for _, apicallCfg := range apicallCfgs {
		if check.EventType == apicallCfg.Name {
			Log.Debugf("action_trigger.launchChecks: periodic check of compliance %+v", apicallCfg)
			results := apicallCfg.CheckCompliance(resource.GetProperties, check.ResourceId, check.EventUser)
			for _, res := range results {
				res := res
				if !res.IsCompliant {
					HandleAction(res, false)
				}
				if len(results) > 0 {
					storeresults.StoreResourceCheckResults(resource.GetId(), results)
				}
			}
		}
	}
}
