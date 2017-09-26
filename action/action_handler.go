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
	"strings"

	"github.com/kreuzwerker/arebot/config"
	"github.com/kreuzwerker/arebot/util"
)

func HandleAction(result config.CompliantCheckResult, isEventDrivenCheck bool) error {

	// (1) fetch all the Action objects triggered by the non-compliant check result
	actions := fetchActions(result.Check)

	// TODO (2) for each "action" in actions,
	HandleAction:
	for _, action := range actions {
		action := action

		// (2.1) verify whether a time condition is defined and, in the affirmative case, if it is satisfied
		/* There are two temporal conditions:
		   -   "start_after": start the action after a given amount of time.
		       IF the action's raised by an event driven check, THEN the action handling terminates here.
		   -   "stop_after": stop the action after a given amount of time.
		       Continue the method execution.
		*/
		if isEventDrivenCheck {
			for _, cond := range action.Condition {
				if cond.Type == "start_after" {
					Log.Debugf("Event-driven actions not triggered because of 'start_after' condition: %s (event %s on resource %s).", action.Name, result.Check.Name, result.ResourceId)
					continue HandleAction
				}
			}
			Log.Debugf("Event-driven actions triggered: %s (event %s on resource %s).", action.Name, result.Check.Name, result.ResourceId)
		} else {
			// the action conditions of the periodic-driven check are evaluated in "action_trigger.go"
			Log.Debugf("Periodic-driven actions triggered: %s (event %s on resource %s).", action.Name, result.Check.Name, result.ResourceId)
		}

		// (2.2) check whether there is an email to deliver. In the affirmative case, send it!
		if email := action.Email; len(email.Receiver) > 0 {
			if receivers := createReceiversList(email, result.Check, result.EventUser); len(receivers) > 0 {
				// TODO:    we are now sending an email for each non-compliant check result
				// FUTURE IMPROVEMENT:  bundle multiple results issued within a given time window
				for _, receiver := range receivers {
					deliveryErr := util.SendEmail(receiver, result, email.Template)
					if deliveryErr != nil {
						Log.Errorf("Could not send the notification email: %s.", deliveryErr.Error())
					}
				}
			}
		}

		// TODO (2.3) check whether there are other operations to execute

	}

	return nil
}

// Return an array with the Action objects associated with the CompliantCheckResult
func fetchActions(cc config.CompliantCheck) []config.Action {
	var actions []config.Action

	cPol := Cfg.GetCompliancePolicy(cc.PolicyName)
	for _, cpa := range cPol.Action {
		for _, cca := range cc.Actions {
			if cpa.Name == cca {
				actions = append(actions, cpa)
				break
			}
		}
	}

	return actions
}

func createReceiversList(email config.EmailNotification, check config.CompliantCheck, eventuser config.EventUserInfo) []string {

	// create the list of receivers
	var receivers []string

	for _, rec := range email.Receiver {
		rec = strings.Replace(rec, " ", "", -1)
		switch rec {
		case "{{State.Creator}}", "{{State.Owner}}":
			rec = check.StateOwner
		case "{{State.Operator}}":
			rec = eventuser.EmailAddress
		default:
		}
		// append only non empty and non-duplicate email addresses
		if rec != "" && !config.ContainsString(receivers, rec) {
			receivers = append(receivers, rec)
		}
	}

	return receivers
}
