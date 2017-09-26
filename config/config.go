package config

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
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"errors"
	"github.com/Sirupsen/logrus"
)

var Log = newLogger()

func newLogger() *logrus.Logger {
	_log := logrus.New()
	_log.Out = os.Stdout
	_log.Formatter = &logrus.TextFormatter{FullTimestamp: true}
	_log.Level = logrus.DebugLevel
	return _log
}

// ***************************************************************************************************************************************
// ***	Config METHODS

// GetAPICallConfigs returns all APICall configuration objects for a given apiCall
func (cfg Config) GetAPICallConfigs(apiCall string, accountID string, vpc string, policyType string) ([]CompliancePolicy, []APICall) {
	Log.Debugf("Getting config for API call: %s accountID: %s, vpc: %s", apiCall, accountID, vpc)
	ac := []APICall{}
	cp := []CompliancePolicy{}

	var compliancePolicies []CompliancePolicy
	switch policyType {
	case "security_group":
		compliancePolicies = cfg.SecurityGroupPolicy
	case "ec2":
		compliancePolicies = cfg.EC2Policy
	case "s3":
		compliancePolicies = cfg.S3Policy
	}

	// XXX: add back reference as part of the result - maybe two slices?
	for _, cpCfg := range compliancePolicies {
		//Log.Infof("cpCfg: %+v", cpCfg)
		// if account ID is given check it and ignore configs that doesn't fit
		if len(cpCfg.Account) > 0 && cpCfg.Account != accountID {
			Log.Debugf("config has accoundID defined but dont match here: %+v", cpCfg.Account)
			continue
		}
		re := regexp.MustCompile(cpCfg.VpcID)
		if vpc != "" && len(cpCfg.VpcID) > 0 && !re.MatchString(vpc) {
			Log.Debugf("config has VPC defined but dont match here: %+v", cpCfg.VpcID)
			continue
		}

		for _, apiCallObj := range cpCfg.APICall {
			if apiCallObj.Name == apiCall {
				ac = append(ac, apiCallObj)
				cp = append(cp, cpCfg)
			}
		}
	}
	return cp, ac
}

// GetAccount returns the Config object of account <number>
func (cfg Config) GetAccount(id string) *Account {

	for _, account := range cfg.Account {
		if account.AccountID == id {
			return &account
		}
	}
	return nil
}

func (cfg Config) GetSecurityGroupPolicy(id string) *CompliancePolicy {

	for _, securityGroup := range cfg.SecurityGroupPolicy {
		if securityGroup.Name == id {
			return &securityGroup
		}
	}
	return nil
}

func (cfg Config) GetEC2Policy(id string) *CompliancePolicy {

	for _, ec2 := range cfg.EC2Policy {
		if ec2.Name == id {
			return &ec2
		}
	}
	return nil
}

func (cfg Config) GetS3Policy(id string) *CompliancePolicy {

	for _, s3 := range cfg.S3Policy {
		if s3.Name == id {
			return &s3
		}
	}
	return nil
}

func (cfg Config) GetCompliancePolicy(id string) *CompliancePolicy {
	if sg := cfg.GetSecurityGroupPolicy(id); sg != nil {
		return sg
	}
	if ec2 := cfg.GetEC2Policy(id); ec2 != nil {
		return ec2
	}
	if s3 := cfg.GetS3Policy(id); s3 != nil {
		return s3
	}
	return nil
}

func (cfg Config) GetActionByIdAndPolicyName(id string, policyName string) *Action {
	for _, action := range cfg.GetCompliancePolicy(policyName).Action {
		if action.Name == id {
			return &action
		}
	}
	return nil
}

func (cfg Config) GetBucketAndFolder() (string, string) {
	return cfg.S3Config.Bucket, cfg.S3Config.LocalFolder
}

func (cfg Config) GetLdapConfig() LdapConfig {
	return cfg.LdapConfig
}

// GetAccountRoleArn returns the configured role ARN for the account given as ID
// and returns an empty string otherwise
func (cfg Config) GetAccountRoleArn(id string) string {
	account := cfg.GetAccount(id)
	if account == nil {
		return ""
	}
	return account.ArebotRoleArn
}

// GetAccountAssumedRoleArn transfers the role ARN into the user identity
// of the role of the account iam -> sts assume role
func (cfg Config) GetAccountAssumedRoleArn(id string) string {
	arn := cfg.GetAccountRoleArn(id)
	if len(arn) == 0 {
		return ""
	}
	r := strings.NewReplacer(":iam:", ":sts:", ":role/", ":assumed-role/")
	arn = r.Replace(arn)

	// use the account session or the global session string or set wildcard
	session := cfg.GetAccountRoleArnSession(id)
	if len(session) == 0 {
		session = ".+"
	}
	return arn + "/" + session
}

// GetAccountRoleArnSession returns the session part of the role as
// it is configured. Returns an empty string otherwise.
func (cfg Config) GetAccountRoleArnSession(id string) string {
	account := cfg.GetAccount(id)
	if account == nil {
		return ""
	}
	session := ""

	if len(account.RoleSessionName) > 0 {

		session = account.RoleSessionName
	} else if len(cfg.AreBotUserSession) > 0 {

		session = cfg.AreBotUserSession
	}
	return session
}

func (cfg Config) ShouldStoreOnDynamoDB() bool {
	return cfg.DynamoDBConfig.ArebotRoleArn != "" && cfg.DynamoDBConfig.Region != ""
}

// ***************************************************************************************************************************************
// APICall METHODS

/* SetTag applies resource tags
getValueFromTemplate func(input string) (string, error):
	Function pointer to parse input e.g. with the help of a templating library
resourceTaggingFunction func(string, string) error:
	Resource specific function to set the tags
triggerResourceAction func(string, string):
	Arguments: property, action
	Function that provides the action functionality of the configuration
*/
func (ac APICall) SetTag(getValueFromTemplate func(input string) (string, error),
	resourceTaggingFunction func(string, string) error,
	triggerResourceAction func( /*property, action*/
		string, string)) {

	for _, c := range ac.Tag {
		Log.Debugf("config.SetTag: %s: %s=%s", c.Name, c.Key, c.Value)
		parsed, err := getValueFromTemplate(c.Value)
		if err != nil {
			Log.Error(err)
			parsed = c.Value
		}

		Log.Debugf("config.SetTag: %s", parsed)

		err = resourceTaggingFunction(c.Key, parsed)
		if err != nil {
			Log.Error(err)
		}
	}
	return
}

func (ac APICall) TagResource(resourceTagFunction func(string, string) error) error {
	for _, t := range ac.Tag {

		Log.Infof("Tagging `%s: %s` based on config: %s", t.Key, t.Value, t.Name)
		if err := resourceTagFunction(t.Key, t.Value); err != nil {
			return err
		}
	}
	return nil
}

// CheckCompliance checks all compliance definitions
func (ac APICall) CheckCompliance(getResourceProperties func(string) []string, resourceId string, eventuser EventUserInfo) []CompliantCheckResult {

	var compliantCheckResults []CompliantCheckResult
	resourcePrefix := strings.Split(resourceId, "-")[0] // identify the resource type

	DoCompliantChecks:
	for _, c := range ac.Compliant {
		c := c
		result := getResourceProperties(c.Name)

		// VERIFY CONDITIONS
		for _, cond := range c.Condition {
			if !satisfyTestCondition(cond, getResourceProperties, c.Name) {
				continue DoCompliantChecks
			}
		}

		// set state Owner
		if resourcePrefix == "sg" && len(getResourceProperties("Tag.Owner")) > 0 {
			c.StateOwner = getResourceProperties("Tag.Owner")[0]
		}

		Log.Debugf("config.CheckCompliance: %s: %+v mandatory=%+v", c.Name, result, c.Mandatory)

		// handle compliance that checks for missing resource properties
		// e.g. missing tags or missing resource description
		if c.Mandatory == true && len(result) == 0 {
			Log.Debugf("config.CheckCompliance: mandatory property `%+v` is missing ", c.Name)
			compliantCheckResults = append(compliantCheckResults, CompliantCheckResult{
				EventType: ac.Name, EventUser: eventuser, ResourceId: resourceId,
				IsCompliant: false, Check: c, Value: "missing", CreationDate: time.Now()})

		}

		for _, r := range result {
			checkName := strings.Split(c.Name, ".")
			var match bool
			var err error

			switch checkName[0] {
				case "IpPermissions":
					reIp, _ := regexp.Compile("^P:([^;]*);FP:([^;]*);TP:([^;]*);IP:(.*)$")
					reUg, _ := regexp.Compile("^P:([^;]*);FP:([^;]*);TP:([^;]*);UG:(.*)$")
					var sbs [][]string
					if reIp.MatchString(r) {
						sbs = reIp.FindAllStringSubmatch(r, -1)
					} else { // if false is a record with User-Group pair
						sbs = reUg.FindAllStringSubmatch(r, -1)
					}

					switch checkName[1] {
						case "FromPort":
							match, err = c.IsCompliant(c.Name, sbs[0][2])

						case "ToPort":
							match, err = c.IsCompliant(c.Name, sbs[0][3])

						case "IpRanges", "UserIdGroupPairs":
							match, err = c.IsCompliant(c.Name, sbs[0][4])
					}

				default:
					match, err = c.IsCompliant(c.Name, r)
			}
			// if the result is not compliant
			if err == nil && !match {
				compliantCheckResults = append(compliantCheckResults, CompliantCheckResult{
					EventType: ac.Name, EventUser: eventuser, ResourceId: resourceId,
					IsCompliant: false, Check: c, Value: r, CreationDate: time.Now()})
			} else {
				// if the result is compliant
				compliantCheckResults = append(compliantCheckResults, CompliantCheckResult{
					EventType: ac.Name, EventUser: eventuser, ResourceId: resourceId,
					IsCompliant: true, Check: c, Value: r, CreationDate: time.Now()})
			}
		}
	}

	// return the list of CompliantCheckResult objects that have been created (without repetitions)
	return mergeComplianceResults(compliantCheckResults)
}

// ***************************************************************************************************************************************
// ***	CompliantCheck METHODS

// IsCompliant returns true, nil if the property is compliant,
// false, nil if it is not compliant
// false, error in case the compliance check is not matching the property
func (c CompliantCheck) IsCompliant(prop string, value string) (bool, error) {
	if c.Name == prop {

		// security group has a tag with a configuerd action
		if len(c.Schema) > 0 {
			// schema check
			re := regexp.MustCompile(c.Schema)
			// negate pattern in schema
			if c.Negate {
				if re.MatchString(value) {
					Log.Debugf("Compliance check for %s - %s is not compliant (negate = true)", prop, value)
					return false, nil
				}
				Log.Debugf("Compliance check for %s - %s is compliant (negate = true)", prop, value)
				return true, nil

			} else {
				if re.MatchString(value) {
					Log.Debugf("Compliance check for %s - %s is compliant", prop, value)
					return true, nil
				}
				Log.Debugf("Compliance check for %s - %s is not compliant", prop, value)
				return false, nil
			}
		}
	}
	return false, fmt.Errorf("Property doesn't match complancy check: %s vs. %s", prop, c.Name)
}

// ***************************************************************************************************************************************
// ***	CompliantCheckResult METHODS

/* 	Compare the values of two CompliantCheckResult objects, except from "IsCompliant" "Value"
and "Date". Return true if the values are the same; return false otherwise
*/
func (ccres CompliantCheckResult) IsSameCheck(otherOne CompliantCheckResult) bool {

	if ccres.ResourceId == otherOne.ResourceId && ccres.EventType == otherOne.EventType && ccres.EventUser.Username == otherOne.EventUser.Username {
		if ccres.Check.Name == otherOne.Check.Name {
			if ccres.IsIpPermissionsCheck() {
				if ccres.Value == otherOne.Value {
					return true
				}
			} else {
				return true
			}
		}
	}

	return false
}

/* 	Compare the values of two CompliantCheckResult objects, except from "Date".
Return true if the values are are the same; return false otherwise
*/
func (ccres CompliantCheckResult) IsSameCheckResult(otherOne CompliantCheckResult) bool {

	if ccres.IsSameCheck(otherOne) && ccres.IsCompliant == otherOne.IsCompliant {
		return true
	}

	return false
}

/*	Return true if the compliant check associated with this result is related to an IpPermissions-type event; return false otherwise.
 */
func (ccres CompliantCheckResult) IsIpPermissionsCheck() bool {
	if strings.Split(ccres.Check.Name, ".")[0] == "IpPermissions" {
		return true
	}
	return false
}

// ***************************************************************************************************************************************
// validation functions

func validateConfigSettings(config *Config) error {
	var err error
	if err = validateCompliancePolicies(config.SecurityGroupPolicy, "security_group_policy"); err != nil {
		return err
	}
	if err = validateCompliancePolicies(config.EC2Policy, "ec2_policy"); err != nil {
		return err
	}
	if err = validateCompliancePolicies(config.S3Policy, "s3_policy"); err != nil {
		return err
	}

	return nil
}

func validateCompliancePolicies(cPolicies []CompliancePolicy, policyType string) error {
	for _, cp := range cPolicies {
		for _, ac := range cp.APICall {
			for _, cc := range ac.Compliant {
				if cc.PolicyName != cp.Name {
					err := errors.New(fmt.Sprintf("CompliantCheck: %s refers to the wrong %s name (it is '%s', should be '%s').",
						cc.Name, policyType, cc.PolicyName, cp.Name))
					Log.Error(err.Error())
					return err
				}
			}
		}
		var availableActions []string
		for _, action := range cp.Action {
			availableActions = append(availableActions, action.Name)
			if err := validateAction(action); err != nil {
				return err
			}
		}
		for _, trigger := range cp.ActionTrigger {
			for _, triggerAction := range trigger.Action {
				if !ContainsString(availableActions, triggerAction) {
					err := errors.New(fmt.Sprintf("Action: %s cannot be used as trigger action, because it is not defined in configuration file. Available actions: %s.",
						triggerAction, availableActions))
					Log.Error(err.Error())
					return err
				}
			}
		}
		for _, apic := range cp.APICall {
			for _, comp := range apic.Compliant {
				for _, action := range comp.Actions {
					if !ContainsString(availableActions, action) {
						err := errors.New(fmt.Sprintf("Action: %s cannot be used as compliance check action, because it is not defined in config. Available actions: %s.",
							action, availableActions))
						Log.Error(err.Error())
						return err
					}
				}
				if err := validateConditions(comp.Condition); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func validateAction(action Action) error {
	var emailRexp = regexp.MustCompile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,64}$")
	var re, _ = regexp.Compile("^([1-9][0-9]*) (second|minute|hour|day)s?$")

	for _, rec := range action.Email.Receiver {
		if strings.HasPrefix(rec, "{{ ") && strings.HasSuffix(rec, " }}") {
			fieldName := rec
			fieldName = strings.Replace(fieldName, "{{ ", "", 1)
			fieldName = strings.Replace(fieldName, " }}", "", 1)
			if !ContainsString(ValidEmailFieldNames, fieldName) {
				err := errors.New(fmt.Sprintf("Field: %s is unsupported as email receiver.", rec))
				Log.Error(err.Error())
				return err
			}
		} else {
			if !emailRexp.Match([]byte(rec)) {
				err := errors.New(fmt.Sprintf("Email address: %s is invalid.", rec))
				Log.Error(err.Error())
				return err
			}
		}
	}

	hasStartAfterCondition := false
	hasStopAfterCondition := false
	for i := range action.Condition {
		tc := action.Condition[i]
		switch tc.Type {
		case "start_after":
			if hasStartAfterCondition {
				err := errors.New(fmt.Sprintf("Duplicated time condition of type 'start_after' for action '%s'.", action.Name))
				Log.Error(err.Error())
				return err
			}
			hasStartAfterCondition = true
		case "stop_after":
			if hasStopAfterCondition {
				err := errors.New(fmt.Sprintf("Duplicated time condition of type 'stop_after' for action '%s'.", action.Name))
				Log.Error(err.Error())
				return err
			}
			hasStopAfterCondition = true

		default:
			err := errors.New(fmt.Sprintf("Wrong type of time condition '%s' for action '%s'. Allowed values: 'start_after', 'stop_after'.", tc.Value, action.Name))
			Log.Error(err.Error())
			return err
		}
		if !re.MatchString(tc.Value) {
			err := errors.New(fmt.Sprintf("Wrong time condition '%s' for action '%s'.", tc.Value, action.Name))
			Log.Error(err.Error())
			return err
		}
	}
	return nil
}

func validateConditions(conditions []Condition) error {
	for _, condition := range conditions {
		if condition.Type == "tag_pair_exists" || condition.Type == "tag_pair_not_exists" {
			re, _ := regexp.Compile("^K:'([^']*)',V:'([^']*)'$")
			if !re.MatchString(condition.Value) {
				err := errors.New(fmt.Sprintf("Condition: %s has a non compliant value: \"%s\". The value must be in the form \"K:'<the_key>',V:'<the_value>'\".", condition.Name, condition.Value))
				Log.Error(err.Error())
				return err
			}
		}

		if ContainsString(LogicalConditionsTypes, condition.Type) && len(condition.Condition) < 2 {
			err := errors.New(fmt.Sprintf("Condition: %s is a logical condition but does not contain at least two underlaying conditions.",
				condition.Name))
			Log.Error(err.Error())
			return err
		}
		if len(condition.Condition) > 0 {
			if err := validateConditions(condition.Condition); err != nil {
				Log.Error(err.Error())
				return err
			}
		}
	}
	return nil
}

// ***************************************************************************************************************************************
// init functions

func integrateConfigSettings(config *Config) error {

	var err error
	if err = integrateCompliancePolicies(&config.SecurityGroupPolicy); err != nil {
		return err
	}
	if err = integrateCompliancePolicies(&config.EC2Policy); err != nil {
		return err
	}
	if err = integrateCompliancePolicies(&config.S3Policy); err != nil {
		return err
	}

	return nil
}

func integrateCompliancePolicies(cPolicies *[]CompliancePolicy) error {
	re, _ := regexp.Compile("^([1-9][0-9]*) (second|minute|hour|day)s?$")

	for _, policy := range *cPolicies {

		for j, _ := range policy.APICall {
			apicall := policy.APICall[j]
			for k, _ := range apicall.Compliant {
				apicall.Compliant[k].PolicyName = policy.Name
			}
		}

		for j, _ := range policy.Action {
			action := policy.Action[j]
			for k := range action.Condition {

				tc := &action.Condition[k]

				// set the Duration field of the time condition
				subs := re.FindAllStringSubmatch(tc.Value, -1)
				durationVal, _ := strconv.ParseInt(subs[0][1], 10, 64)
				switch subs[0][2] {
				case "day":
					tc.ValueDuration = time.Duration(durationVal) * time.Hour * 24
				case "hour":
					tc.ValueDuration = time.Duration(durationVal) * time.Hour
				case "minute":
					tc.ValueDuration = time.Duration(durationVal) * time.Minute
				case "second":
					tc.ValueDuration = time.Duration(durationVal) * time.Second
				}
				Log.Debugf("Duration value %v.", tc)
			}
		}
	}

	return nil
}

// ***************************************************************************************************************************************
// support functions

func satisfyTestCondition(condition Condition, getResourceProperties func(string) []string, checkName string) bool {

	switch condition.Type {
	case "tag_key_exists":
		if len(getResourceProperties("Tag."+condition.Value)) == 0 {
			Log.Debugf("False condition for the compliance check '%s': Tag '%s' was expected (Condition: '%s')", checkName, condition.Value, condition.Name)
			return false
		}

	case "tag_key_not_exists":
		if len(getResourceProperties("Tag."+condition.Value)) > 0 {
			Log.Debugf("False condition for the compliance check '%s': Tag '%s' was not expected (Condition: '%s')", checkName, condition.Value, condition.Name)
			return false
		}

	case "tag_value_exists":
		if len(getResourceProperties("Tag:Value."+condition.Value)) == 0 {
			Log.Debugf("False condition for the compliance check '%s': Tag value '%s' was expected (Condition: '%s')", checkName, condition.Value, condition.Name)
			return false
		}

	case "tag_value_not_exists":
		if len(getResourceProperties("Tag:Value."+condition.Value)) > 0 {
			Log.Debugf("False condition for the compliance check '%s': Tag value '%s' was not expected (Condition: '%s')", checkName, condition.Value, condition.Name)
			return false
		}

	case "tag_pair_exists": // expected pattern: K:'<thekey>',V:'<thevalue>'
		re := regexp.MustCompile("K:'([^']*)',V:'([^']*)'")
		subms := re.FindAllStringSubmatch(condition.Value, -1)
		if len(subms[0]) == 3 {
			exists := len(getResourceProperties("Tag:Pair."+subms[0][1]+"---"+subms[0][2])) > 0
			if !exists {
				Log.Debugf("False condition for the compliance check '%s': Tag pair K:'%s',V:'%s' was expected (Condition: '%s')", checkName, subms[0][1], subms[0][2], condition.Name)
				return false
			}
		}

	case "tag_pair_not_exists": // expected pattern: K:'<thekey>',V'<thevalue>'
		re := regexp.MustCompile("K:'([^']*)',V:'([^']*)'")
		subms := re.FindAllStringSubmatch(condition.Value, -1)
		if len(subms[0]) == 3 {
			exists := len(getResourceProperties("Tag:Pair."+subms[0][1]+"---"+subms[0][2])) > 0
			if exists {
				Log.Debugf("False condition for the compliance check '%s': Tag pair K:'%s',V:'%s' was not expected (Condition: '%s')", checkName, subms[0][1], subms[0][2], condition.Name)
				return false
			}
		}
	case "AND", "and":
		isSatisfied := true
		for _, cond := range condition.Condition {
			isSatisfied = isSatisfied && satisfyTestCondition(cond, getResourceProperties, checkName)
		}
		if !isSatisfied {
			Log.Debugf("False multiple condition (AND type) for the compliance check '%s'.", checkName)
			return false
		}
	case "OR", "or":
		isSatisfied := false
		for _, cond := range condition.Condition {
			isSatisfied = isSatisfied || satisfyTestCondition(cond, getResourceProperties, checkName)
		}
		if !isSatisfied {
			Log.Debugf("False multiple condition (OR type) for the compliance check '%s'.", checkName)
			return false
		}
	}
	return true
}

/* 	Given an array of CompliantCheckResult (CCR) objects, it returns a new array
without duplicates (i.e., if ccr1.IsSameCheckResult(ccr2) == true ).
*/
func mergeComplianceResults(results []CompliantCheckResult) []CompliantCheckResult {
	var mergedResults []CompliantCheckResult
	for _, res := range results {
		// if the res object is not already in the mergedResults array
		if !contains(&mergedResults, &res) {
			mergedResults = append(mergedResults, res)
		}
	}

	return mergedResults
}

/* 	Return true if the passed CompliantCheckResult object is contained in the passed
array of CompliantCheckResult objects; return false otherwise
*/
func contains(array *[]CompliantCheckResult, isThere *CompliantCheckResult) bool {
	result := false
	if isThere != nil && array != nil && len(*array) > 0 {
		for _, elem := range *array {
			if isThere.IsSameCheckResult(elem) {
				result = true
				break
			}
		}
	}
	return result
}

func ContainsString(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
