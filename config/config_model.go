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
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/hcl"
	"time"
)

var LogicalConditionsTypes = []string{"AND", "OR"}
var ValidEmailFieldNames = []string{"State.Creator", "APIEvent.UserIdentity.ARN", "State.Owner", "State.Operator"}

// Config type
type Config struct {
	Region              string             `hcl:"region"`
	AccessKey           string             `hcl:"access_key"`
	SecretKey           string             `hcl:"secret_key"`
	SecurityGroupPolicy []CompliancePolicy `hcl:"security_group_policy"`
	EC2Policy           []CompliancePolicy `hcl:"ec2_policy"`
	S3Policy            []CompliancePolicy `hcl:"s3_policy"`
	AreBotUserSession   string             `hcl:"arebot_user_session_name"`
	Account             []Account          `hcl:"account"`
	LdapConfig          LdapConfig         `hcl:"ldap_config"`
	S3Config            S3Config           `hcl:"s3_config"`
	SesConfig           SesConfig          `hcl:"ses_config"`
	DynamoDBConfig      DynamoDBConfig     `hcl:"dynamodb_config"`
}

type CompliancePolicy struct {
	Name          string          `hcl:",key"`
	Account       string          `hcl:"account"`
	VpcID         string          `hcl:"vpc"` // default ".*"
	APICall       []APICall       `hcl:"api_call"`
	Action        []Action        `hcl:"action"`
	ActionTrigger []ActionTrigger `hcl:"action_trigger"`
}

/* APICall can have the following values:
   CreateTags
   DeleteTags
   AuthorizeSecurityGroupEgress
   AuthorizeSecurityGroupIngress
   CreateSecurityGroup
   DeleteSecurityGroup
   RevokeSecurityGroupEgress
   RevokeSecurityGroupIngress
*/
type APICall struct {
	Name      string           `hcl:",key"`
	Tag       []TagResource    `hcl:"tag"`
	Compliant []CompliantCheck `hcl:"compliant"`
}

/* TagResource will trigger a resource tagging with a fixed key, value pair
 */
type TagResource struct {
	Name  string `hcl:",key"`
	Key   string `hcl:"key"`
	Value string `hcl:"value"`
}

/* 	CompliantCheck checks whether the resource property "Name" is compliant
with what defined in "Schema"
*/
type CompliantCheck struct {
	Name       string `hcl:",key"`
	PolicyName string `hcl:"policy_name"`
	StateOwner string `hcl:"state_owner"`
	// pattern to check
	Schema string `hcl:"schema"`
	// pattern negation trigger - negate regular extension defined in schema
	Negate      bool        `hcl:"negate"`
	Mandatory   bool        `hcl:"mandatory"`
	Description string      `hcl:"description"`
	Condition   []Condition `hcl:"condition"`
	Actions     []string    `hcl:"actions"`
}

type Condition struct {
	//tag_key_not_exists/tag_value_not_exists vs. tag_key_exists/tag_value_exists
	//Type can be set to 'AND'/'OR' values and then
	Name      string      `hcl:",key"`
	Type      string      `hcl:"type"`
	Value     string      `hcl:"value"`
	Condition []Condition `hcl:"condition"`
}

//type CheckCondition struct {
//	TagKeyExists      string  `hcl:"tag_key_exists"`
//	TagKeyNotExists   string  `hcl:"tag_key_not_exists"`
//	TagValueExists    string  `hcl:"tag_value_exists"`
//	TagValueNotExists string  `hcl:"tag_value_not_exists"`
//}

/* *** ACTIONS *** */

// The action to take in response to a non-compliant check
type Action struct {
	Name      string              `hcl:",key"`
	Email     EmailNotification   `hcl:"email"`
	Condition []TimeCondition     `hcl:"condition"`
	Operation []ResourceOperation `hcl:"operation"`
}

type EmailNotification struct {
	Receiver []string
	Template string // the path to the template
}

type TimeCondition struct {
	Name          string `hcl:",key"`
	Type          string `hcl:"type"` //stop_after/start_after
	Value         string `hcl:"value"`
	ValueDuration time.Duration
}

type ResourceOperation struct {
}

type ActionTrigger struct {
	Name     string   `hcl:",key"`
	Schedule string   `hcl:"schedule"`
	Action   []string `hcl:"action"`
}

/* *** ******* *** */

type Account struct {
	Name            string `hcl:",key"`
	AccountID       string `hcl:"account_id"`
	Region          string `hcl:"region"`
	ArebotRoleArn   string `hcl:"arebot_role_arn"`
	AllEventsQueue  string `hcl:"all_events_queue"`
	RoleSessionName string `hcl:"role_session_name"`
}

type LdapConfig struct {
	LdapHost     string `hcl:"ldap_host"`
	LdapPort     string `hcl:"ldap_port"`
	BindUsername string `hcl:"bind_username"`
	BindPassword string `hcl:"bind_password"`
	SearchBase   string `hcl:"search_base"`
}

type S3Config struct {
	Region        string `hcl:"region"`
	Bucket        string `hcl:"bucket"`
	LocalFolder   string `hcl:"local_folder"`
	ArebotRoleArn string `hcl:"arebot_role_arn"`
}

type SesConfig struct {
	Region        string `hcl:"region"`
	ArebotRoleArn string `hcl:"arebot_role_arn"`
	SenderAddress string `hcl:"sender_address"`
	MessageTopic  string `hcl:"message_topic"`
	MessageBody   string `hcl:"message_body"`
}

type DynamoDBConfig struct {
	Region        string `hcl:"region"`
	ArebotRoleArn string `hcl:"arebot_role_arn"`
}

type CompliantCheckResult struct {
	IsCompliant          bool
	Check                CompliantCheck
	EventUser            EventUserInfo
	EventType            string
	Value, ResourceId    string
	DateAndTypeComposite string
	CreationDate         time.Time
}

type EventUserInfo struct {
	AccountId, Username, EmailAddress, Region string
}

// ParseConfig parse the given HCL string into a Config struct.
func ParseConfig(hclText string) (*Config, error) {
	Log.Debugf("Parsing config: %s", hclText)
	result := &Config{}
	var errors *multierror.Error

	hclParseTree, err := hcl.Parse(hclText)
	if err != nil {
		return nil, err
	}

	if err := hcl.DecodeObject(&result, hclParseTree); err != nil {
		return nil, err
	}

	if err = integrateConfigSettings(result); err != nil {
		return nil, err
	}
	if err = validateConfigSettings(result); err != nil {
		return nil, err
	}

	Log.Infof("Starting with config %v", result)

	return result, errors.ErrorOrNil()
}
