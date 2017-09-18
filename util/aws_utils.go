package util

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/kreuzwerker/arebot/config"
	"github.com/kreuzwerker/arebot/ldap"
	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ses"
)

var (
	// Log Logger for this package
	Log = newLogger()
	// Cfg Config for this package
	Cfg *config.Config
)

type AwsResourceType interface {
	GetId()					string
	GetProperties(string)	[]string
}

func newLogger() *logrus.Logger {
	_log := logrus.New()
	_log.Out = os.Stdout
	_log.Formatter = &logrus.TextFormatter{FullTimestamp: true}
	_log.Level = logrus.DebugLevel
	return _log
}

func GetAWSConfig(accountID string) *aws.Config {
	var account *config.Account

	if account = Cfg.GetAccount(accountID); account == nil {
		Log.Infof("Error: no account configuration found for ID: %s", accountID)
		return nil
	}

	sess := session.Must(session.NewSession())

	// credentials can be defined with optional session string used for the request ARN
	// if this is defined in the config we add it here in order to identify our own
	// API calls later on. If nothing is configured a ramdom string will be used.
	var creds *credentials.Credentials
	if len(Cfg.GetAccountRoleArnSession(accountID)) > 0 {
		creds = stscreds.NewCredentials(sess, account.ArebotRoleArn, func(p *stscreds.AssumeRoleProvider) {
			p.RoleSessionName = Cfg.GetAccountRoleArnSession(accountID)
		})
	} else {
		creds = stscreds.NewCredentials(sess, account.ArebotRoleArn)
	}
	return &aws.Config{Credentials: creds, Region: &account.Region}
}

func GetS3Config() *aws.Config {
	sess := session.Must(session.NewSession())

	creds := stscreds.NewCredentials(sess, Cfg.S3Config.ArebotRoleArn)
	return &aws.Config{Credentials: creds, Region: &Cfg.S3Config.Region}
}

func GetSesConfig() *aws.Config {
	sess := session.Must(session.NewSession())

	creds := stscreds.NewCredentials(sess, Cfg.SesConfig.ArebotRoleArn)
	return &aws.Config{Credentials: creds, Region: &Cfg.SesConfig.Region}
}

func GetDynamoDBConfig() *aws.Config {
	sess := session.Must(session.NewSession())

	creds := stscreds.NewCredentials(sess, Cfg.DynamoDBConfig.ArebotRoleArn)
	return &aws.Config{Credentials: creds, Region: &Cfg.DynamoDBConfig.Region}
}

/*
Describe security group current state getter 123Test123 172.31.18.11
*/
func DescribeSecurityGroupById(id string, accountID string) (*ec2.DescribeSecurityGroupsOutput, error) {

	cfg := GetAWSConfig(accountID)
	if cfg == nil {
		return nil, errors.New("Can't describe resource ID: " + id)
	}

	sess := session.Must(session.NewSession())
	svc := ec2.New(sess, cfg)

	params := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []*string{
			aws.String(id),
		},
	}
	resp, err := svc.DescribeSecurityGroups(params)

	if err != nil {
		return nil, err
	}

	// Pretty-print the response data.
	//Log.Println(resp)
	return resp, nil
}

/*
Describe EC2 instance
*/
func DescribeEC2ById(id string, accountID string) (*ec2.Reservation, error) {

cfg := GetAWSConfig(accountID)
if cfg == nil {
	return nil, errors.New("Can't describe resource ID: " + id)
}

sess := session.Must(session.NewSession())
svc := ec2.New(sess, cfg)

params := &ec2.DescribeInstancesInput{
	InstanceIds: []*string{
		aws.String(id),
	},
}
resp, err := svc.DescribeInstances(params)

if err != nil {
	return nil, err
}
return resp.Reservations[0], nil
}

/*
Describe Volume instance
*/
func DescribeVolumeById(id string, accountID string) (*ec2.Volume, error) {

	cfg := GetAWSConfig(accountID)
	if cfg == nil {
		return nil, errors.New("Can't describe resource ID: " /*+ sg.ID*/)
	}

	sess := session.Must(session.NewSession())
	svc := ec2.New(sess, cfg)

	params := &ec2.DescribeVolumesInput{
		VolumeIds: []*string{
			aws.String(id),
		},
	}
	resp, err := svc.DescribeVolumes(params)

	if err != nil {
		return nil, err
	}
	return resp.Volumes[0], nil
}

/*
Describe Snapshot instance
*/
func DescribeSnapshotById(id string, accountID string) (*ec2.Snapshot, error) {

	cfg := GetAWSConfig(accountID)
	if cfg == nil {
		return nil, errors.New("Can't describe resource ID: " /*+ sg.ID*/)
	}

	sess := session.Must(session.NewSession())
	svc := ec2.New(sess, cfg)

	params := &ec2.DescribeSnapshotsInput{
		SnapshotIds: []*string{
			aws.String(id),
		},
	}
	resp, err := svc.DescribeSnapshots(params)

	if err != nil {
		return nil, err
	}
	return resp.Snapshots[0], nil
}

func DescribeSecurityGroupsByTag(accountID string, tagKey string, tagValue string) (*ec2.DescribeSecurityGroupsOutput, error) {

	cfg := GetAWSConfig(accountID)
	if cfg == nil {
		return nil, errors.New("Can't describe resource ID: " /*+ sg.ID*/)
	}

	sess := session.Must(session.NewSession())
	svc := ec2.New(sess, cfg)

	var filters []*ec2.Filter
	if tagKey != "" {
		filters = append(filters, &ec2.Filter{Name: aws.String("tag-key"), Values: []*string{aws.String(tagKey)}})
	}

	if tagValue != "" {
		filters = append(filters, &ec2.Filter{Name: aws.String("tag-value"), Values: []*string{aws.String(tagValue)}})
	}

	params := &ec2.DescribeSecurityGroupsInput{
		Filters: filters,
	}
	resp, err := svc.DescribeSecurityGroups(params)

	if err != nil {
		return nil, err
	}

	// Pretty-print the response data.
	//Log.Println(resp)
	return resp, nil
}

func ParseEC2ResponseRunStartInstance(response interface{}, property string) (string, error) {
	respMap := response.(map[string]interface{})
	isets := (respMap["instancesSet"].(map[string]interface{}))["items"].([]interface{})
	propMap := isets[0].(map[string]interface{})

	result := propMap[property]
	if result == nil {
		err := errors.New("aws_utils: Error parsing RunInstances/StartInstances response elements. Cannot find the " + property + " property.")
		return "", err
	} else {
		return result.(string), nil
	}
}

func FindEmailBasedOnUserIdentity(accountID string, userIdentity map[string]string) string {
	userName := userIdentity["name"]
	if userName == "" {
		return ""
	}
	return FindEmailBasedOnUserName(userName)
}

func FindEmailBasedOnUserName(userName string) string {
	if strings.Contains(userName, "/") {
		userName = strings.Split(userName, "/")[1]
	}
	ldapConfig := Cfg.GetLdapConfig()
	filter := fmt.Sprintf("(sAMAccountName=%s)", userName)
	attributes := []string{"sAMAccountName", "mail", "cn", "userPrincipalName"}
	ldapPort, err := strconv.Atoi(ldapConfig.LdapPort)
	if err != nil {
		return ""
	}
	result, err := ldap.LdapLookup(ldapConfig.LdapHost, ldapPort, ldapConfig.BindUsername, ldapConfig.BindPassword,
		ldapConfig.SearchBase, filter, attributes)
	if err != nil {
		Log.Warnf("Ldap lookup for username: %s not successfull.", userName)
		return ""
	}
	if len(result.Entries) > 0 {
		return result.Entries[0].GetAttributeValue("mail")
	}
	return ""
}

// TODO send reports of multiple check results
func SendEmail(emailAddress string, result config.CompliantCheckResult, template string) error {

	cfg := GetSesConfig()
	Log.Infof("Sending email to: %s", emailAddress)
	sess := session.Must(session.NewSession())
	svc := ses.New(sess, cfg)

	// Mail Subject
	finalSubject := strings.Replace(Cfg.SesConfig.MessageTopic, "{{State.Operator}}", result.EventUser.Username, -1)
	finalSubject = strings.Replace(finalSubject, "{{Region}}", result.EventUser.Region, -1)

	// Mail body
	var finalMessageBody string
	var msgBodyErr error

	if template == "" {
		finalMessageBody, msgBodyErr = createMessageBody(result, "standard")
	} else {
		finalMessageBody, msgBodyErr = createMessageBody(result, template)
	}

	if msgBodyErr != nil {
		return errors.New("Message body creation failed: " + msgBodyErr.Error())
	}

	message := &ses.SendEmailInput{
		Source:      aws.String(Cfg.SesConfig.SenderAddress),
		Destination: &ses.Destination{ToAddresses: []*string{aws.String(emailAddress)}},
		Message: &ses.Message{
			Subject: &ses.Content{Data: aws.String(finalSubject)},
			Body:    &ses.Body{Html: &ses.Content{Data: aws.String(finalMessageBody)}},
		},
	}
	output, err := svc.SendEmail(message)
	if err != nil {
		return errors.New("Failed delivery: " + err.Error())
	}
	Log.Info(output)

	return nil
}
