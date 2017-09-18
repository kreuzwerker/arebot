package securitygroup

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/kreuzwerker/arebot/config"
	"github.com/kreuzwerker/arebot/util"
)

var (
	// Log Logger for this package
	Log = newLogger()
	// Cfg Config for this package
	Cfg *config.Config
)

func newLogger() *logrus.Logger {
	_log := logrus.New()
	_log.Out = os.Stdout
	_log.Formatter = &logrus.TextFormatter{FullTimestamp: true}
	_log.Level = logrus.DebugLevel
	return _log
}

// SecurityGroupError error definition
type SecurityGroupError struct {
	id     string
	msg    string
	Ignore bool
}

func (e SecurityGroupError) Error() string {
	return fmt.Sprintf("SecurityGroup error %s: %s", e.id, e.msg)
}

// NewSecurityGroupError create new SecurityGroupError
func NewSecurityGroupError(id, msg string, ignore bool) SecurityGroupError {
	return SecurityGroupError{id: id, msg: msg, Ignore: ignore}
}

type SecurityGroup struct {
	State  *ec2.SecurityGroup
}

// NewSecurityGroup create a new SecurityGroup object
func NewSecurityGroup(sgout *ec2.SecurityGroup) SecurityGroup {
	sg := SecurityGroup{}
	if sgout == nil {
		sgout = new(ec2.SecurityGroup)
	}

	sg.State = sgout
	return sg
}

// NewSecurityGroupWithStatus create a new SecurityGroup object including the current status of the AWS resource
func NewSecurityGroupWithStatus(sgID string, accountID string, describeFunc ...func(string, string) (*ec2.DescribeSecurityGroupsOutput, error)) (SecurityGroup, error) {
	desc := NewSecurityGroup(nil)

	var state *ec2.DescribeSecurityGroupsOutput
	var err error
	// check for function that returns the current state of the security group and use it
	if len(describeFunc) == 1 {
		state, err = describeFunc[0](sgID, accountID)
	} else {
		state, err = util.DescribeSecurityGroupById(sgID, accountID)
	}

	if err != nil {
		Log.Errorf("security_group.NewSecurityGroupWithStatus: %s", err)
		return desc, NewSecurityGroupError(sgID, err.Error(), true)
	}

	desc.State = state.SecurityGroups[0]

	return desc, nil
}

func FindAllSecGroupsWithTag(tagKey string, tagValue string) ([]SecurityGroup, error) {
	var result []SecurityGroup
	for _, account := range Cfg.Account {
		groups, err := util.DescribeSecurityGroupsByTag(account.AccountID, tagKey, tagValue)
		if err != nil {
			Log.Errorf("security_group.FindAllSecGroupsWithTag: %s", err)
			return nil, err
		}
		for _, group := range groups.SecurityGroups {
			result = append(result, NewSecurityGroup(group))
		}
	}
	return result, nil
}

// GetProperties returns the given properties for <key> argument
func (sg *SecurityGroup) GetProperties(key string) []string {
	/*
					   GroupName
				     IpPermissions(Ingress)
				     IpPermissionsEgress
		          FromPort
		          toPort
		          IpProtocol
		          IpRange.CidrIp
		          UserIdGroupPairs
		            GroupId
				     Tags
		          key
		          Value
				     VpcId
	*/
	var result []string

	splitKey := strings.Split(key, ".")
	Log.Debugf("SecurityGroup Property keys: %+v", splitKey)

	switch splitKey[0] {
	case "GroupName":
		if sg.State.GroupName != nil {
			Log.Debugf("SecurityGroup.GetProperties: Found GroupName: %s", fmt.Sprintf("%s", *sg.State.GroupName))
			result = append(result, *sg.State.GroupName)
		}
		return result

	case "IpPermissions":
		if len(splitKey) < 2 {
			return nil
		}
		switch splitKey[1] {

		case "FromPort", "ToPort":
			for _, x := range sg.State.IpPermissions {
				v := reflect.ValueOf(x).Elem()
				n := v.FieldByName(splitKey[1])

				for _, ipr := range x.IpRanges {
					resultFormat := "P:" + *x.IpProtocol + ";FP:" + strconv.Itoa(int(*x.FromPort)) + ";TP:" + strconv.Itoa(int(*x.ToPort)) + ";IP:" + *ipr.CidrIp
					Log.Debugf("SecurityGroup.GetProperties: Found %s: %d\n\tAdd result: %s", splitKey[1], n.Elem(), resultFormat)
					// convert reflect.Value == int64 to string type is kind of hard
					result = append(result, resultFormat)
				}
				for _, ugp := range x.UserIdGroupPairs {
					resultFormat := "P:" + *x.IpProtocol + ";FP:" + strconv.Itoa(int(*x.FromPort)) + ";TP:" + strconv.Itoa(int(*x.ToPort)) + ";UG:" + *ugp.UserId + "/" + *ugp.GroupId
					Log.Debugf("SecurityGroup.GetProperties: Found %s: %d\n\tAdd result: %s", splitKey[1], n.Elem(), resultFormat)
					// convert reflect.Value == int64 to string type is kind of hard
					result = append(result, resultFormat)
				}
			}
		case "IpRanges":
			for _, x := range sg.State.IpPermissions {
				for _, ipr := range x.IpRanges {
					resultFormat := "P:" + *x.IpProtocol + ";FP:" + strconv.Itoa(int(*x.FromPort)) + ";TP:" + strconv.Itoa(int(*x.ToPort)) + ";IP:" + *ipr.CidrIp
					Log.Debugf("SecurityGroup.GetProperties: Found %s: %s\n\tAdd result: %s", splitKey[1], *ipr.CidrIp, resultFormat)
					// convert reflect.Value == int64 to string type is kind of hard
					result = append(result, resultFormat)
				}
			}

		case "UserIdGroupPairs":
			if len(splitKey) < 3 {
				return nil
			}
			switch splitKey[2] {
			case "GroupId", "UserId":
				for _, x := range sg.State.IpPermissions {
					for _, p := range x.UserIdGroupPairs {

						v := reflect.ValueOf(p).Elem()
						n := v.FieldByName(splitKey[2])

						resultFormat := "P:" + *x.IpProtocol + ";FP:" + strconv.Itoa(int(*x.FromPort)) + ";TP:" + strconv.Itoa(int(*x.ToPort)) + ";UG:" + *p.UserId + "/" + *p.GroupId
						Log.Debugf("SecurityGroup.GetProperties: Found %s: %s\n\tAdd result: %s", splitKey[2], n.Elem(), resultFormat)
						result = append(result, resultFormat)
					}
				}
			default:
				Log.Warnf("Configuration IpPermissions.UserIdGroupPairs.%s is not supported!", splitKey[2])
			}
		default:
			Log.Warnf("Configuration IpPermissions.%s is not supported!", splitKey[1])
		}
	case "Tag":
		for _, t := range sg.State.Tags {
			if t.Key != nil && *t.Key == splitKey[1] {
				Log.Debugf("SecurityGroup.GetProperties: Found Tag: `%s: %s`", *t.Key, *t.Value)
				result = append(result, *t.Value)
			}
		}
	case "Tag:Value":
		value := strings.Split(key, "Tag:Value.")
		for _, t := range sg.State.Tags {
			if t.Value != nil && *t.Value == value[1] {
				Log.Debugf("SecurityGroup.GetProperties: Found Tag with Value: `%s: %s`", *t.Key, *t.Value)
				result = append(result, *t.Value)
			}
		}
	case "Tag:Pair":
		value := strings.Split(key, "Tag:Pair.")
		pair := strings.Split(value[1], "---")
		for _, t := range sg.State.Tags {
			// Log.Debugf(">>> %s == %s ? %t ; %s == %s ? %t", *t.Key, pair[0], *t.Key == pair[0], *t.Value, pair[1], *t.Value == pair[1])
			if t.Key != nil && *t.Key == pair[0] && t.Value != nil && *t.Value == pair[1] {
				Log.Debugf("SecurityGroup.GetProperties: Found Tag with pair: `%s - %s`", *t.Key, *t.Value)
				result = append(result, *t.Value)
			}
		}
	}

	return result
}

func (sg *SecurityGroup) GetId() string {
	return *sg.State.GroupId
}

/*
TagCreator Tag security group with the user identity given in the event
*/
func (sg SecurityGroup) TagCreator(ui map[string]string) error {
	creator := ui["name"]
	switch ui["entity"] {
	case "assumed-role":
		name := strings.Split(ui["name"], "/")
		Log.Printf("user: %s", name[1])
	case "user":
		Log.Printf("user: %s", ui["name"])
	}

	return sg.Tag("Creator", creator)
}

func (sg SecurityGroup) Tag(key string, value string) error {
	Log.Printf("Tagging %s with: `%s: %s`", *sg.State.GroupId, key, value)

	cfg := util.GetAWSConfig(*sg.State.OwnerId)
	if cfg == nil {
		return errors.New("Can't describe resource ID: " /*+ sg.ID*/)
	}

	sess := session.Must(session.NewSession())
	svc := ec2.New(sess, cfg)

	params := &ec2.CreateTagsInput{
		Resources: []*string{ // Required
			aws.String(*sg.State.GroupId), // Required
		},
		Tags: []*ec2.Tag{ // Required
			{ // Required
				Key:   aws.String(key),
				Value: aws.String(value),
			},
			// More values...
		},
	}
	_, err := svc.CreateTags(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		Log.Println(err.Error())
		return err
	}

	return nil
}
