package core

import (
	"io/ioutil"
	"testing"
	"time"

	"github.com/kreuzwerker/arebot/cloudwatch"
	"github.com/kreuzwerker/arebot/config"
	"github.com/kreuzwerker/arebot/resource/securitygroup"
	"github.com/kreuzwerker/arebot/util"

	"github.com/aws/aws-sdk-go/service/ec2"
)

func strHelper(s string) *string {
	x := new(string)
	*x = s
	return x
}

func intHelper(i int64) *int64 {
	x := new(int64)
	*x = i
	return x
}

func TestIgnoreEvent(t *testing.T) {
	awsEvent := cloudwatch.AWSEvent{
		ApiCall:          "CreateSecurityGroup",
		RequestParameter: nil,
		Event: cloudwatch.Event{
			ID:         "5afe66f1-7fc6-410a-83cf-1ba77cb14c8d",
			DetailType: "AWS API Call via CloudTrail",
			Source:     "aws.ec2",
			Account:    "000000000000",
			Time:       time.Time{},
			Region:     "eu-central-1",
			Resources:  nil,
			Detail:     []byte{},
		},
		ApiDetail: cloudwatch.APIDetail{
			EventID:             "793fc880-58cc-4126-86df-67045515f912",
			EventName:           "CreateSecurityGroup",
			EventSource:         "ec2.amazonaws.com",
			EventTime:           time.Time{},
			EventType:           "AwsApiCall Event Version: 1.05",
			AWSRegion:           "eu-central-1",
			AdditionalEventData: nil,
			RequestParams:       []byte{},
			ResponseElements:    nil,
			SourceIPAddress:     "84.177.42.212",
			UserAgent:           "signin.amazonaws.com",
			UserIdentity: cloudwatch.UserIdentity{
				Type:           "IAMUser",
				PrincipleID:    "ABCDEFGHIJKLMNOPQRST0",
				ARN:            "arn:aws:iam::000000000000:user/dev",
				AccountID:      "000000000000",
				SessionContext: nil,
			},
		},
	}

	// config with RoleSessionName
	Cfg, _ = config.ParseConfig(handleEventsConfigTestFixure1)
	ignore, _ := ignoreEvent(awsEvent)
	if ignore {
		t.Errorf("Event shouldn't be ignored: %+v", awsEvent)
	}
	awsEvent.ApiDetail.UserIdentity.ARN = "arn:aws:sts::000000000000:assumed-role/arebot/session"
	ignore, _ = ignoreEvent(awsEvent)
	if !ignore {
		t.Errorf("Event should be ignored: %+v", awsEvent)
	}
	awsEvent.ApiDetail.UserIdentity.ARN = "arn:aws:sts::000000000000:assumed-role/arebot/123456Session"
	ignore, _ = ignoreEvent(awsEvent)
	if ignore {
		t.Errorf("Event shouldn't be ignored: %+v", awsEvent)
	}

	// config with no RoleSessionName
	awsEvent.Event.Account = "111111111111"
	awsEvent.ApiDetail.UserIdentity.ARN = "arn:aws:sts::111111111111:assumed-role/arebot/123456789"
	ignore, _ = ignoreEvent(awsEvent)
	if !ignore {
		t.Errorf("Event should be ignored: %+v", awsEvent)
	}
	awsEvent.ApiDetail.UserIdentity.ARN = "arn:aws:iam::111111111111:user/dev"
	ignore, _ = ignoreEvent(awsEvent)
	if ignore {
		t.Errorf("Event shouldn't be ignored: %+v", awsEvent)
	}
}

const handleEventsConfigTestFixure1 = `

account "account-test" {
  account_id = "000000000000"
  region = "eu-central-1"
  arebot_role_arn = "arn:aws:iam::000000000000:role/arebot"
  all_events_queue = "all_events"
	role_session_name = "session"
}
account "account-prod" {
  account_id = "111111111111"
  region = "eu-central-1"
  arebot_role_arn = "arn:aws:iam::111111111111:role/arebot"
  all_events_queue = "all_events"
}
`

func TestHandleEvent(t *testing.T) {
	awsEvent := cloudwatch.AWSEvent{
		ApiCall: "CreateSecurityGroup",
		RequestParameter: map[string]interface{}{
			"groupName":        "test",
			"groupDescription": "test",
			"vpcId":            "vpc-0000aaaa",
		},
		Event: cloudwatch.Event{
			ID:         "5afe66f1-7fc6-410a-83cf-1ba77cb14c8d",
			DetailType: "AWS API Call via CloudTrail",
			Source:     "aws.ec2",
			Account:    "222233334444",
			Time:       time.Time{},
			Region:     "eu-central-1",
			Resources:  nil,
			Detail:     []byte{},
		},
		ApiDetail: cloudwatch.APIDetail{
			EventID:             "793fc880-58cc-4126-86df-67045515f912",
			EventName:           "CreateSecurityGroup",
			EventSource:         "ec2.amazonaws.com",
			EventTime:           time.Time{},
			EventType:           "AwsApiCall Event Version: 1.05",
			AWSRegion:           "eu-central-1",
			AdditionalEventData: nil,
			RequestParams:       []byte{},
			ResponseElements: map[string]interface{}{
				"_return": "true",
				"groupId": "sg-aa00bb11",
			},
			SourceIPAddress: "84.177.42.212",
			UserAgent:       "signin.amazonaws.com",
			UserIdentity: cloudwatch.UserIdentity{
				Type:           "IAMUser",
				PrincipleID:    "ABCDEFGHIJKLMNOPQRST0",
				ARN:            "arn:aws:iam::222233334444:user/dev",
				AccountID:      "222233334444",
				SessionContext: nil,
			},
		},
	}

	configFile, err := ioutil.ReadFile("./test/sg.cfg")
	if err != nil {
		panic(err)
	}
	Cfg, err = config.ParseConfig(string(configFile[:]))
	if err != nil {
		panic(err)
	}
	securitygroup.Cfg = Cfg
	util.Cfg = Cfg
	HandleAWSEvent(awsEvent)
}

func TestCompliantCheckCondition(t *testing.T) {

	Cfg, _ := config.ParseConfig(string(configCheckConditions[:]))
	event, err := cloudwatch.DecodeEvent([]byte(createNonCompliantTagNameEvent))
	if err != nil {
		t.Error(err)
	}

	sgFalseCondition, _ := securitygroup.NewSecurityGroupWithStatus("sg-11bbcc22", "222233334444", func(id string, account string) (*ec2.DescribeSecurityGroupsOutput, error) {
		return &ec2.DescribeSecurityGroupsOutput{
			SecurityGroups: []*ec2.SecurityGroup{
				{
					GroupId:   strHelper("sg-11bbcc22"),
					GroupName: strHelper("Test"),
					Tags: []*ec2.Tag{
						{
							Key:   strHelper("Name"),
							Value: strHelper("Test"),
						},
						{
							Key:   strHelper("OtherTag"),
							Value: strHelper("OtherValue"),
						},
					},
					VpcId: strHelper("vpc-0000aaaa"),
				},
			},
		}, nil
	})

	sgTrueCondition, _ := securitygroup.NewSecurityGroupWithStatus("sg-11bbcc22", "222233334444", func(id string, account string) (*ec2.DescribeSecurityGroupsOutput, error) {
		return &ec2.DescribeSecurityGroupsOutput{
			SecurityGroups: []*ec2.SecurityGroup{
				{
					GroupId:   strHelper("sg-11bbcc22"),
					GroupName: strHelper("Test"),
					Tags: []*ec2.Tag{
						{
							Key:   strHelper("Name"),
							Value: strHelper("Test"),
						},
					},
					VpcId: strHelper("vpc-0000aaaa"),
				},
			},
		}, nil
	})

	eventuser := config.EventUserInfo{AccountId: "222233334444", Username: "dev"}

	// CHECK FALSE CONDITION
	Log.Debugf("Checking false AND condition.")
	_, apicallsCfg := Cfg.GetAPICallConfigs(event.ApiCall, eventuser.AccountId, *sgFalseCondition.State.VpcId, "security_group")
	Log.Debugf("event_handler.handleSecurityGroupEvent: checking compliance %+v", apicallsCfg[0])
	results := apicallsCfg[0].CheckCompliance(sgFalseCondition.GetProperties, *sgFalseCondition.State.GroupId, eventuser)
	if len(results) > 0 {
		t.Errorf("The compliant check 'Tag.Name' should not have been performed because of false AND conditions.")
	}

	// CHECK TRUE CONDITION
	Log.Debugf("Checking true AND condition.")
	_, apicallsCfg = Cfg.GetAPICallConfigs(event.ApiCall, eventuser.AccountId, *sgTrueCondition.State.VpcId, "security_group")
	Log.Debugf("event_handler.handleSecurityGroupEvent: checking compliance %+v", apicallsCfg[0])
	results = apicallsCfg[0].CheckCompliance(sgTrueCondition.GetProperties, *sgTrueCondition.State.GroupId, eventuser)
	if len(results) == 0 {
		t.Errorf("The compliant check 'Tag.Name' should have been performed because of true AND conditions.")
	}

}

const configCheckConditions = `
security_group_policy "XXX" {
  api_call "CreateTags" {
	compliant "Tag.Name" {
	  schema = "[A-Z].*"
	  actions = [ "doNothing" ]

	  condition "MultipleAND" {
		type = "AND"
		condition "NoOtherTag" {
		  type = "tag_pair_not_exists"
		  value = "K:'OtherTag',V:'OtherValue'"
		}
		condition "HasNameTagKey" {
		  type = "tag_key_exists"
		  value = "Name"
		}
	  }
	}
  }

  action "doNothing" {}
}
`

const createNonCompliantTagNameEvent = `{
	"version": "0",
	"id": "65a4aa53-471e-4565-bbe0-c35e3dde226b",
	"detail-type": "AWS API Call via CloudTrail",
	"source": "aws.ec2",
	"account": "222233334444",
	"time": "2017-04-12T19:28:59Z",
	"region": "eu-central-1",
	"resources": [],
	"detail": {
		"eventVersion": "1.05",
		"userIdentity": {
			"type": "IAMUser",
			"principalId": "ABCDEFGHIJKLMNOPQRST0",
			"arn": "arn:aws:iam::222233334444:user/dev",
			"accountId": "222233334444",
			"accessKeyId": "ASIAJWTQ7CEH5SXNF7DQ",
			"userName": "dev",
			"sessionContext": {
				"attributes": {
					"mfaAuthenticated": "false",
					"creationDate": "2017-04-12T19:04:35Z"
				}
			},
			"invokedBy": "signin.amazonaws.com"
		},
		"eventTime": "2017-04-12T19:28:59Z",
		"eventSource": "ec2.amazonaws.com",
		"eventName": "CreateTags",
		"awsRegion": "eu-central-1",
		"sourceIPAddress": "84.177.42.212",
		"userAgent": "signin.amazonaws.com",
		"requestParameters": {
			"resourcesSet": {
				"items": [{
					"resourceId": "sg-11bbcc22"
				}]
			},
			"tagSet": {
				"items": [{
					"key": "Name",
					"value": "NonCompliantName"
				}]
			}
		},
		"responseElements": {
			"_return": true
		},
		"requestID": "2d901ea6-0253-43b5-bfc4-ed63f59c76a5",
		"eventID": "bb096886-331c-4b12-9a78-73b793e1f383",
		"eventType": "AwsApiCall"
	}
}
`
