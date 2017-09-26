package cloudwatch

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
	"reflect"
	"testing"
	"time"

	"github.com/kreuzwerker/arebot/config"
)

func TestMain(m *testing.M) {
	//mySetupFunction()
	Log = newLogger()
	retCode := m.Run()
	//   myTeardownFunction()
	os.Exit(retCode)
}

func TestRequestParameter(t *testing.T) {
	event, err := DecodeEvent([]byte(createTags2))
	if err != nil {
		t.Error(err)
	}

	x := event.RequestParameter.(*CreateTagsRequestParameters)

	//fmt.Printf("RequestParameter: %+v\n", x.ResourcesSet.Items[0]["resourceId"])
	if x.ResourcesSet.Items[0]["resourceId"] != "sg-00aa11bb" {
		t.Errorf("resourceId doesn't match: %v", x.ResourcesSet.Items[0]["resourceId"])
	}

}

func TestStateEvent(t *testing.T) {
	event, err := DecodeEvent([]byte(ec2StateEvent))
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("StateEvent: %+v\n", event)
	//fmt.Println(event.Detail.UserIdentity.ARN)

}

func TestDecodeEvent(t *testing.T) {
	expected := &ApiEvent{
		ID:         "5afe66f1-7fc6-410a-83cf-1ba77cb14c8d",
		DetailType: "AWS API Call via CloudTrail",
		Source:     "aws.ec2",
		Account:    "222233334444",
		Time:       time.Date(2017, time.April, 11, 20, 27, 47, 0, time.UTC), //"2017-04-11 20:27:47 +0000 UTC",
		Region:     "eu-central-1",
		Resources:  []string{},
		Detail: APIDetail{
			EventID:             "793fc880-58cc-4126-86df-67045515f912",
			EventName:           "CreateSecurityGroup",
			EventSource:         "ec2.amazonaws.com",
			EventTime:           time.Date(2017, time.April, 11, 20, 27, 47, 0, time.UTC), //"2017-04-11 20:27:47 +0000 UTC",
			EventType:           "AwsApiCall",
			EventVersion:        "1.05",
			AWSRegion:           "eu-central-1",
			AdditionalEventData: nil,
			SourceIPAddress: "84.177.42.212",
			UserAgent:       "signin.amazonaws.com",
			UserIdentity: UserIdentity{
				Type:        "IAMUser",
				PrincipleID: "ABCDEFGHIJKLMNOPQRST0",
				ARN:         "arn:aws:iam::222233334444:user/dev",
				AccountID:   "222233334444",
			},
			RequestParams: []byte(`{"groupName":"test","groupDescription":"test","vpcId":"vpc-22cc33dd"}`),
		},
	}

	expectedRequestParams := CreateSecurityGroupRequestParameters{
		GroupName:        "test",
		GroupDescription: "test",
		VpcId:            "vpc-22cc33dd",
	}
	event, err := DecodeEvent([]byte(testEvent))
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("API: %+v\n", event)

	if !reflect.DeepEqual(event.ApiDetail, expected.Detail) {
		fmt.Printf("%+v\n%+v", event.ApiDetail.RequestParams, expected.Detail.RequestParams)
		t.Error("event structure differed from expectation")
	}
	if !reflect.DeepEqual(event.RequestParameter, &expectedRequestParams) {
		fmt.Printf("%+v - %+v", event.RequestParameter, &expectedRequestParams)
		t.Error("event structure differed from expectation")
	}
	user, err := event.ApiDetail.ParseUserIdentity()
	if err != nil || user["arn"] != "arn:aws:iam::222233334444:user/dev" {
		t.Error("user identity arn doesn't match")
	}
	if err != nil || user["name"] != "dev" {
		t.Error("user identity arn doesn't match")
	}

	event.ApiDetail.UserIdentity.ARN = "arn:aws:iam::000000000000:role/arebot/session"
	user, err = event.ApiDetail.ParseUserIdentity()
	if err != nil || user["name"] != "arebot/session" {
		t.Errorf("user identity arn doesn't match %s", user)
	}
}

func TestSetTag(t *testing.T) {

	user := "arn:aws:iam::222233334444:user/dev.arebot@kreuzwerker.de"
	userEmail := "dev.arebot@kreuzwerker.de"
	e := AWSEvent{
		ApiDetail: APIDetail{
			UserIdentity: UserIdentity{
				Type:        "IAMUser",
				PrincipleID: "ABCDEFGHIJKLMNOPQRST0",
				ARN:         user,
				AccountID:   "222233334444",
			},
		},
	}

	cfg, err := config.ParseConfig(settag_ARN)
	if err != nil {
		t.Error(err)
	}
	_, apicallsConfigs := cfg.GetAPICallConfigs("CreateSecurityGroup", "", "", "security_group")
	Log.Printf("XXX: %+v %s", apicallsConfigs, reflect.TypeOf(apicallsConfigs))

	for _, apicallCfg := range apicallsConfigs {
		Log.Printf("cfg: %+v", apicallCfg)

		apicallCfg.SetTag(e.GetValueFromTemplate, func(key string, value string) error {
			if value != user {
				t.Errorf("user identity arn %s doesn't match %s", value, user)
			}
			return nil
		}, func(arg4 string, arg5 string) {
			return
		})

		cfg, err = config.ParseConfig(settag_NAME)
		if err != nil {
			t.Error(err)
		}
		_, apicallsConfigs := cfg.GetAPICallConfigs("CreateSecurityGroup", "", "", "security_group")
		Log.Printf("XXX: %+v %s", apicallsConfigs, reflect.TypeOf(apicallsConfigs))

		for _, apicallCfg := range apicallsConfigs {
			//Log.Printf("%+v", e)
			Log.Printf("cfg: %+v", apicallCfg)

			apicallCfg.SetTag(e.GetValueFromTemplate, func(key string, value string) error {
				if value != userEmail {
					t.Errorf("user identity arn %s doesn't match %s", value, userEmail)
				}
				return nil
			}, func(arg4 string, arg5 string) {
				return
			})
		}
	}
}

const settag_ARN = `
security_group "tag" {
	api_call "CreateSecurityGroup" {
		tag "TagOwnerARN" {
			key = "Owner"
			value = "{{ .ApiDetail.UserIdentity.ARN }}"
		}
	}
}`

const settag_NAME = `
security_group "tag" {
	api_call "CreateSecurityGroup" {
		tag "TagOwnerEmail" {
			key = "Owner"
			value = "{{ . | UIDName}}"
		}
	}
}`

const testEvent = `{
	"version": "0",
	"id": "5afe66f1-7fc6-410a-83cf-1ba77cb14c8d",
	"detail-type": "AWS API Call via CloudTrail",
	"source": "aws.ec2",
	"account": "222233334444",
	"time": "2017-04-11T20:27:47Z",
	"region": "eu-central-1",
	"resources": [],
	"detail": {
		"eventVersion": "1.05",
		"userIdentity": {
			"type": "IAMUser",
			"principalId": "ABCDEFGHIJKLMNOPQRST0",
			"arn": "arn:aws:iam::222233334444:user/dev",
			"accountId": "222233334444",
			"accessKeyId": "ASIAITFPQZEVIZBAUPPA",
			"userName": "dev",
			"invokedBy": "signin.amazonaws.com"
		},
		"eventTime": "2017-04-11T20:27:47Z",
		"eventSource": "ec2.amazonaws.com",
		"eventName": "CreateSecurityGroup",
		"awsRegion": "eu-central-1",
		"sourceIPAddress": "84.177.42.212",
		"userAgent": "signin.amazonaws.com",
		"requestID": "bf69d873-7679-451e-be90-0a8866b73cc5",
		"eventID": "793fc880-58cc-4126-86df-67045515f912",
		"eventType": "AwsApiCall",
		"requestParameters": {"groupName":"test","groupDescription":"test","vpcId":"vpc-22cc33dd"}
	}
}`

const ec2StateEvent = `{
	"version": "0",
	"id": "551cfe96-8e0c-4cbe-bd84-63fd6884d015",
	"detail-type": "EC2 Instance State-change Notification",
	"source": "aws.ec2",
	"account": "222233334444",
	"time": "2017-04-22T07:01:03Z",
	"region": "eu-central-1",
	"resources": ["arn:aws:ec2:eu-central-1:222233334444:instance/i-aaaabbbbccccdddd0"],
	"detail": {
		"instance-id": "i-aaaabbbbccccdddd0",
		"state": "shutting-down"
	}
}`

const createTags2 = `{
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
					"resourceId": "sg-00aa11bb"
				}]
			},
			"tagSet": {
				"items": [{
					"key": "xxx",
					"value": "bla"
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
