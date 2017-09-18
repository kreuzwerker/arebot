package cloudwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/kreuzwerker/arebot/config"
	"github.com/kreuzwerker/arebot/util"
	"github.com/Masterminds/sprig"
	"github.com/Sirupsen/logrus"
)

var (
	Cfg *config.Config
	Log = newLogger()
)

func newLogger() *logrus.Logger {
	_log := logrus.New()
	_log.Out = os.Stdout
	_log.Formatter = &logrus.TextFormatter{FullTimestamp: true}
	_log.Level = logrus.DebugLevel
	return _log
}

// Event represents a CloudWatch Event
// http://docs.aws.amazon.com/AmazonCloudWatch/latest/events/EventTypes.html#api_event_type
type Event struct {
	ID         string          `json:"id"`
	DetailType string          `json:"detail-type"`
	Source     string          `json:"source"`
	Account    string          `json:"account"`
	Time       time.Time       `json:"time"`
	Region     string          `json:"region"`
	Resources  []string        `json:"resources"`
	Detail     json.RawMessage `json:"detail"`
}

type ApiEvent struct {
	ID         string    `json:"id"`
	DetailType string    `json:"detail-type"`
	Source     string    `json:"source"`
	Account    string    `json:"account"`
	Time       time.Time `json:"time"`
	Region     string    `json:"region"`
	Resources  []string  `json:"resources"`
	Detail     APIDetail `json:"detail"`
}

// AutoScalingGroupDetail of the triggered event
type AutoScalingGroupDetail struct {
	ActivityID           string            `json:"ActivityId"`
	AutoScalingGroupName string            `json:"AutoScalingGroupName"`
	Cause                string            `json:"Cause"`
	Details              map[string]string `json:"Details"`
	EC2InstanceID        string            `json:"EC2InstanceId"`
	RequestID            string            `json:"RequestId"`
	StatusCode           string            `json:"StatusCode"`

	StartTime time.Time `json:"StartTime"`
	EndTime   time.Time `json:"EndTime"`
}

// EC2Detail of the triggered event
type EC2Detail struct {
	InstanceID string `json:"instance-id"`
	State      string `json:"state"`
}

// APIDetail of the triggered event
// This is useful for API or Console events
type APIDetail struct {
	EventID      string    `json:"eventID"`
	EventName    string    `json:"eventName"`
	EventSource  string    `json:"eventSource"`
	EventTime    time.Time `json:"eventTime"`
	EventType    string    `json:"eventType"`
	EventVersion string    `json:"eventVersion"`

	AWSRegion string `json:"awsRegion"`
	//AdditionalEventData map[string]string `json:"additionalEventData,omitempty"`
	AdditionalEventData interface{} `json:"additionalEventData,omitempty"`
	//RequestParams       interface{} `json:"requestParameters"`
	RequestParams json.RawMessage `json:"requestParameters"`
	//ResponseElements    map[string]string `json:"responseElements,omitempty"`
	ResponseElements interface{}  `json:"responseElements,omitempty"`
	SourceIPAddress  string       `json:"sourceIPAddress"`
	UserAgent        string       `json:"userAgent"`
	UserIdentity     UserIdentity `json:"userIdentity,omitempty"`
	ErrorCode        string       `json:"errorCode"`
	ErrorMessage     string       `json:"errorMessage"`
}

type UserIdentity struct {
	Type        string `json:"type,omitempty"`
	PrincipleID string `json:"principalId,omitempty"`
	ARN         string `json:"arn,omitempty"`
	AccountID   string `json:"accountId,omitempty"`
	//SessionContext map[string]string `json:"sessionContext,omitempty"`
	SessionContext interface{} `json:"sessionContext,omitempty"`
}

type CreateTagsRequestParameters struct {
	ResourcesSet struct {
		Items []map[string]string `json:"items"`
	} `json:"resourcesSet"`
	TagSet struct {
		Items []map[string]string `json:"items"`
	} `json:"tagSet"`
}

type SecurityGroupPolicyRequestParameters struct {
	GroupId string `json:"groupId,omitempty"`
}

type CreateSecurityGroupRequestParameters struct {
	GroupName        string `json:"groupName,omitempty"`
	GroupDescription string `json:"groupDescription,omitempty"`
	VpcId            string `json:"vpcId,omitempty"`
}

type SnapshotRequestParameters struct {
	SnapshotId	string `json:"snapshotId,omitempty"`
}

type VolumeRequestParameters struct {
	VolumeId	string `json:"volumeId,omitempty"`
}

type AWSEvent struct {
	Event            Event
	ApiDetail        APIDetail
	ApiCall          string
	RequestParameter interface{}
}

type AWSEventInterface interface {
	handleEventType(event Event)
}

func unmarshalJsonObject(jsonStr []byte, obj interface{}, otherFields map[string]json.RawMessage) (err error) {
	objValue := reflect.ValueOf(obj).Elem()
	knownFields := map[string]reflect.Value{}
	for i := 0; i != objValue.NumField(); i++ {
		jsonName := strings.Split(objValue.Type().Field(i).Tag.Get("json"), ",")[0]
		knownFields[jsonName] = objValue.Field(i)
	}

	err = json.Unmarshal(jsonStr, &otherFields)
	if err != nil {
		return
	}

	for key, chunk := range otherFields {
		if field, found := knownFields[key]; found {
			err = json.Unmarshal(chunk, field.Addr().Interface())
			if err != nil {
				return
			}
			delete(otherFields, key)
		}
	}
	return
}

// func (e *AWSEvent) getCreateTagsRequestParameters(event Event) (CreateTagsRequestParameters, error) {
// 	req := CreateTagsRequestParameters{}
// 	err := json.Unmarshal([]byte(e.ApiDetail.RequestParams), &req)
// 	return req, err
//}

func (e *AWSEvent) handleEventType(event Event) error {
	e.Event = event
	switch event.DetailType {
	case "AWS API Call via CloudTrail":

		if err := json.Unmarshal(e.Event.Detail, &e.ApiDetail); err != nil {
			return err
		}
		e.ApiCall = e.ApiDetail.EventName
	default:
		Log.Printf("Unknown event type: %s", event.DetailType)
		e.ApiCall = "unknown"
	}
	return nil
}

// GetValueFromTemplate parse input string as a template and sets values from AWSEvent event.
func (e *AWSEvent) GetValueFromTemplate(input string) (string, error) {

	funcMapCustom := template.FuncMap{
		// The name "title" is what the function will be called in the template text.
		"UIDName": func(e *AWSEvent) (string, error) {
			a, err := e.ApiDetail.ParseUserIdentity()
			return a["name"], err
		},
		"UIDEmail": func(e *AWSEvent) (string, error) {
			a, err := e.ApiDetail.ParseUserIdentity()
			if err != nil {
				return "", err
			}
			email := util.FindEmailBasedOnUserIdentity(e.Event.Account, a)
			return email, err
		},
	}
	// add Sprig http://masterminds.github.io/sprig/ functions
	funcMap := sprig.TxtFuncMap()
	for k, v := range funcMapCustom {
		funcMap[k] = v
	}

	tmpl, err := template.New("event").Funcs(funcMap).Parse(input)
	if err != nil {
		return input, err
	}
	w := bytes.NewBuffer(nil)
	err = tmpl.Execute(w, e)
	if err != nil {
		return input, err
	}

	Log.Debugf("cloudwatch_event.getValueFromTemplate parsed: '%s' parsed %s", input, w.String())
	return w.String(), err

}

func DecodeEvent(data json.RawMessage) (AWSEvent, error) {
	e := AWSEvent{}
	_e := Event{}
	var req interface{} = nil

	if err := json.Unmarshal(data, &_e); err != nil {
		return e, err
	}
	e.handleEventType(_e)

	switch e.ApiCall {
	case "CreateTags":
		req = &CreateTagsRequestParameters{}
	case "DeleteTags":
		req = &CreateTagsRequestParameters{}
	case "CreateSecurityGroup":
		req = &CreateSecurityGroupRequestParameters{}
	case "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupEgress", "DeleteSecurityGroup":
		req = &SecurityGroupPolicyRequestParameters{}
	case "DeleteVolume":
		req = &VolumeRequestParameters{}
	case "DeleteSnapshot":
		req = &SnapshotRequestParameters{}
	}

	if req != nil {
		other := map[string]json.RawMessage{}
		if err := unmarshalJsonObject([]byte(e.ApiDetail.RequestParams), req, other); err != nil {
			return e, err
		}
		e.RequestParameter = req
	} else {
		Log.Printf("Unhandled event API call: %s. RequestParameters not set.\n", e.ApiCall)
	}
	return e, nil
}

func (e APIDetail) ParseUserIdentity() (map[string]string, error) {

	pattern := `(?P<arn>arn:aws:(?P<service>sts|iam)::(?P<account>[0-9]{12}):(?P<entity>role|assumed-role|user)/(?P<name>\S+))`
	s := e.UserIdentity.ARN
	re := regexp.MustCompile(pattern)

	if re.MatchString(e.UserIdentity.ARN) {
		n1 := re.SubexpNames()
		result := re.FindStringSubmatch(s)

		md := map[string]string{}
		for i, n := range result {
			//fmt.Printf("%d. match='%s'\tname='%s'\n", i, n, n1[i])
			md[n1[i]] = n

		}
		return md, nil
	}
	return nil, errors.New("Error parsing event user identity: " + e.UserIdentity.ARN)
}
