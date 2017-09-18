package core

import (
	"regexp"

	"strings"

	"github.com/kreuzwerker/arebot/cloudwatch"
	"github.com/kreuzwerker/arebot/resource/ec2"
	"github.com/kreuzwerker/arebot/resource/securitygroup"

	"github.com/kreuzwerker/arebot/action"
	"github.com/kreuzwerker/arebot/config"
	"github.com/kreuzwerker/arebot/storeresults"
	"github.com/kreuzwerker/arebot/util"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
)

func HandleEvent(msg *sqs.Message) error {
	Log.Println(aws.StringValue(msg.Body))

	event, err := cloudwatch.DecodeEvent([]byte(*msg.Body))
	if err != nil {
		panic(err)
	}

	if ignore, _ := ignoreEvent(event); ignore {
		return nil
	}

	return HandleAWSEvent(event)
}

func HandleAWSEvent(event cloudwatch.AWSEvent) error {
	Log.Printf("Received API call: %s", event.ApiCall)
	// create a new object storing information about the user that has determined the event
	eventUser := createEventUserInfo(event.ApiDetail)

	switch event.ApiCall {
	case "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress":
		id := event.RequestParameter.(*cloudwatch.SecurityGroupPolicyRequestParameters).GroupId
		sg, err := securitygroup.NewSecurityGroupWithStatus(id, eventUser.AccountId)
		if err != nil {
			return err
		}
		Log.Printf("%+v changed (security group)", sg)
		handleSecurityGroupEvent(event, eventUser, sg)

	case "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupEgress":
		id := event.RequestParameter.(*cloudwatch.SecurityGroupPolicyRequestParameters).GroupId
		sg, err := securitygroup.NewSecurityGroupWithStatus(id, eventUser.AccountId)
		if err != nil {
			return err
		}
		Log.Printf("%+v changed (security group)", sg)
		handleSecurityGroupEvent(event, eventUser, sg)

	case "CreateSecurityGroup":
		_ /* uid */, err := event.ApiDetail.ParseUserIdentity()
		if err != nil {
			//Log.Errorf("%s", err)
			return err
		}
		resp := event.ApiDetail.ResponseElements.(map[string]interface{})
		id := resp["groupId"].(string)
		sg, err := securitygroup.NewSecurityGroupWithStatus(id, eventUser.AccountId)
		if err != nil {
			return err
		}
		Log.Printf("%+v created (security group)", sg)
		//sg.TagCreator(uid)
		handleSecurityGroupEvent(event, eventUser, sg)

	case "CreateTags":
		for _, item := range event.RequestParameter.(*cloudwatch.CreateTagsRequestParameters).ResourcesSet.Items {
			rid := item["resourceId"]

			if strings.HasPrefix(rid, "sg-") { // SecurityGroups
				sg, err := securitygroup.NewSecurityGroupWithStatus(rid, eventUser.AccountId)
				if err != nil {
					return err
				}
				Log.Printf("%+v tagged (security group)", sg)
				handleSecurityGroupEvent(event, eventUser, sg)
			} else if strings.HasPrefix(rid, "i-") { // EC2 instances
				e, err := ec2instance.NewEC2WithStatus(rid, eventUser.AccountId)
				if err != nil {
					return err
				}
				Log.Printf("%+v tagged (ec2 instance)", e)
				handleEC2Event(event, eventUser, e)
			}
		}

	case "DeleteTags":
		for _, item := range event.RequestParameter.(*cloudwatch.CreateTagsRequestParameters).ResourcesSet.Items {
			rid := item["resourceId"]

			if strings.HasPrefix(rid, "sg-") { // SecurityGroups
				sg, err := securitygroup.NewSecurityGroupWithStatus(rid, eventUser.AccountId)
				if err != nil {
					return err
				}
				//Log.Printf("%+v deleted tags: %+v", sg, item)
				for _, item := range event.RequestParameter.(*cloudwatch.CreateTagsRequestParameters).TagSet.Items {
					if strings.HasPrefix(item["key"], "AreBOT.") {
						sg.Tag(item["key"], item["value"])
					}
					Log.Printf("%+v deleted tag: %+v (security group)", sg, item)
				}

			} else if strings.HasPrefix(rid, "i-") { // EC2 instances
				e, err := ec2instance.NewEC2WithStatus(rid, eventUser.AccountId)
				if err != nil {
					return err
				}
				for _, item := range event.RequestParameter.(*cloudwatch.CreateTagsRequestParameters).TagSet.Items {
					// if strings.HasPrefix(item["key"], "AreBOT.") {
					// 	e.Tag(item["key"], item["value"])
					// }
					Log.Printf("%+v deleted tag: %+v (ec2 instance)", e, item)
				}
			}
		}

	case "DeleteSecurityGroup":
		id := event.RequestParameter.(*cloudwatch.SecurityGroupPolicyRequestParameters).GroupId
		//sg := SecurityGroup.NewSecurityGroupWithStatus(id, event.ApiDetail.UserIdentity.AccountID)
		Log.Printf("Security group ID: %s", id)
		Log.Printf("%s deleted (security group)", id)
		storeresults.DeleteCheckResultsByResourceId(id)
		return nil

	case "RunInstances", "StartInstances":
		_, err := event.ApiDetail.ParseUserIdentity()
		if err != nil {
			return err
		}
		resp := event.ApiDetail.ResponseElements.(map[string]interface{})
		id, err := util.ParseEC2ResponseRunStartInstance(resp, "instanceId")
		if err != nil {
			return err
		}
		e, err := ec2instance.NewEC2WithStatus(id, eventUser.AccountId)
		if err != nil {
			return err
		}
		Log.Printf("%+v started (ec2 instance)", e)
		handleEC2Event(event, eventUser, e)

	case "CreateVolume":
		resp := event.ApiDetail.ResponseElements.(map[string]interface{})
		id := resp["volumeId"].(string)
		v, err := ec2instance.NewVolumeWithStatus(id, eventUser.AccountId)
		if err != nil {
			return err
		}
		Log.Printf("%+v created (volume)", v)
		handleVolumeEvent(event, eventUser, v)

	case "AttachVolume":
		resp := event.ApiDetail.ResponseElements.(map[string]interface{})
		volumeId := resp["volumeId"].(string)
		instanceId := resp["instanceId"].(string)
		v, err := ec2instance.NewVolumeWithStatus(volumeId, eventUser.AccountId)
		if err != nil {
			return err
		}
		Log.Printf("%+v attached volume to instance %s", v, instanceId)
		handleVolumeEvent(event, eventUser, v)

	case "CreateSnapshot":
		resp := event.ApiDetail.ResponseElements.(map[string]interface{})
		snapId := resp["snapshotId"].(string)
		volumeId := resp["volumeId"].(string)
		s, err := ec2instance.NewSnapshotWithStatus(snapId, eventUser.AccountId)
		if err != nil {
			return err
		}
		Log.Printf("%+v snapshot created from volume %s", s, volumeId)
		handleSnapshotEvent(event, eventUser, s)

	case "DeleteVolume":
		id := event.RequestParameter.(*cloudwatch.VolumeRequestParameters).VolumeId
		Log.Printf("Volume ID: %s", id)
		Log.Printf("%s deleted (volume)", id)
		storeresults.DeleteCheckResultsByResourceId(id)

		return nil

	case "DeleteSnapshot":
		id := event.RequestParameter.(*cloudwatch.SnapshotRequestParameters).SnapshotId
		Log.Printf("Snapshot ID: %s", id)
		Log.Printf("%s deleted (snapshot)", id)
		storeresults.DeleteCheckResultsByResourceId(id)

		return nil

	case "PutBucketTagging":
		Log.Warn("PutBucketTagging API call not supported yet.")
		return nil
	}

	return nil
}

func handleSecurityGroupEvent(event cloudwatch.AWSEvent, eventuser config.EventUserInfo, sg securitygroup.SecurityGroup) {
	_, apicallsConfigs := Cfg.GetAPICallConfigs(event.ApiCall, eventuser.AccountId, *sg.State.VpcId, "security_group")
	execCompliantChecks(&sg, apicallsConfigs, eventuser)
}

func handleEC2Event(event cloudwatch.AWSEvent, eventuser config.EventUserInfo, e ec2instance.EC2inst) {
	_, apicallsConfigs := Cfg.GetAPICallConfigs(event.ApiCall, eventuser.AccountId, *e.State.VpcId, "ec2")
	execCompliantChecks(&e, apicallsConfigs, eventuser)
}

func handleVolumeEvent(event cloudwatch.AWSEvent, eventuser config.EventUserInfo, v ec2instance.Volume) {
	_, apicallsConfigs := Cfg.GetAPICallConfigs(event.ApiCall, eventuser.AccountId, "", "ec2")
	execCompliantChecks(&v, apicallsConfigs, eventuser)
}

func handleSnapshotEvent(event cloudwatch.AWSEvent, eventuser config.EventUserInfo, s ec2instance.Snapshot) {
	_, apicallsConfigs := Cfg.GetAPICallConfigs(event.ApiCall, eventuser.AccountId, "", "ec2")
	execCompliantChecks(&s, apicallsConfigs, eventuser)
}

func execCompliantChecks(resource util.AwsResourceType, apicallsConfigs []config.APICall, eventuser config.EventUserInfo) {
	for _, apicallCfg := range apicallsConfigs {
		Log.Debugf("event_handler.execCompliantChecks: checking compliance %+v", apicallCfg)
		// apply compliance checks based on configuration
		results := apicallCfg.CheckCompliance(resource.GetProperties, resource.GetId(), eventuser)

		for _, result := range results {
			result := result
			if !result.IsCompliant {
				action.HandleAction(result, true)
			}
		}

		if len(results) > 0 {
			storeresults.StoreResourceCheckResults(resource.GetId(), results)
		}
	}
}

func ignoreEvent(event cloudwatch.AWSEvent) (bool, error) {

	user, err := event.ApiDetail.ParseUserIdentity()

	if Cfg.GetAccount(event.Event.Account) == nil {
		Log.Printf("Error getting account configuration for account %s, event type: %s, source: %s", event.Event.Account, event.Event.DetailType, event.Event.Source)
		return true, err
	}
	if err != nil {
		Log.Printf("Error parsing user identity: %s event type: %s, source: %s", err, event.Event.DetailType, event.Event.Source)
		return true, err
	}
	// get the roleArn from the configuration (for that account)
	configuredRoleArn := Cfg.GetAccountRoleArn(event.Event.Account)
	modifiedArn := Cfg.GetAccountAssumedRoleArn(event.Event.Account)
	Log.Printf("Checking event user identity based on configured user: %s (%s) on account %s", configuredRoleArn, modifiedArn, event.Event.Account)

	re := regexp.MustCompile(modifiedArn)
	if re.MatchString(user["arn"]) {
		//if user["arn"] == cfg.getAccountRoleArn(event.Event.Account) {
		Log.Printf("Ignoring AREBOT event type: %s, source: %s", event.Event.DetailType, event.Event.Source)
		return true, nil
	}

	// exit for unhandled event types
	if event.Event.DetailType != "AWS API Call via CloudTrail" || !(event.Event.Source == "aws.ec2" || event.Event.Source == "aws.s3") {
		Log.Printf("Ignoring unhandled event type: %s, source: %s", event.Event.DetailType, event.Event.Source)
		return true, nil
	}

	if len(event.ApiDetail.ErrorCode) > 0 {
		Log.Printf("Ignoring failed event type: %s, source: %s, error: %s", event.Event.DetailType, event.Event.Source, event.ApiDetail.ErrorCode)
		return true, nil
	}

	return false, nil
}

// Retrieve user information from the API detail and return a new EventUserInfo object
func createEventUserInfo(apidetail cloudwatch.APIDetail) config.EventUserInfo {
	var eventUserInfo config.EventUserInfo

	eventUserInfo.AccountId = apidetail.UserIdentity.AccountID

	// retrieve user information from the API detail
	userIdentity, parseErr := apidetail.ParseUserIdentity()
	if parseErr != nil {
		Log.Errorf("Cannot Parse user Identity: %s.", parseErr)
	} else {
		username := userIdentity["name"]
		eventUserInfo.Username = username
		eventUserInfo.EmailAddress = util.FindEmailBasedOnUserName(username)
	}

	// retrieve the region of the user
	eventUserInfo.Region = apidetail.AWSRegion

	return eventUserInfo
}
