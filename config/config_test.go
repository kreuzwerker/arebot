package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	//mySetupFunction()
	Log = newLogger()
	retCode := m.Run()
	//   myTeardownFunction()
	os.Exit(retCode)
}

func TestConfigParsingNew(t *testing.T) {
	configFile, err := ioutil.ReadFile("../test/test_create_sg.cfg")
	if err != nil {
		panic(err)
	}
	config, err := ParseConfig(string(configFile[:]))
	if err != nil {
		panic(err)
	}

	_, apicallsConfigs := config.GetAPICallConfigs("CreateSecurityGroup", "222233334444", "vpc-12345678", "security_group")
	if len(apicallsConfigs) != 1 {
		t.Errorf("apicallsConfigs == %d expected 1", len(apicallsConfigs))
	}
	_, apicallsConfigs = config.GetAPICallConfigs("CreateSecurityGroup", "222233334444", "vpc-11111111", "security_group")
	if len(apicallsConfigs) != 1 {
		t.Errorf("apicallsConfigs == %d expected 1", len(apicallsConfigs))
	}
	_, apicallsConfigs = config.GetAPICallConfigs("CreateSecurityGroup", "222233334444", "vpc-12345679", "security_group")
	if len(apicallsConfigs) != 0 {
		t.Errorf("apicallsConfigs == %d expected 0", len(apicallsConfigs))
	}
	_, apicallsConfigs = config.GetAPICallConfigs("CreateSecurityGroup", "355291122841", "vpc-12345678", "security_group")
	if len(apicallsConfigs) != 0 {
		t.Errorf("apicallsConfigs == %d expected 0", len(apicallsConfigs))
	}
}

func TestConfigRoleSession(t *testing.T) {

	config, err := ParseConfig(roleSessionConfigTestFixure)
	if err != nil {
		t.Error(err)
	}
	expected := "arn:aws:sts::000000000000:assumed-role/arebot/session"
	if config.GetAccountAssumedRoleArn("000000000000") != expected {
		fmt.Printf("%+v vs. %+v\n", config.GetAccountAssumedRoleArn("000000000000"), expected)
		t.Error("account role ARN is differed from expectation")
	}
	expected = "arn:aws:sts::111111111111:assumed-role/arebot/.+"
	if config.GetAccountAssumedRoleArn("111111111111") != expected {
		fmt.Printf("%+v vs. %+v\n", config.GetAccountAssumedRoleArn("111111111111"), expected)
		t.Error("account role ARN is differed from expectation")
	}

	config, err = ParseConfig(roleSessionConfigTestFixure + "\narebot_user_session_name = \"globalsession\"")
	if err != nil {
		t.Error(err)
	}
	expected = "arn:aws:sts::111111111111:assumed-role/arebot/globalsession"
	if config.GetAccountAssumedRoleArn("111111111111") != expected {
		fmt.Printf("%+v vs. %+v\n", config.GetAccountAssumedRoleArn("111111111111"), expected)
		t.Error("account role ARN is differed from expectation")
	}
}

func TestParsingAdditionalSettings(t *testing.T) {

	config, err := ParseConfig(additionalSettings)
	if err != nil {
		t.Error(err)
	}
	t.Logf("Settings: %+v", config)
}

func TestNegation(t *testing.T) {

	config, err := ParseConfig(negation)
	if err != nil {
		t.Error(err)
	}
	if config.SecurityGroupPolicy[0].APICall[0].Compliant[0].Negate != true {
		t.Error("negate is false")
	}
}

func TestComplianceMissing(t *testing.T) {

	config, err := ParseConfig(missingCompliance)
	if err != nil {
		t.Error(err)
	}
	c := config.SecurityGroupPolicy[0].APICall[0].Compliant[0]
	if c.Mandatory != true {
		t.Error("mandatory is false")
	}

}

func TestParsingNewConfig(t *testing.T) {
	config, err := ParseConfig(newConfig)
	if err != nil {
		t.Error(err)
	}
	orCondition := config.SecurityGroupPolicy[0].APICall[0].Compliant[0].Condition[0]
	if orCondition.Type != "OR" {
		t.Error("name not match.")
	}
	if len(orCondition.Condition) != 2 {
		t.Error("wrong amount of Condition.")
	}
	if orCondition.Condition[0].Name != "TagExists" {
		t.Error("name of first not match.")
	}
	if orCondition.Condition[1].Type != "tag_key_not_exists" {
		t.Error("type for second not match.")
	}
	if len(config.SecurityGroupPolicy[0].APICall[0].Compliant[0].Actions) != 2 {
		t.Error("to many/few actions in Compliant check.")
	}
	if len(config.SecurityGroupPolicy[0].ActionTrigger) != 2 {
		t.Error("wrong amount of Action triggers.")
	}
	if len(config.SecurityGroupPolicy[0].ActionTrigger[1].Action) != 2 {
		t.Error("wrong amount of Actions in Action trigger.")
	}
	if len(config.SecurityGroupPolicy[0].Action) != 2 {
		t.Error("wrong amount of Actions in SG config.")
	}
	if len(config.SecurityGroupPolicy[0].Action[0].Email.Receiver) != 2 {
		t.Error("wrong amount of recievers in one of SG actions email config.")
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := ParseConfig(newConfig); err != nil {
		t.Error("Config validation returned an error, but it shouldn't have.")
	}
	if _, err := ParseConfig(invalidActionsConfig); err == nil {
		t.Error("Config actions validation haven't returned any error, but it should have.")
	}
	if _, err := ParseConfig(invalidConditionConfig); err == nil {
		t.Error("Config conditions validation haven't returned any error, but it should have.")
	}
	if _, err := ParseConfig(invalidConditionOnTagPairConfig); err == nil {
		t.Error("Config conditions validation haven't returned any error, but it should have.")
	}
	actionField := Action{Email: EmailNotification{Receiver: []string{"asd@asd.asd", "{{ asd }}"}}}
	if err := validateAction(actionField); err == nil {
		t.Error("Actions validation should return error. Invalid field.")
	}
	action := Action{Email: EmailNotification{Receiver: []string{"invalidEmailAddress@", "{{ State.Creator }}"}}}
	if err := validateAction(action); err == nil {
		t.Error("Actions validation should return error. Invalid email address.")
	}
	var conditions []Condition
	conditions = append(conditions, Condition{Name: "name", Type: "OR"})
	if err := validateConditions(conditions); err == nil {
		t.Error("Conditions validation should return error. Logical condition does not contain underlaying conditions.")
	}
}

func TestMergeResults(t *testing.T) {
	var compliantCheckResults []CompliantCheckResult
	compliantCheckResults = append(compliantCheckResults, CompliantCheckResult{
		EventType: "AType", EventUser: EventUserInfo{Username: "Valid UserName", AccountId: "123", EmailAddress: "test@test.com", Region: "europe"},
		ResourceId: "SG ID", IsCompliant: false, Check: CompliantCheck{}, Value: "invalid value for given type", CreationDate: time.Now()})
	compliantCheckResults = append(compliantCheckResults, CompliantCheckResult{
		EventType: "AType", EventUser: EventUserInfo{Username: "Valid UserName", AccountId: "123", EmailAddress: "test@test.com", Region: "europe"},
		ResourceId:  "SG ID",
		IsCompliant: false, Check: CompliantCheck{}, Value: " different invalid value for given type", CreationDate: time.Now()})
	compliantCheckResults = append(compliantCheckResults, CompliantCheckResult{
		EventType: "AType", EventUser: EventUserInfo{Username: "Valid UserName", AccountId: "123", EmailAddress: "test@test.com", Region: "europe"},
		ResourceId: "SG ID", IsCompliant: true, Check: CompliantCheck{}, Value: "valid value for given type", CreationDate: time.Now()})
	compliantCheckResults = append(compliantCheckResults, CompliantCheckResult{
		EventType: "AType", EventUser: EventUserInfo{Username: "Valid UserName", AccountId: "123", EmailAddress: "test@test.com", Region: "europe"},
		ResourceId: "SG ID", IsCompliant: false, Check: CompliantCheck{}, Value: " different invalid value for given type", CreationDate: time.Now()})
	compliantCheckResults = append(compliantCheckResults, CompliantCheckResult{
		EventType: "AType", EventUser: EventUserInfo{Username: "Valid UserName", AccountId: "123", EmailAddress: "test@test.com", Region: "europe"},
		ResourceId: "SG ID", IsCompliant: false, Check: CompliantCheck{}, Value: "invalid value for given type", CreationDate: time.Now()})

	compliantCheckResults = mergeComplianceResults(compliantCheckResults)

	if len(compliantCheckResults) != 2 {
		t.Errorf("merge function should return 2 results but returned: %d \n%+v", len(compliantCheckResults), compliantCheckResults)
	}
}

const botConfig = `region = "us-west-2"
access_key = "something"
secret_key = "something_else"
bucket = "backups"
all_events_queue = "all_events"
security_group_policy "tag" {
  tag "Name" {
    schema = "(A)([PSTCD]+)([WLAO]+)(N[1-9]|SI|C[1-9]|WS|CF)-(SEG)([05])([A-Z0-9]{3,5})"
		action = "delete"
  }
}
account "account-test" {
  account_id = "000000000000"
  region = "eu-central-1"
  bucket = "bucket"
  local_folder = "folder"
  arebot_role_arn = "arn:aws:iam::000000000000:role/AreBot"
  all_events_queue = "all_events"
	role_session_name = "session"
}
`

const roleSessionConfigTestFixure = `
account "account-test" {
  account_id = "000000000000"
  region = "eu-central-1"
  bucket = "bucket"
  local_folder = "folder"
  arebot_role_arn = "arn:aws:iam::000000000000:role/arebot"
  all_events_queue = "all_events"
	role_session_name = "session"
}
account "account-prod" {
  account_id = "111111111111"
  region = "eu-central-1"
  bucket = "bucket"
  local_folder = "folder"
  arebot_role_arn = "arn:aws:iam::111111111111:role/arebot"
  all_events_queue = "all_events"
}
`

const additionalSettings = `
arebot_config {
  region = "eu-west-1"
  bucket = ""
  local_folder = ".test"
  arebot_role_arn = "arn:aws:iam::000011112222:role/AreBot"
}

ldap_config {
  ldap_host = "localhost"
  ldap_port = "389000"
  bind_username = "username"
  bind_password = "password"
  search_base = "dc=ads,dc=localhost,dc=com"
}
`

const negation = `
security_group_policy "tag" {
	api_call "CreateSecurityGroup" {
		compliant "Tag.AppId" {
			schema = "NSS-001:SecPerimeter"
			negate = true
			actions = [ "ignore" ]
		}
	}

	action "ignore" {}
}`

const missingCompliance = `
security_group_policy "tag" {
	api_call "CreateSecurityGroup" {
		compliant "Tag.AppId" {
			schema = "NSS-001:SecPerimeter"
			mandatory = true
			actions = [ "ignore" ]
		}
	}

	action "ignore" {}
}`

const newConfig = `
security_group_policy "XXX" {
  vpc = "^vpc-9bec0bf2$"

  api_call "CreateSecurityGroup" {
    compliant "GroupName" {
      schema = "(launch-wizard-)[1-9]+[0-9]*"
      negate = true
      actions = ["sendEmail" , "modifyProperty"]
      condition "CloudFormationCondition" {
        type = "OR"
        condition "TagExists" {
          type = "tag_key_exists"
          value = "^aws:cloudformation:logical-id$"
        }
        condition "TagNotExists" {
          type = "tag_key_not_exists"
          value = "^aws:cloudformation:logical-id$"
        }
      }
    }
  }
  action_trigger "PeriodicallyCheckForTagsBeingPresent" {
    schedule = "0 8 * * *"
    action = [ "modifyProperty" ]
  }
  action_trigger "PeriodicallyCheckForIngressBeingValid" {
    schedule = "0 8-18 * * *"
    action = [ "sendEmail" , "modifyProperty" ]
  }
  action "sendEmail" {
    email {
      receiver = [ "{{ State.Creator }}", "admin@example.com" ]
      template = "path/to/template"
    }
    condition "olderThen" {
      type = "stop_after"
      value = "10 days"
    }
  }
  action "modifyProperty" {
    email {
      receiver = [ "{{ State.Creator }}", "admin@example.com" ]
      template = "path/to/template"
    }
    modify {
      remove = true
    }
    condition "wait14Days" {
      type = "start_after"
      value = "14 days"
    }
  }
}`

const invalidActionsConfig = `
security_group_policy "XXX" {
  api_call "CreateSecurityGroup" {
    compliant "GroupName" {
      schema = "(launch-wizard-)[1-9]+[0-9]*"
      negate = true
      actions = ["sendEmail"]
      condition "CloudFormationCondition" {
        type = "tag_key_exists"
        value = "^aws:cloudformation:logical-id$"
      }
    }
  }
}`

const invalidConditionConfig = `
security_group_policy "XXX" {
  api_call "CreateSecurityGroup" {
    compliant "GroupName" {
      schema = "(launch-wizard-)[1-9]+[0-9]*"
      negate = true
      actions = ["sendEmail"]
      condition "CloudFormationCondition" {
        type = "OR"
        condition "TagExists" {
          type = "tag_key_exists"
          value = "^aws:cloudformation:logical-id$"
        }
      }
    }
  }
  action "sendEmail" {
    email {
      receiver = [ "{{ State.Creator }}", "admin@example.com" ]
      template = "path/to/template"
    }
    condition "olderThen" {
      type = "stop_after"
      value = "10 days"
    }
  }
}`

const invalidConditionOnTagPairConfig = `
security_group_policy "XXX" {
  api_call "CreateSecurityGroup" {
    compliant "GroupName" {
      schema = "(launch-wizard-)[1-9]+[0-9]*"
      negate = true
      actions = ["doNothing"]
      condition "CloudFormationCondition" {
        type = "tag_pair_exists"
        value = "K:key,V:value"
      }
    }
  }
  action "doNothing" {}
}`
