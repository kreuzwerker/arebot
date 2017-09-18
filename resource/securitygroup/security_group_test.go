package securitygroup

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/kreuzwerker/arebot/config"
)

func TestMain(m *testing.M) {
	//mySetupFunction()
	Log = newLogger()
	retCode := m.Run()
	//   myTeardownFunction()
	os.Exit(retCode)
}

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

func TestCreateSG(t *testing.T) {

	configFile, err := ioutil.ReadFile("../../test/sg.cfg")
	if err != nil {
		panic(err)
	}
	Cfg, err = config.ParseConfig(string(configFile[:]))
	if err != nil {
		panic(err)
	}

	sg, err := NewSecurityGroupWithStatus("sg-aabb1122", "222233334444", func(id string, account string) (*ec2.DescribeSecurityGroupsOutput, error) {
		return &ec2.DescribeSecurityGroupsOutput{
			SecurityGroups: []*ec2.SecurityGroup{
				{
					Description: strHelper("my description"),
					GroupId:     strHelper("sg-bbaa2211"),
					GroupName:   strHelper("Test"),
					IpPermissions: []*ec2.IpPermission{
						&ec2.IpPermission{
							FromPort:   intHelper(20),
							IpProtocol: strHelper("tcp"),
							UserIdGroupPairs: []*ec2.UserIdGroupPair{
								{
									GroupId: strHelper("sg-f366819a"),
									UserId:  strHelper("222233334444"),
								},
							},
							ToPort: intHelper(22),
						},
						&ec2.IpPermission{
							FromPort:   intHelper(20),
							IpProtocol: strHelper("tcp"),
							IpRanges: []*ec2.IpRange{
								&ec2.IpRange{
									CidrIp: strHelper("0.0.0.0/0"),
								},
							},
							ToPort: intHelper(22),
						},
						&ec2.IpPermission{
							FromPort:   intHelper(20),
							IpProtocol: strHelper("tcp"),
							IpRanges: []*ec2.IpRange{
								&ec2.IpRange{
									CidrIp: strHelper("0.0.0.0/0"),
								},
							},
							ToPort: intHelper(22),
						},
					},
					IpPermissionsEgress: []*ec2.IpPermission{
						{
							IpProtocol: strHelper("-1"),
							IpRanges: []*ec2.IpRange{
								{
									CidrIp: strHelper("0.0.0.0/0"),
								},
							},
						},
					},
					OwnerId: strHelper("222233334444"),
					Tags: []*ec2.Tag{
						{
							Key:   strHelper("Name"),
							Value: strHelper("Test2"),
						},
						{
							Key:   strHelper("SomeTag"),
							Value: strHelper("SomeValue"),
						},
					},
					VpcId: strHelper("vpc-00aa11bb"),
				},
			},
		}, nil
	})
	Log.Infof("%+v", sg)
	if err != nil {
		panic(err)
	}

	/*sgConfigParents*/
	_, apicallsConfigs := Cfg.GetAPICallConfigs("CreateSecurityGroup", "222233334444", *sg.State.VpcId, "security_group")

	if len(apicallsConfigs) != 1 {
		t.Errorf("GetAPICallConfigs should return exactly 1 results. But it returned: %d \n%+v", len(apicallsConfigs), apicallsConfigs)
	}

	for _, apicallCfg := range apicallsConfigs {
		//Log.Infof("XXX %+v %+v", sg.GetProperties("IpPermissions.FromPort"), apicallCfg)
		Log.Infof("XXX %+v", apicallCfg)
		results := apicallCfg.CheckCompliance(sg.GetProperties, "sg-bbaa2211", config.EventUserInfo{})
		if len(results) != 7 {
			t.Errorf("CheckCompliance should return exactly 7 results. But it returned: %d \n%+v", len(results), results)
		}
	}
}
