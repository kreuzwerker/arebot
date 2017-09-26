package filesystem

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
	"os"
	"reflect"
	"testing"

	"github.com/kreuzwerker/arebot/config"
	"github.com/aws/aws-sdk-go/service/ec2"
)

func TestMain(m *testing.M) {
	//mySetupFunction()
	Log = newLogger()
	retCode := m.Run()
	//   myTeardownFunction()
	os.Exit(retCode)
}

const groupId = "sg-0011aabb"

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

func TestStoreState(t *testing.T) {
	var err error
	Cfg, err = config.ParseConfig(localFolderConf)
	if err != nil {
		panic(err)
	}

	sg := ec2.SecurityGroup{
		Description: strHelper("my description"),
		GroupId:     strHelper(groupId),
		GroupName:   strHelper("Test"),
		IpPermissions: []*ec2.IpPermission{
			&ec2.IpPermission{
				FromPort:   intHelper(20),
				IpProtocol: strHelper("tcp"),
				UserIdGroupPairs: []*ec2.UserIdGroupPair{
					{
						GroupId: strHelper(groupId),
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
		VpcId: strHelper("vpc-aabb1122"),
	}
	StoreState(sg)

	storedState, _ := GetState(groupId)

	if !reflect.DeepEqual(sg, storedState) {
		t.Errorf("State after read is not same that was saved.\nSaved: %s \nLoaded: %s", sg, storedState)
	}
	_, folder := Cfg.GetBucketAndFolder()
	os.RemoveAll(folder)
}

const localFolderConf = `
s3_config {
   region = "eu-west-1"
   bucket = ""
   local_folder = ".checkresult_states"
   arebot_role_arn = "arn:aws:iam::000011112222:role/AreBot"
}`
