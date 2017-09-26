package storeresults

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
	"testing"
	"time"

	"github.com/kreuzwerker/arebot/config"
)

const groupId = "sg-0011aabb"

const localFolderConf = `
s3_config {
   region = "eu-west-1"
   bucket = ""
   local_folder = ".checkresult_states"
   arebot_role_arn = "arn:aws:iam::000011112222:role/AreBot"
}`

func TestMain(m *testing.M) {
	Log = newLogger()

	var err error
	Cfg, err = config.ParseConfig(localFolderConf)
	if err != nil {
		panic(err)
	}
	InitVars(Log, Cfg)

	retCode := m.Run()
	os.Exit(retCode)
}

func TestStoreResourceCheckResults(t *testing.T) {
	var compliantCheckResults []config.CompliantCheckResult

	cc1 := config.CompliantCheck{Name: "Tag.AppId", Schema: "NSS-001:SecPerimeter", Negate: false, Mandatory: true, Actions: []string{"ignore"}, Description: "Some Description"}
	cc2 := config.CompliantCheck{Name: "Tag.Name", Schema: "(SOMESCHEMA)", Negate: false, Mandatory: true, Actions: []string{"ignore"}, Description: "Some other Description"}
	cc3 := config.CompliantCheck{Name: "GroupName", Schema: "(SOMESCHEMA)", Negate: false, Mandatory: true, Actions: []string{"ignore"}, Description: "A further other Description"}

	// CCR1: should be stored!
	compliantCheckResults = append(compliantCheckResults, config.CompliantCheckResult{
		EventType: "AType", EventUser: config.EventUserInfo{Username: "Valid UserName", AccountId: "123", EmailAddress: "test@test.com", Region: "europe"}, ResourceId: "SG ID",
		IsCompliant: false, Check: cc1, Value: "invalid value for given type", CreationDate: time.Now()})
	// CCR2: same resource, same event, same check, than CCR1 -> should not be stored!!
	compliantCheckResults = append(compliantCheckResults, config.CompliantCheckResult{
		EventType: "AType", EventUser: config.EventUserInfo{Username: "Valid UserName", AccountId: "123", EmailAddress: "test@test.com", Region: "europe"}, ResourceId: "SG ID",
		IsCompliant: false, Check: cc1, Value: " different invalid value for given type", CreationDate: time.Now()})
	// CCR3: is compliant -> should not be stored!
	compliantCheckResults = append(compliantCheckResults, config.CompliantCheckResult{
		EventType: "BType", EventUser: config.EventUserInfo{Username: "Valid UserName", AccountId: "123", EmailAddress: "test@test.com", Region: "europe"}, ResourceId: "SG ID",
		IsCompliant: true, Check: cc2, Value: "valid value for given type", CreationDate: time.Now()})


	StoreResourceCheckResults(groupId, compliantCheckResults)

	savedResults := GetResourceCheckResults(groupId)

	if len(*savedResults) != 1 {
		t.Errorf("There should be 1 result, but where: %d \n %v", len(*savedResults), *savedResults)
	}

	var otherCompliantCheckResults []config.CompliantCheckResult
	// CCR4: different event than CCR1 -> should be stored!
	otherCompliantCheckResults = append(otherCompliantCheckResults, config.CompliantCheckResult{
		EventType: "BType", EventUser: config.EventUserInfo{Username: "Valid UserName", AccountId: "123", EmailAddress: "test@test.com", Region: "europe"}, ResourceId: "SG ID",
		IsCompliant: false, Check: cc2, Value: "invalid value for given type", CreationDate: time.Now()})
	// CCR5: different event than CCR1 and CCR4 -> should be stored!
	otherCompliantCheckResults = append(otherCompliantCheckResults, config.CompliantCheckResult{
		EventType: "CType", EventUser: config.EventUserInfo{Username: "Valid UserName", AccountId: "123", EmailAddress: "test@test.com", Region: "europe"}, ResourceId: "SG ID",
		IsCompliant: false, Check: cc3, Value: " different invalid value for given type", CreationDate: time.Now()})
	// CCR6: same check of CCR1, but this time compliant -> should not be stored, and the CCR1 store object should be removed!
	otherCompliantCheckResults = append(otherCompliantCheckResults, config.CompliantCheckResult{
		EventType: "AType", EventUser: config.EventUserInfo{Username: "Valid UserName", AccountId: "123", EmailAddress: "test@test.com", Region: "europe"}, ResourceId: "SG ID",
		IsCompliant: true, Check: cc1, Value: "valid value for given type", CreationDate: time.Now()})

	StoreResourceCheckResults(groupId, otherCompliantCheckResults)

	otherSavedResults := GetResourceCheckResults(groupId)

	if len(*otherSavedResults) != 2 {
		t.Errorf("There should be 2 results after second save but were: %d \n %v", len(*otherSavedResults), *otherSavedResults)
	}

	_, folder := Cfg.GetBucketAndFolder()
	os.RemoveAll(folder)
}
