package dynamodb

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
	"github.com/kreuzwerker/arebot/config"
	"github.com/kreuzwerker/arebot/util"
	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/guregu/dynamo"
	"os"
)

var (
	// Log Logger for this package
	Log = newLogger()
	// Cfg Config for this package
	Cfg *config.Config
)

const tableName = "CompliantCheckResult"
const partitionKey = "ResourceId"
const sortKey = "DateAndTypeComposite"

func newLogger() *logrus.Logger {
	_log := logrus.New()
	_log.Out = os.Stdout
	_log.Formatter = &logrus.TextFormatter{FullTimestamp: true}
	_log.Level = logrus.DebugLevel
	return _log
}

func GetCheckResultsByResourceId(resourceId string) (*[]config.CompliantCheckResult, error) {
	db := dynamo.New(session.New(), util.GetDynamoDBConfig())
	table := db.Table(tableName)

	var results []config.CompliantCheckResult

	if err := table.Get(partitionKey, resourceId).All(&results); err != nil {
		Log.Errorf("Error while reading record by resourceId: %s. Error message: %s", resourceId, err.Error())
		return nil, err
	}
	return &results, nil
}

func GetCheckResultByResourceIdAndSortKey(resourceId, dateAndTypeComposite string) (*config.CompliantCheckResult, error) {
	db := dynamo.New(session.New(), util.GetDynamoDBConfig())
	table := db.Table(tableName)

	var result config.CompliantCheckResult

	if resourceId != "" && dateAndTypeComposite != "" {
		if err := table.Get(partitionKey, resourceId).Range(sortKey, dynamo.Equal, dateAndTypeComposite).One(&result); err != nil {
			Log.Errorf("Error while reading record by resourceId: %s and sortKey: %s. Error message: %s", resourceId, sortKey, err.Error())
			return nil, err
		}
	} else {
		return nil, nil
	}
	return &result, nil
}

// TODO take into account the policyName
func GetCheckResultsByActionAndPolicyName(action string, policyName string) (*[]config.CompliantCheckResult, error) {
	db := dynamo.New(session.New(), util.GetDynamoDBConfig())
	table := db.Table(tableName)

	var results []config.CompliantCheckResult

	if err := table.Scan().Filter("contains('Check'.Actions, ?)", action).All(&results); err != nil {
		Log.Errorf("Error while reading record by action: %s. Error message: %s", action, err.Error())
		return nil, err
	}
	return &results, nil
}

func UpdateCheckConfigInCheckResult(resourceId, dateAndTypeComposite string, conf config.CompliantCheck) error {
	db := dynamo.New(session.New(), util.GetDynamoDBConfig())
	table := db.Table(tableName)

	if err := table.Update(partitionKey, resourceId).Range(sortKey, dateAndTypeComposite).Set("Conf", conf).Run(); err != nil {
		Log.Errorf("Error while updating record with partitionKey: %s and rangeKey: %s. Error message: %s", resourceId,
			dateAndTypeComposite, err.Error())
		return err
	}
	return nil
}

func DeleteCheckResultByResourceIdAndSortKey(resourceId, dateAndTypeComposite string) error {
	db := dynamo.New(session.New(), util.GetDynamoDBConfig())
	table := db.Table(tableName)

	if err := table.Delete(partitionKey, resourceId).Range(sortKey, dateAndTypeComposite).Run(); err != nil {
		Log.Errorf("Error while deleting check result with partitionKey: %s and rangeKey: %s. Error message: %s", resourceId,
			dateAndTypeComposite, err.Error())
		return err
	}
	return nil
}

func DeleteCheckResultsByResourceId(resourceId string) error {
	db := dynamo.New(session.New(), util.GetDynamoDBConfig())
	table := db.Table(tableName)

	if err := table.Delete(partitionKey, resourceId).Run(); err != nil {
		Log.Errorf("Error while deleting check results with partitionKey: %s. Error message: %s", resourceId, err.Error())
		return err
	}
	return nil
}

func StoreCheckResults(resourceId string, results []config.CompliantCheckResult) []error {
	var errors []error
	currentResults, _ := GetCheckResultsByResourceId(resourceId)
	for _, curr := range *currentResults {
		found := false
		for _, res := range results {
			if curr.ResourceId == res.ResourceId && curr.DateAndTypeComposite == res.DateAndTypeComposite {
				found = true
				break
			}
		}
		if !found {
			DeleteCheckResultByResourceIdAndSortKey(curr.ResourceId, curr.DateAndTypeComposite)
		}
	}
	for _, result := range results {
		if res, _ := GetCheckResultByResourceIdAndSortKey(result.ResourceId, result.DateAndTypeComposite); res != nil {
			err := UpdateCheckConfigInCheckResult(result.ResourceId, result.DateAndTypeComposite, result.Check)
			errors = append(errors, err)
		} else {
			err := StoreCheckResult(result)
			errors = append(errors, err)
		}
	}
	return nil
}

func StoreCheckResult(object config.CompliantCheckResult) error {
	db := dynamo.New(session.New(), util.GetDynamoDBConfig())
	table := db.Table(tableName)

	object.DateAndTypeComposite = object.CreationDate.String() + object.EventType
	// put item
	if err := table.Put(object).Run(); err != nil {
		Log.Errorf("Error while storing record: %v. Error message: %s", object, err.Error())
		return err
	}
	return nil
}
