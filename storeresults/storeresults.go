package storeresults

import (
	"errors"
	"os"

	"github.com/Sirupsen/logrus"

	"github.com/kreuzwerker/arebot/config"
	"github.com/kreuzwerker/arebot/storeresults/dynamodb"
	"github.com/kreuzwerker/arebot/storeresults/filesystem"
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

func InitVars(log *logrus.Logger, cfg *config.Config) {
	Log = log
	dynamodb.Log = log
	filesystem.Log = log

	Cfg = cfg
	dynamodb.Cfg = cfg
	filesystem.Cfg = cfg
}

/* 	GetResourceCheckResults, given a security group ID, checks whether there is any CompliantCheckResult object
	stored (in a JSON-encoded file). If so, then it parses the data and return the array of objects that it encodes;
	otherwise, returns nil.
*/
func GetResourceCheckResults(resourceId string) *[]config.CompliantCheckResult {
	var results *[]config.CompliantCheckResult

	if Cfg.ShouldStoreOnDynamoDB() {
		results, _ = dynamodb.GetCheckResultsByResourceId(resourceId)
		if len(*results) > 0 {
			return results
		}
	}

	results, _ = filesystem.GetCheckResultsByResourceId(resourceId)
	return results
}

/* 	GetCheckResultsByActionAndPolicyName returns the list (possibly empty) of stored compliance check results,
	fetching them either from the dynamodb or the file system repos.
*/
func GetCheckResultsByActionAndPolicyName(actionName, policyName string) (*[]config.CompliantCheckResult, error) {
	if Cfg.ShouldStoreOnDynamoDB() {
		results, err := dynamodb.GetCheckResultsByActionAndPolicyName(actionName, policyName)
		if len(*results) > 0 {
			return results, err
		}
	}

	results, err := filesystem.GetCheckResultsByActionAndPolicyName(actionName, policyName)
	return results, err
}

/*	StoreResourceCheckResults stores a merged array of current and stored CompliantCheckResults objs associated with
	a resource into either a local folder, or s3 bucket, or both. The stored objects must be: non duplicated (FILO), non compliant
*/
func StoreResourceCheckResults(resourceId string, results []config.CompliantCheckResult) error {

	// the merged array of current and stored CompliantCheckResults objects associated with
	// the resource, and encoded as JSON
	resultsToStore := mergeWithCurrent(resourceId, results)

	if Cfg.ShouldStoreOnDynamoDB() {
		errs := dynamodb.StoreCheckResults(resourceId, resultsToStore)
		if errs != nil {
			var errMsg string
			for _, err := range errs {
				errMsg += err.Error()
			}
			return errors.New(errMsg)
		}
	}

	// save also in the file-based storage
	err := filesystem.StoreCheckResults(resourceId, resultsToStore)
	return err
}

/* DeleteCheckResultsByResourceId deletes all the stored compliance check results associated with the passed resource. */
func DeleteCheckResultsByResourceId(resourceId string) error {
	var err error

	if Cfg.ShouldStoreOnDynamoDB() {
		err = dynamodb.DeleteCheckResultsByResourceId(resourceId)
		if err != nil {
			return err
		}
	}

	err = filesystem.DeleteCheckResultsByResourceId(resourceId)
	return err
}

/* 	DeleteExpiredCheckResults deletes all the stored compliance check results associated with the passed resource if
 	contained in the passed list. Typically used to delete expired results
*/
func DeleteCheckResultsByResourceIdAndResultsList(resourceId string, resultlist []config.CompliantCheckResult) {

	if Cfg.ShouldStoreOnDynamoDB() {
		for _, r := range resultlist {
			dynamodb.DeleteCheckResultByResourceIdAndSortKey(resourceId, r.CreationDate.String()+r.EventType)
		}
	} else {
		filesystem.DeleteCheckResultsByResourceIdAndResultsList(resourceId, resultlist)
	}
}


// ************************************************************************************
// ***	SUPPORT METHODS

/*	Merge the passed array of CompliantCheckResult objects with the possible state data
	associated with the same resource. Return the resulting array to store.
*/
func mergeWithCurrent(resourceId string, results []config.CompliantCheckResult) []config.CompliantCheckResult {

	// fetch the stored array of CompliantCheckResult objects associated with resourceId, if any
	storedContent := GetResourceCheckResults(resourceId)

	var mergedSlice []config.CompliantCheckResult

	var storedResultsToDeleteIndexes []int
	var currentResultsToSkipIndexes []int

	// populate the mergedSlice variable
	if storedContent != nil && len(*storedContent) > 0 {
		CheckStored:
		// for each stored CompliantCheckResult object (always non-compliant)
		for i, stor := range *storedContent {

			if stor.IsIpPermissionsCheck() {
				// if stor is not among the new results, then delete it
				isToDelete := true
				currentsHasIpPermissions := false
				for _, curr := range results {
					if curr.IsIpPermissionsCheck() {
						currentsHasIpPermissions = true
					}
					if stor.IsSameCheck(curr) && stor.Value == curr.Value {
						isToDelete = false
					}
				}
				if isToDelete && currentsHasIpPermissions {
					storedResultsToDeleteIndexes = append(storedResultsToDeleteIndexes, i)
					continue CheckStored
				}
			}

			// for each current CompliantCheckResult object
			for j, curr := range results {
				// if stored and current checks are the same
				if curr.IsSameCheck(stor) {
					// always keep the first (stored) object
					currentResultsToSkipIndexes = append(currentResultsToSkipIndexes, j)
					// if the current check is compliant
					if curr.IsCompliant {
						// then delete also the stored object, as the non-compliance has been fixed
						storedResultsToDeleteIndexes = append(storedResultsToDeleteIndexes, i)
					}
				}
			}
		}

		// add the stored CompliantCheckResult objects to the merged array
		for i, stor := range *storedContent {
			// if the result is not to delete
			if !contains(storedResultsToDeleteIndexes, i) {
				mergedSlice = append(mergedSlice, stor)
			}
		}

		// add only non duplicated and non compliant CompliantCheckResult objects to the merged array
		for j, curr := range results {
			if !curr.IsCompliant && !contains(currentResultsToSkipIndexes, j) {
				mergedSlice = appendIfMissing(mergedSlice, curr)
			}
		}

	} else { // if there is no stored array associated with the passed resource ID
		// add only non duplicated and non compliant CompliantCheckResult objects to the merged array
		for j, curr := range results {
			if !curr.IsCompliant && !contains(currentResultsToSkipIndexes, j) {
				mergedSlice = appendIfMissing(mergedSlice, curr)
			}
		}
	}
	return mergedSlice
}

// return true if the array of intergers `s` includes the integer `e`;
// return false otherwise
func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func appendIfMissing(slice []config.CompliantCheckResult, state config.CompliantCheckResult) []config.CompliantCheckResult {
    for _, cs := range slice {
        if cs.IsSameCheck(state) {
            return slice
        }
    }
    return append(slice, state)
}
