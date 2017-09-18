package filesystem

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/kreuzwerker/arebot/config"
)

func GetCheckResultsByResourceId(resourceId string) (*[]config.CompliantCheckResult, error) {

	f := NewFileFetcher()
	s3 := NewS3FileFetcher()
	bucket, folder := Cfg.GetBucketAndFolder()
	var pstr []byte
	var err error
	if folder != "" {
		// fetch the data from the state file associated with the sec.group `groupId`
		pstr, err = getDataFromFile(f, folder, resourceId)
		if err != nil {
			Log.Error(err)
		}
	}
	if len(pstr) <= 0 && bucket != "" {
		pstr, err = getDataFromFile(s3, folder, resourceId)
		if err != nil {
			Log.Error(err)
		}
	}
	// if any state data (JSON-encoded) has been fetched, then parses the
	// data and stores it in the `results` array of CompliantCheckResult objects
	if len(pstr) > 0 {
		// Log.Printf("pstr=%s", pstr)
		var results []config.CompliantCheckResult
		err := json.Unmarshal(pstr, &results)
		if err != nil {
			Log.Error(err)
			return nil, err
		}
		return &results, nil
	}
	// otherwise (i.e., no state data fetched), return nil
	return nil, nil
}

/* 	GetCheckResultsByActionAndPolicyName returns the list of CompliantCheckResult objects that fire at least one of
	the (passed) actions triggered by the current trigger considered, by searching into the folder where result states
	are stored
*/
func GetCheckResultsByActionAndPolicyName(action string, policyName string) (*[]config.CompliantCheckResult, error) {

	// Explore the folder with the stored states related to SECURITY GROUPS.
	if Cfg.S3Config.LocalFolder == "" {
		emptyResult := []config.CompliantCheckResult{}
		return &emptyResult, errors.New("Could not find any stored compliant check associated with an action " + action + " defined in the " + policyName + " compliant policy.")
	}

	filenameList := []string{}
	err := filepath.Walk(Cfg.S3Config.LocalFolder, func(path string, f os.FileInfo, err error) error {
		if !f.IsDir() && !strings.HasSuffix(f.Name(), "-state") {
			filenameList = append(filenameList, filepath.Base(path))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var results []config.CompliantCheckResult

	// For each file in the folder where the CompliantCheckResult objects are stored
	for _, resourceId := range filenameList {

		// consider each CompliantCheckResult stored in the current state file
		storedResults, _ := GetCheckResultsByResourceId(resourceId)
		if storedResults == nil {
			continue
		}
		for _, res := range *storedResults {
			// check whether at least one of the actions is the one passed to this function
			if res.Check.PolicyName == policyName && config.ContainsString(res.Check.Actions, action) {
				// append the CompliantCheck (no duplicates) to the slice of checks to check later
				results = append(results, res)
			}
		}
	}
	if len(results) == 0 {
		return nil, errors.New("Could not find any stored compliant check associated with an action " + action + " defined in the " + policyName + " compliant policy.")
	}
	return &results, nil
}

func DeleteCheckResultsByResourceIdAndResultsList(resourceId string, resultsToDelete []config.CompliantCheckResult) {

	var results []config.CompliantCheckResult
	storedResults, _ := GetCheckResultsByResourceId(resourceId)

	for _, sr := range *storedResults {
		if !containsResult(resultsToDelete, sr) {
			results = append(results, sr)
		}
	}

	StoreCheckResults(resourceId, results)
}

func DeleteCheckResultsByResourceId(resourceId string) error {
	var err = os.Remove(Cfg.S3Config.LocalFolder + string(os.PathSeparator) + resourceId)
	return err
}

func StoreCheckResults(resourceId string, results []config.CompliantCheckResult) error {

	f := NewFileFetcher()
	s3 := NewS3FileFetcher()
	bucket, folder := Cfg.GetBucketAndFolder()

	// encode the array into a JSON format
	byteArr, err := json.Marshal(results)
	if err != nil {
		Log.Error(err)
		return nil
	}

	// save the encoded merged array into the local folder, if any configured
	// (the file name is the same as the resourceId)
	if folder != "" {
		pstr, err := saveDataToFile(byteArr, f, folder, resourceId)
		if err != nil {
			Log.Error(err)
			return err
		}
		Log.Printf("pstr=%s", pstr)
	}

	// save the encoded merged array into the s3 bucket, if any configured
	// (the file name is the same as the resourceId)
	if bucket != "" {
		pstrS3, err := saveDataToFile(byteArr, s3, bucket, resourceId)
		if err != nil {
			Log.Error(err)
			return err
		}
		Log.Printf("pstr=%s", pstrS3)
	}
	return nil
}

// ************************************************************************************
// ***	Functions used for testing purposes

func GetState(groupId string) (ec2.SecurityGroup, error) {
	f := NewFileFetcher()
	s3 := NewS3FileFetcher()
	bucket, folder := Cfg.GetBucketAndFolder()
	var pstr []byte
	var err error
	if folder != "" {
		pstr, err = getDataFromFile(f, folder, groupId+"-state")
		if err != nil {
			Log.Error(err)
		}
	}
	if len(pstr) <= 0 && bucket != "" {
		pstr, err = getDataFromFile(s3, folder, groupId+"-state")
		if err != nil {
			Log.Error(err)
		}
	}
	if len(pstr) > 0 {
		Log.Printf("pstr=%s", pstr)
		secGrp, err := NewStateDataFromByte(pstr, &ec2.SecurityGroup{})
		if err != nil {
			Log.Error(err)
			return ec2.SecurityGroup{}, err
		}
		return *secGrp, nil
	}
	return ec2.SecurityGroup{}, err
}

func StoreState(state ec2.SecurityGroup) error {
	f := NewFileFetcher()
	s3 := NewS3FileFetcher()
	bucket, folder := Cfg.GetBucketAndFolder()

	byteArr, err := json.Marshal(state)
	if err != nil {
		Log.Error(err)
		return err
	}

	if folder != "" {
		pstr, err := saveDataToFile(byteArr, f, folder, *state.GroupId+"-state")
		if err != nil {
			Log.Error(err)
			return err
		}
		Log.Printf("pstr=%s", pstr)
	}

	if bucket != "" {
		pstrS3, err := saveDataToFile(byteArr, s3, bucket, *state.GroupId+"-state")
		if err != nil {
			Log.Error(err)
			return err
		}
		Log.Printf("pstr=%s", pstrS3)
	}
	return nil
}

// XXX
func containsResult(slice []config.CompliantCheckResult, result config.CompliantCheckResult) bool {
	for _, r := range slice {
		if r.IsSameCheckResult(result) {
			return true
		}
	}
	return false
}
