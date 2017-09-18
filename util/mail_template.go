package util

import (
	"bytes"
	"errors"
	"html/template"
	"io/ioutil"
	"regexp"

	"github.com/kreuzwerker/arebot/config"
)

type varsTemplate struct {
	AccountID     string
	AccountRegion string
	Results       []mailResults
	// Results       []config.CompliantCheckResult
}

type mailResults struct {
	CheckResult    config.CompliantCheckResult
	FormattedValue string
}

// TODO send reports of multiple check results
func createMessageBody(checkResult config.CompliantCheckResult, templateName string) (string, error) {
	// TODO temporary fix until multiple check results support
	checkResults := []config.CompliantCheckResult{checkResult}
	// define an instance of the vars object
	v := varsTemplate{
		AccountID:     checkResult.EventUser.Username,
		AccountRegion: checkResult.EventUser.Region,
		Results:       createMailResults(checkResults),
	}

	// fetch the content for generating the template
	content, err := ioutil.ReadFile("./util/mailtemplate/" + templateName + ".html")
	if err != nil {
		return "", errors.New("Could not open the template file: " + err.Error())
	}

	// create a new template with the given content
	t := template.New("Mail Template")
	// parse the content and generate the template
	t, err = t.Parse(string(content))
	if err != nil {
		return "", errors.New("Could not parse the Template: " + err.Error())
	}

	// merge the template with the content of the variables in v
	var mergedContent bytes.Buffer
	err = t.Execute(&mergedContent, v)
	if err != nil {
		return "", errors.New("Could not execute the merge of the Template: " + err.Error())
	}

	finalMail := assembleTemplate(mergedContent.String())
	return finalMail, nil
}

func assembleTemplate(content string) string {
	header, err := ioutil.ReadFile("./util/mailtemplate/header.html")
	if err != nil {
		Log.Errorf("Could not open the template file: %s", err.Error())
	}
	footer, err := ioutil.ReadFile("./util/mailtemplate/footer.html")
	if err != nil {
		Log.Errorf("Could not open the template file: %s", err.Error())
	}
	return string(header) + content + string(footer)
}

func createMailResults(ccres []config.CompliantCheckResult) []mailResults {
	var mresults []mailResults

	for _, r := range ccres {
		if r.IsIpPermissionsCheck() {

			reIp, _ := regexp.Compile("^P:([^;]*);FP:([^;]*);TP:([^;]*);IP:(.*)$")
			reUg, _ := regexp.Compile("^P:([^;]*);FP:([^;]*);TP:([^;]*);UG:(.*)$")
			var sbs [][]string
			if reIp.MatchString(r.Value) {
				sbs = reIp.FindAllStringSubmatch(r.Value, -1)
			} else { // if false is a record with User-Group pair
				sbs = reUg.FindAllStringSubmatch(r.Value, -1)
			}
			mresults = append(mresults, mailResults{CheckResult: r, FormattedValue: "(" + sbs[0][1] + ") " + sbs[0][4] + ":" + sbs[0][2] + "-" + sbs[0][3]})

		} else {
			mresults = append(mresults, mailResults{CheckResult: r, FormattedValue: r.Value})
		}
	}

	return mresults
}
