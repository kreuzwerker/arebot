package sqsworker

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
)

// NewSQSClient returns a SQS Client and a Queue URL for you you to connect to
func NewSQSClient(queueName string, cfgs ...*aws.Config) (*sqs.SQS, string) {
	sess, err := session.NewSession()
	if err != nil {
		Log.Warn("failed to create session,", err)
		panic(err)
		// return nil, ""
	}
	svc := sqs.New(sess, cfgs...)
	// try and find the queue url

	params := &sqs.GetQueueUrlInput{
		QueueName: aws.String(queueName), // Required
	}
	resp, err := svc.GetQueueUrl(params)

	if err != nil {
		// Print the error, cast err to aws err.Error to get the Code and
		// Message from an error.
		Log.Errorf("Impossible to access the '%s' SQS queue specified in the configuration file: %s", queueName, err.Error())
		Log.Errorf("Terminate Arebot execution")
		os.Exit(1)
		// return nil, ""
	}

	return svc, aws.StringValue(resp.QueueUrl)
}
