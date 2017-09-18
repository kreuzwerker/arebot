package sqsworker

import (
	"fmt"
	"sync"

	"github.com/kreuzwerker/arebot/resource/securitygroup"

	"github.com/Sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
)

// HandlerFunc is used to define the Handler that is run on for each message
type HandlerFunc func(msg *sqs.Message) error

func (f HandlerFunc) HandleMessage(msg *sqs.Message) error {
	return f(msg)
}

// Handler interface
type Handler interface {
	HandleMessage(msg *sqs.Message) error
}

type InvalidEventError struct {
	event string
	msg   string
}

func (e InvalidEventError) Error() string {
	return fmt.Sprintf("[Invalid Event: %s] %s", e.event, e.msg)
}

func NewInvalidEventError(event, msg string) InvalidEventError {
	return InvalidEventError{event: event, msg: msg}
}

// Exported Variables
var (
	// The maximum number of messages to return. Amazon SQS never returns more messages
	// than this value (however, fewer messages might be returned). Valid values
	// are 1 to 10. Default is 10.
	MaxNumberOfMessage int64 = 10
	// The duration (in seconds) for which the call waits for a message to arrive
	// in the queue before returning. If a message is available, the call returns
	// sooner than WaitTimeSeconds.
	WaitTimeSecond int64 = 20

	Log *logrus.Logger
)

// Start starts the polling and will continue polling till the application is forcibly stopped
func Start(svc *sqs.SQS, queueURL string, h Handler) {
	for {

		Log.Debug("worker: Start Polling: ", queueURL)
		params := &sqs.ReceiveMessageInput{
			QueueUrl:            aws.String(queueURL), // Required
			MaxNumberOfMessages: aws.Int64(MaxNumberOfMessage),
			MessageAttributeNames: []*string{
				aws.String("All"), // Required
			},
			WaitTimeSeconds: aws.Int64(WaitTimeSecond),
		}

		resp, err := svc.ReceiveMessage(params)
		if err != nil {
			Log.Println(err)
			continue
		}
		if len(resp.Messages) > 0 {
			run(svc, queueURL, h, resp.Messages)
		}
	}
}

// poll launches goroutine per received message and wait for all message to be processed
func run(svc *sqs.SQS, queueURL string, h Handler, messages []*sqs.Message) {
	numMessages := len(messages)
	Log.Debugf("worker: Received %d messages", numMessages)

	var wg sync.WaitGroup
	wg.Add(numMessages)
	for i := range messages {
		go func(m *sqs.Message) {
			// launch goroutine
			defer wg.Done()
			if err := handleMessage(svc, queueURL, m, h); err != nil {
				Log.Errorf("sqsworker.worker.run: %s", err.Error())
			}
		}(messages[i])
	}

	wg.Wait()
}

func handleMessage(svc *sqs.SQS, queueURL string, m *sqs.Message, h Handler) error {
	var err error
	err = h.HandleMessage(m)

	/* sqs worker errors */
	if _, ok := err.(InvalidEventError); ok {
		Log.Error(err.Error())
	} else /* securitygroup errors */ if _err, ok := err.(securitygroup.SecurityGroupError); ok {
		if _err.Ignore != true {
			return err
		}
		Log.Warnf("Ignoring error and deleting message: %s", _err.Error())
	} else /* all other error */ if err != nil {
		return err
	}

	params := &sqs.DeleteMessageInput{
		QueueUrl:      aws.String(queueURL), // Required
		ReceiptHandle: m.ReceiptHandle,      // Required
	}
	_, err = svc.DeleteMessage(params)
	if err != nil {
		return err
	}
	Log.Debug("worker: deleted message from queue: %s", aws.StringValue(m.ReceiptHandle))

	return nil
}
