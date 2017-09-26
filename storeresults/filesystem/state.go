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
	"bytes"
	"encoding/json"
	"io"
	"os"

	"github.com/kreuzwerker/arebot/config"
	"github.com/Sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/s3"
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

type FileFetcher interface {
	GetObject(*s3.GetObjectInput) (*s3.GetObjectOutput, error)
	PutObject(*s3.PutObjectInput) (*s3.PutObjectOutput, error)
}

func NewStateDataFromByte(byteData []byte, s *ec2.SecurityGroup) (*ec2.SecurityGroup, error) {
	err := json.Unmarshal(byteData, s)
	if err != nil {
		return &ec2.SecurityGroup{}, err
	}
	return s, nil
}

/* 	Return the resource state data associated with the security group named as the
 	`key` parameter, and stored in a file with the same name `key`.
*/
func getDataFromFile(fetcher FileFetcher, bucket string, key string) ([]byte, error) {
	results, err := fetcher.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		return nil, err
	}
	defer results.Body.Close()

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, results.Body); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func saveDataToFile(input []byte, fetcher FileFetcher, bucket string, key string) (*s3.PutObjectOutput, error) {
	results, err := fetcher.PutObject(&s3.PutObjectInput{
		Body:   bytes.NewReader(bytes.NewBuffer(input).Bytes()),
		Bucket: aws.String(bucket),
		Key:    aws.String(key), // `key` is the security group ID
		/*
		   ServerSideEncryption: aws.String("AES256"),
		   Tagging:              aws.String("key1=value1&key2=value2"),
		*/
	})

	// log.Print(results)

	if err != nil {
		return nil, err
	}
	return results, nil
}
