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
  "github.com/aws/aws-sdk-go/service/s3"
  "github.com/aws/aws-sdk-go/aws/session"
  
  "github.com/kreuzwerker/arebot/util"
)

type s3FileFetcher struct {
  data []byte
  file string
}

func NewS3FileFetcher() FileFetcher {
  return &s3FileFetcher{}
}

func (fetcher *s3FileFetcher) GetObject(s3Input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
  cfg := util.GetS3Config()

  sess := session.Must(session.NewSession())
  svc := s3.New(sess, cfg)

  resp, err := svc.GetObject(s3Input)
  if err != nil {
    Log.Errorln(err)
    return nil, err
  }

  return resp, nil
}

func (fetcher *s3FileFetcher) PutObject(s3Input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
  cfg := util.GetS3Config()

  sess := session.Must(session.NewSession())
  svc := s3.New(sess, cfg)

  resp, err := svc.PutObject(s3Input)
  if err != nil {
    Log.Errorln(err)
    return nil, err
  }

  return resp, nil
}
