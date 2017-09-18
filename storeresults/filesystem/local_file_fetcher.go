package filesystem

import (
  "path/filepath"
  "io/ioutil"
  "log"
  "os"
  "bytes"
  
  "github.com/aws/aws-sdk-go/service/s3"
)

type fileFetcher struct {
  data []byte
  file string
}

func NewFileFetcher() FileFetcher {
  return &fileFetcher{}
}

func (fetcher *fileFetcher) GetObject(s3Input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
  // completely ignore the input, just return an object wrapping the fetcher.data

  fetcher.file = filepath.Join(*s3Input.Bucket, *s3Input.Key)
  jsonbuf, err := ioutil.ReadFile(fetcher.file)
  log.Printf("reading offers from file '%s'", fetcher.file)
  if err != nil {
    return nil, err
  }
  fetcher.data = jsonbuf
  return &s3.GetObjectOutput{
    Body: *(NewMockBody(fetcher.data)),
  }, nil
}

func (fetcher *fileFetcher) PutObject(s3Input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
  // completely ignore the input, just return an object wrapping the fetcher.data
  //log.Printf("writing offers to file '%s'", fetcher.file)
  furl := filepath.Join(*s3Input.Bucket, *s3Input.Key)
  if err := os.MkdirAll(filepath.Dir(furl), os.ModePerm); err != nil {
    return nil, err
  }
  //log.Printf("%+v, %+v", furl, filepath.Dir(furl))
  b, err := ioutil.ReadAll(s3Input.Body)
  if err = ioutil.WriteFile(furl, b, 0644); err != nil {
    return nil, err
  }
  return &s3.PutObjectOutput{}, nil
}

type MockBody struct {
  buf *bytes.Buffer
}

func (m MockBody) Close() error {
  return nil
}

func (m MockBody) Read(p []byte) (n int, err error) {
  return m.buf.Read(p)
}

func (m MockBody) Write(p []byte) (n int, err error) {
  return m.buf.Write(p)
}

func NewMockBody(jsonBody []byte) *MockBody {
  ret := MockBody{
    buf: bytes.NewBuffer(jsonBody),
  }
  return &ret
}
