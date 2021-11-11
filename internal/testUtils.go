package publiccerts

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/go-resty/resty/v2"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/certificate/certificate_struct"
	"io/ioutil"
	"net/http"
	"strings"
)

type RestClientFactoryMock struct {
	CheckParameters func(method string, path string, body interface{})
	CheckHeaders    func(method string, path string, headers map[string]string)
	BuildResponse   func(url string, method string, headers map[string]string, requestBody interface{}, responseScheme interface{}) (*resty.Response, error)
	Results         map[RequestKey]RequestResult
}

type RequestKey struct {
	Method, Path string
	Body         interface{}
}

type RequestResult struct {
	StatusCode int
	JsonBody   string
	Error      error
}

func (rcm RestClientFactoryMock) SendRequest(url string, method string, headers map[string]string, requestBody interface{}, responseScheme interface{}) (*resty.Response, error) {
	if rcm.CheckParameters != nil {
		rcm.CheckParameters(method, url, requestBody)
	}
	if rcm.CheckHeaders != nil {
		rcm.CheckHeaders(method, url, headers)
	}
	var reqResult RequestResult
	found := false
	//find result that matches to request  key
	for key := range rcm.Results {
		if method == key.Method && strings.Contains(url, key.Path) && (key.Body == nil || requestBody == key.Body) {
			reqResult = rcm.Results[key]
			found = true
			break
		}
	}
	if !found {
		if rcm.BuildResponse != nil {
			return rcm.BuildResponse(url, method, headers, requestBody, responseScheme)
		}
		return nil, errors.New("mock doesn't support this request")
	}
	if reqResult.Error != nil {
		return nil, reqResult.Error
	}
	resp := &resty.Response{
		Request: nil,
		RawResponse: &http.Response{
			StatusCode: reqResult.StatusCode,
			Body:       ioutil.NopCloser(bytes.NewBufferString(reqResult.JsonBody)),
		},
	}
	if responseScheme != nil {
		_ = json.Unmarshal([]byte(reqResult.JsonBody), responseScheme)
	}
	return resp, nil
}

func (rcm RestClientFactoryMock) GetClient() *resty.Client {
	return nil
}

func (rcm RestClientFactoryMock) InitClientWithOptions(opts rest_client.RestClientOptions) *resty.Client {
	return nil
}

//CertificateParse implementation.
type parserMock struct {
}

func (cp *parserMock) ParseCertificate(cert string, inter string, privateKey string) (*certificate_struct.Certificate, error) {
	return nil, errors.New("parsing error")
}
