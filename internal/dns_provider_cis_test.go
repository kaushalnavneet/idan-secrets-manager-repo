package publiccerts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/hashicorp/go-hclog"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	smErrors "github.ibm.com/security-services/secrets-manager-vault-plugins-common/errors"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	mock "github.ibm.com/security-services/secrets-manager-vault-plugins-common/testing"
	"gotest.tools/v3/assert"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

const (
	domainId      = "domainId"
	domainName    = "domainName"
	keyAuth       = "keyAuth"
	tokenNotInUse = "token"
	fakeIamToken  = "fake.access.token"
	fakeIamError  = "test error"
	cisCrn        = "cis_crn"
	cisApikey     = "cis_apikey"
	smCrn         = "SM_crn"
	txtRecordId   = "txtRecordId"
	subdomain     = "sub.sub.sub.domain.com"
)

func Test_ValidateConfig(t *testing.T) {
	common.SetLogger(hclog.L())

	providerConfig := map[string]string{dnsConfigCisCrn: cisCrn, dnsConfigCisApikey: cisApikey, dnsConfigSMCrn: smCrn}
	iamMock := &mock.AuthUtilsMock{}

	t.Run("Happy flow ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				RequestKey{Method: http.MethodGet, Path: urlCISProd}: {StatusCode: 200, JsonBody: `{}`},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, fakeIamToken, headers[authUserTokenHeader])
			}}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.validateConfig()
		assert.NilError(t, err)
	})
	t.Run("Authorization error", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				RequestKey{Method: http.MethodGet, Path: urlCISProd}: {StatusCode: 403, JsonBody: `{}`},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, fakeIamToken, headers[authUserTokenHeader])
			}}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.validateConfig()
		expectedMessage := fmt.Sprintf(authorizationError, "to access", dnsProviderCISInstance)
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07031, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})
	t.Run("CIS server error", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				RequestKey{Method: http.MethodGet, Path: urlCISProd}: {StatusCode: 503, JsonBody: `{}`},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, fakeIamToken, headers[authUserTokenHeader])
			}}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.validateConfig()
		expectedMessage := fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS)
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07032, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})
	t.Run("CIS client error", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				RequestKey{Method: http.MethodGet, Path: urlCISProd}: {Error: errors.New("timout")},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, fakeIamToken, headers[authUserTokenHeader])
			}}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.validateConfig()
		expectedMessage := fmt.Sprintf(unavailableDNSError, dnsProviderCIS)
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07030, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})
	t.Run("CIS wrong api key", func(t *testing.T) {
		rc := &RestClientFactoryMock{}
		iamMock.AuthPluginReqErr = true
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.validateConfig()
		expectedMessage := obtainTokenError + ": " + fakeIamError
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07029, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})
	t.Run("No s2s auth to access CIS", func(t *testing.T) {
		providerConfig[dnsConfigCisApikey] = ""
		rc := &RestClientFactoryMock{}
		iamMock.AuthPluginReqErr = true
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.validateConfig()
		expectedMessage := obtainCRNTokenError + ": " + fakeIamError
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07029, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})
}

func Test_Present(t *testing.T) {
	common.SetLogger(hclog.L())

	providerConfig := map[string]string{dnsConfigCisCrn: cisCrn, dnsConfigCisApikey: cisApikey, dnsConfigSMCrn: smCrn}
	iamMock := &mock.AuthUtilsMock{}
	challengeBody := buildChallengeBody()
	expectedDomainData := CISDomainData{
		name:           domainName,
		zoneId:         domainId,
		txtRecordName:  challengeBody.Name,
		txtRecordValue: challengeBody.Content,
		txtRecordId:    txtRecordId,
	}

	t.Run("Happy flow ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCISProd}: {StatusCode: 200, JsonBody: string(buildCISListResponse(true))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlCISProd}: {StatusCode: 200, JsonBody: string(buildCISResponse())},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, fakeIamToken, headers[authUserTokenHeader])
			},
			CheckParameters: func(method string, path string, body interface{}) {
				if method == http.MethodPost {
					sentBody := CISRequest{}
					json.Unmarshal([]byte(body.(*bytes.Buffer).String()), &sentBody)
					assert.DeepEqual(t, challengeBody, sentBody)
					assert.Equal(t, path, fmt.Sprintf(`%s/%s/zones/%s/dns_records`, urlCISProd, url.QueryEscape(cisCrn), url.QueryEscape(domainId)))
				}
			}}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.Present(domainName, tokenNotInUse, keyAuth)
		assert.NilError(t, err)
		assert.Equal(t, true, reflect.DeepEqual(*dns.Domains[domainName], expectedDomainData))
	})

	t.Run("Domain not found ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCISProd}: {StatusCode: 200, JsonBody: string(buildCISListResponse(false))},
			},
		}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.Present(subdomain, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07072, fmt.Sprintf(domainIsNotFound, subdomain, dnsProviderCISInstance))
		assert.Equal(t, expectedMessage, err.Error())
	})

}

func buildChallengeBody() CISRequest {
	txtRecordName, txtRecordValue := dns01.GetRecord(domainName, keyAuth)
	body := CISRequest{
		Name:    txtRecordName,
		Content: txtRecordValue,
		Type:    "TXT",
		TTL:     txtRecordTtl,
	}
	return body
}

func buildCISListResponse(found bool) []byte {
	cisListResp := CISResponseList{
		Success: true,
		Result:  []CISResult{},
		Errors:  nil,
	}
	if found {
		cisListResp.Result = append(cisListResp.Result, CISResult{ID: domainId})
	}
	respListStr, _ := json.Marshal(cisListResp)
	return respListStr
}

func buildCISResponse() []byte {
	cisResp := CISResponseResult{
		Success: true,
		Result:  CISResult{ID: txtRecordId},
		Errors:  nil,
	}
	respStr, _ := json.Marshal(cisResp)
	return respStr
}
