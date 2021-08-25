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

var (
	clientError       = errors.New("timeout")
	urlToGetZoneId    = fmt.Sprintf(`%s/%s/zones?name=%s&status=active`, urlCISProd, url.QueryEscape(cisCrn), domainName)
	urlToSetChallenge = fmt.Sprintf(`%s/%s/zones/%s/dns_records`, urlCISProd, url.QueryEscape(cisCrn), domainId)
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
				RequestKey{Method: http.MethodGet, Path: urlCISProd}: {Error: clientError},
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
	expectedChallengeBody := buildChallengeBody()
	expectedDomainData := CISDomainData{
		name:           domainName,
		zoneId:         domainId,
		txtRecordName:  expectedChallengeBody.Name,
		txtRecordValue: expectedChallengeBody.Content,
		txtRecordId:    txtRecordId,
	}
	urlToGetTxtRecord := fmt.Sprintf(`%s/%s/zones/%s/dns_records?type=TXT&name=%s&content=%s`, urlCISProd, url.QueryEscape(cisCrn), domainId, expectedChallengeBody.Name, expectedChallengeBody.Content)

	t.Run("Happy flow ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlToGetZoneId}: {StatusCode: 200, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlToSetChallenge}: {StatusCode: 200, JsonBody: string(buildCISResponse())},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, fakeIamToken, headers[authUserTokenHeader])
			},
			CheckParameters: func(method string, path string, body interface{}) {
				if method == http.MethodPost {
					actualChallengBody := CISRequest{}
					json.Unmarshal([]byte(body.(*bytes.Buffer).String()), &actualChallengBody)
					assert.DeepEqual(t, expectedChallengeBody, actualChallengBody)
				}
			}}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.Present(domainName, tokenNotInUse, keyAuth)
		assert.NilError(t, err)
		assert.Equal(t, true, reflect.DeepEqual(*dns.Domains[domainName], expectedDomainData))
	})

	t.Run("Happy flow - Challenge record already exist ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlToGetZoneId}: {StatusCode: 200, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlToSetChallenge}: {StatusCode: 400, JsonBody: "{}"},
				//get existing txt record
				RequestKey{Method: http.MethodGet, Path: urlToGetTxtRecord}: {StatusCode: 200, JsonBody: string(buildCISListResponse(txtRecordId))},
			},
		}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.Present(domainName, tokenNotInUse, keyAuth)
		assert.NilError(t, err)
		assert.Equal(t, true, reflect.DeepEqual(*dns.Domains[domainName], expectedDomainData))
	})

	t.Run("Domain not found ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCISProd}: {StatusCode: 200, JsonBody: string(buildCISListResponse(""))},
			},
		}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.Present(subdomain, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07072, fmt.Sprintf(domainIsNotFound, subdomain, dnsProviderCISInstance))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("Authorization error when get zone by domain ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCISProd}: {StatusCode: 403, JsonBody: "{}"},
			},
		}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07073, fmt.Sprintf(authorizationError, "to get zones from", dnsProviderCISInstance))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("Authorization error when set challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlToGetZoneId}: {StatusCode: 200, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlToSetChallenge}: {StatusCode: 403, JsonBody: "{}"},
			},
		}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07077, fmt.Sprintf(authorizationError, "to set txt record in", dnsProviderCISInstance))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("Authorization error when get existing challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlToGetZoneId}: {StatusCode: 200, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlToSetChallenge}: {StatusCode: 400, JsonBody: "{}"},
				//get existing txt record
				RequestKey{Method: http.MethodGet, Path: urlToGetTxtRecord}: {StatusCode: 403, JsonBody: "{}"},
			},
		}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07089, fmt.Sprintf(authorizationError, "to get txt record from", dnsProviderCISInstance))
		assert.Equal(t, expectedMessage, err.Error())

	})

	t.Run("CIS server error when get zone by domain ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlToGetZoneId}: {StatusCode: 500, JsonBody: "{}"},
			},
		}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07074, fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("CIS server error when set challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlToGetZoneId}: {StatusCode: 200, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlToSetChallenge}: {StatusCode: 503, JsonBody: "{}"},
			},
		}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07078, fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("CIS server error when get existing challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlToGetZoneId}: {StatusCode: 200, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlToSetChallenge}: {StatusCode: 400, JsonBody: "{}"},
				//get existing txt record
				RequestKey{Method: http.MethodGet, Path: urlToGetTxtRecord}: {StatusCode: 503, JsonBody: "{}"},
			},
		}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07060, fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS))
		assert.Equal(t, expectedMessage, err.Error())

	})

	t.Run("CIS client error when get zone by domain ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlToGetZoneId}: {Error: clientError},
			},
		}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07071, fmt.Sprintf(unavailableDNSError, dnsProviderCIS))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("CIS client error when set challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlToGetZoneId}: {StatusCode: 200, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlToSetChallenge}: {Error: clientError},
			},
		}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07076, fmt.Sprintf(unavailableDNSError, dnsProviderCIS))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("CIS client error when get existing challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlToGetZoneId}: {StatusCode: 200, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlToSetChallenge}: {StatusCode: 400, JsonBody: "{}"},
				//get existing txt record
				RequestKey{Method: http.MethodGet, Path: urlToGetTxtRecord}: {Error: clientError},
			},
		}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07087, fmt.Sprintf(unavailableDNSError, dnsProviderCIS))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("Challenge record not found ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlToGetZoneId}: {StatusCode: 200, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlToSetChallenge}: {StatusCode: 400, JsonBody: "{}"},
				//get existing txt record
				RequestKey{Method: http.MethodGet, Path: urlToGetTxtRecord}: {StatusCode: 200, JsonBody: string(buildCISListResponse(""))},
			},
		}
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07088, internalServerError)
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("No s2s auth to access CIS", func(t *testing.T) {
		providerConfig[dnsConfigCisApikey] = ""
		rc := &RestClientFactoryMock{}
		iamMock.AuthPluginReqErr = true
		dns := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := dns.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07070, obtainCRNTokenError+": "+fakeIamError)
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

func buildCISListResponse(foundId string) []byte {
	cisListResp := CISResponseList{
		Success: true,
		Result:  []CISResult{},
		Errors:  nil,
	}
	if foundId != "" {
		cisListResp.Result = append(cisListResp.Result, CISResult{ID: foundId})
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
