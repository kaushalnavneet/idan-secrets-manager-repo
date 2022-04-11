package publiccerts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/hashicorp/go-hclog"
	smErrors "github.ibm.com/security-services/secrets-manager-common-utils/errors"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	mock "github.ibm.com/security-services/secrets-manager-vault-plugins-common/testing"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/vault_client_impl"
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
	cisCrn        = "crn:v1:bluemix:public:internet-svcs:global:a/22222222222222222222222222222222:13617212-081d-4c52-964d-823c5cf11111::"
	cisApikey     = "cis_apikey"
	smCrn         = "SM_crn"
	txtRecordId   = "txtRecordId"
	subdomain     = "sub.sub.sub.domain.com"
)

var (
	txtRecName, txtRecValue = dns01.GetRecord(domainName, keyAuth)
	clientError             = errors.New("timeout")

	urlCisToGetZoneId       = fmt.Sprintf(`%s/%s/zones?name=%s&status=active`, urlCISProd, url.QueryEscape(cisCrn), domainName)
	urlCisToSetChallenge    = fmt.Sprintf(`%s/%s/zones/%s/dns_records`, urlCISProd, url.QueryEscape(cisCrn), domainId)
	urlCisToRemoveTxtRecord = fmt.Sprintf(`%s/%s/zones/%s/dns_records/%s`, urlCISProd, url.QueryEscape(cisCrn), domainId, txtRecordId)
	urlCisToGetTxtRecord    = fmt.Sprintf(`%s/%s/zones/%s/dns_records?type=TXT&name=%s&content=%s`, urlCISProd, url.QueryEscape(cisCrn), domainId, txtRecName, txtRecValue)

	expectedCisDomainData = CISDomainData{
		name:           domainName,
		zoneId:         domainId,
		txtRecordName:  txtRecName,
		txtRecordValue: txtRecValue,
		txtRecordId:    txtRecordId,
	}

	expectedCisChallengeBody = CISRequest{
		Name:    txtRecName,
		Content: txtRecValue,
		Type:    "TXT",
		TTL:     txtRecordTtl,
	}
)

func Test_CIS_CreateConfig(t *testing.T) {

	rc := &RestClientFactoryMock{}

	t.Run("Can be created without iam utils", func(t *testing.T) {
		providerConfig := map[string]string{dnsConfigCisCrn: cisCrn, dnsConfigCisApikey: cisApikey, dnsConfigSMCrn: smCrn}
		cisProvider := NewCISDNSProvider(providerConfig, rc, nil)
		expectedConfig := &CISDNSConfig{
			CRN:           cisCrn,
			CISEndpoint:   urlCISProd,
			IAMEndpoint:   urlIamProd,
			APIKey:        cisApikey,
			TTL:           txtRecordTtl,
			Domains:       make(map[string]*CISDomainData),
			restClient:    rc,
			smInstanceCrn: smCrn,
			authUtils:     &common.AuthUtilsImpl{Client: &vault_client_impl.VaultClientFactory{Logger: common.Logger()}},
		}
		assert.Equal(t, true, reflect.DeepEqual(expectedConfig, cisProvider))
	})

	t.Run("Can be created for CIS Integration", func(t *testing.T) {
		cisIntCrn := "crn:v1:bluemix:staging:internet-svcs-ci:global:a/22222222222222222222222222222222:13617212-081d-4c52-964d-823c5cf11111::"
		providerConfig := map[string]string{dnsConfigCisCrn: cisIntCrn}
		cisProvider := NewCISDNSProvider(providerConfig, rc, nil)
		expectedConfig := &CISDNSConfig{
			CRN:           cisIntCrn,
			CISEndpoint:   urlCISIntegration,
			IAMEndpoint:   urlIamStage,
			APIKey:        "",
			TTL:           txtRecordTtl,
			Domains:       make(map[string]*CISDomainData),
			restClient:    rc,
			smInstanceCrn: "",
			authUtils:     &common.AuthUtilsImpl{Client: &vault_client_impl.VaultClientFactory{Logger: common.Logger()}},
		}
		assert.Equal(t, true, reflect.DeepEqual(expectedConfig, cisProvider))
	})

	t.Run("Can be created for CIS staging", func(t *testing.T) {
		cisStaging := "crn:v1:bluemix:staging:internet-svcs:global:a/22222222222222222222222222222222:13617212-081d-4c52-964d-823c5cf11111::"
		providerConfig := map[string]string{dnsConfigCisCrn: cisStaging}
		iamMock := &mock.AuthUtilsMock{}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		expectedConfig := &CISDNSConfig{
			CRN:           cisStaging,
			CISEndpoint:   urlCISStage,
			IAMEndpoint:   urlIamStage,
			APIKey:        "",
			TTL:           txtRecordTtl,
			Domains:       make(map[string]*CISDomainData),
			restClient:    rc,
			smInstanceCrn: "",
			authUtils:     iamMock,
		}
		assert.Equal(t, true, reflect.DeepEqual(expectedConfig, cisProvider))
	})
}

func Test_CIS_ValidateConfigStructure(t *testing.T) {
	common.SetLogger(hclog.L())
	t.Run("Happy flow ", func(t *testing.T) {
		providerConfig := map[string]string{dnsConfigCisCrn: cisCrn, dnsConfigCisApikey: cisApikey}
		err := validateCISConfigStructure(providerConfig, smCrn)
		assert.NilError(t, err)
	})

	t.Run("Missing Cis crn", func(t *testing.T) {
		providerConfig := map[string]string{}
		err := validateCISConfigStructure(providerConfig, smCrn)
		expectedMessage := fmt.Sprintf(configMissingField, providerTypeDNS, dnsConfigCisCrn)
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07025, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})

	t.Run("Invalid Cis crn", func(t *testing.T) {
		providerConfig := map[string]string{dnsConfigCisCrn: "crn:v1:bluemix:public:OTHER-SERVICE:global:a/22222222222222222222222222222222:13617212-081d-4c52-964d-823c5cf11111::"}
		err := validateCISConfigStructure(providerConfig, smCrn)
		expectedMessage := invalidCISInstanceCrn
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07027, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})

	t.Run("Not Cis crn", func(t *testing.T) {
		providerConfig := map[string]string{dnsConfigCisCrn: "wrong"}
		err := validateCISConfigStructure(providerConfig, smCrn)
		expectedMessage := invalidCISInstanceCrn
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07026, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})

	t.Run("Unexpected field", func(t *testing.T) {
		providerConfig := map[string]string{dnsConfigCisCrn: cisCrn, "unexpected_field": "value"}
		err := validateCISConfigStructure(providerConfig, smCrn)
		expectedMessage := fmt.Sprintf(invalidConfigStruct, providerTypeDNS, dnsConfigTypeCIS, "["+dnsConfigCisCrn+","+dnsConfigCisApikey+"]")
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07028, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})
}

func Test_CIS_ValidateConfig(t *testing.T) {
	common.SetLogger(hclog.L())

	providerConfig := map[string]string{dnsConfigCisCrn: cisCrn, dnsConfigCisApikey: cisApikey, dnsConfigSMCrn: smCrn}
	iamMock := &mock.AuthUtilsMock{}

	t.Run("Happy flow ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				RequestKey{Method: http.MethodGet, Path: urlCISProd}: {StatusCode: http.StatusOK, JsonBody: `{}`},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, fakeIamToken, headers[authUserTokenHeader])
			}}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.validateConfig()
		assert.NilError(t, err)
	})

	t.Run("Authorization error", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				RequestKey{Method: http.MethodGet, Path: urlCISProd}: {StatusCode: http.StatusForbidden, JsonBody: `{}`},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, fakeIamToken, headers[authUserTokenHeader])
			}}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.validateConfig()
		expectedMessage := fmt.Sprintf(authorizationError, "to access", dnsProviderCISInstance)
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07031, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})

	t.Run("CIS server error", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				RequestKey{Method: http.MethodGet, Path: urlCISProd}: {StatusCode: http.StatusServiceUnavailable, JsonBody: `{}`},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, fakeIamToken, headers[authUserTokenHeader])
			}}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.validateConfig()
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
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.validateConfig()
		expectedMessage := fmt.Sprintf(unavailableDNSError, dnsProviderCIS)
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07030, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})

	t.Run("CIS wrong api key", func(t *testing.T) {
		rc := &RestClientFactoryMock{}
		iamMock.AuthPluginReqErr = true
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.validateConfig()
		expectedMessage := obtainTokenError + ": " + fakeIamError
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07029, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})

	t.Run("No s2s auth to access CIS", func(t *testing.T) {
		providerConfig[dnsConfigCisApikey] = ""
		rc := &RestClientFactoryMock{}
		iamMock.AuthPluginReqErr = true
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.validateConfig()
		expectedMessage := obtainCRNTokenError + ": " + fakeIamError
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07029, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})
}

func Test_CIS_Present(t *testing.T) {
	common.SetLogger(hclog.L())
	providerConfig := map[string]string{dnsConfigCisCrn: cisCrn, dnsConfigCisApikey: cisApikey, dnsConfigSMCrn: smCrn}
	iamMock := &mock.AuthUtilsMock{}

	t.Run("Happy flow ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCisToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlCisToSetChallenge}: {StatusCode: http.StatusOK, JsonBody: string(buildCISResponse())},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, fakeIamToken, headers[authUserTokenHeader])
			},
			CheckParameters: func(method string, path string, body interface{}) {
				if method == http.MethodPost {
					actualChallengBody := CISRequest{}
					json.Unmarshal([]byte(body.(*bytes.Buffer).String()), &actualChallengBody)
					assert.DeepEqual(t, expectedCisChallengeBody, actualChallengBody)
				}
			}}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.Present(domainName, tokenNotInUse, keyAuth)
		assert.NilError(t, err)
		assert.Equal(t, true, reflect.DeepEqual(*cisProvider.Domains[domainName], expectedCisDomainData))
	})

	t.Run("Happy flow - Challenge record already exist ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCisToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlCisToSetChallenge}: {StatusCode: http.StatusBadRequest, JsonBody: "{}"},
				//get existing txt record
				RequestKey{Method: http.MethodGet, Path: urlCisToGetTxtRecord}: {StatusCode: http.StatusOK, JsonBody: string(buildCISListResponse(txtRecordId))},
			},
		}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.Present(domainName, tokenNotInUse, keyAuth)
		assert.NilError(t, err)
		assert.Equal(t, true, reflect.DeepEqual(*cisProvider.Domains[domainName], expectedCisDomainData))
	})

	t.Run("Domain not found ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCISProd}: {StatusCode: http.StatusOK, JsonBody: string(buildCISListResponse(""))},
			},
		}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.Present(subdomain, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07072, fmt.Sprintf(domainIsNotFound, subdomain, dnsProviderCISInstance))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("Authorization error when get zone by domain ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCISProd}: {StatusCode: http.StatusForbidden, JsonBody: "{}"},
			},
		}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07073, fmt.Sprintf(authorizationError, "to get zones from", dnsProviderCISInstance))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("Authorization error when set challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCisToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlCisToSetChallenge}: {StatusCode: http.StatusForbidden, JsonBody: "{}"},
			},
		}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07077, fmt.Sprintf(authorizationError, "to set txt record in", dnsProviderCISInstance))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("Authorization error when get existing challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCisToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlCisToSetChallenge}: {StatusCode: http.StatusBadRequest, JsonBody: "{}"},
				//get existing txt record
				RequestKey{Method: http.MethodGet, Path: urlCisToGetTxtRecord}: {StatusCode: http.StatusForbidden, JsonBody: "{}"},
			},
		}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07089, fmt.Sprintf(authorizationError, "to get txt record from", dnsProviderCISInstance))
		assert.Equal(t, expectedMessage, err.Error())

	})

	t.Run("CIS server error when get zone by domain ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCisToGetZoneId}: {StatusCode: http.StatusServiceUnavailable, JsonBody: "{}"},
			},
		}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07074, fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("CIS server error when set challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCisToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlCisToSetChallenge}: {StatusCode: http.StatusServiceUnavailable, JsonBody: "{}"},
			},
		}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07078, fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("CIS server error when get existing challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCisToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlCisToSetChallenge}: {StatusCode: http.StatusBadRequest, JsonBody: "{}"},
				//get existing txt record
				RequestKey{Method: http.MethodGet, Path: urlCisToGetTxtRecord}: {StatusCode: http.StatusServiceUnavailable, JsonBody: "{}"},
			},
		}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07060, fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS))
		assert.Equal(t, expectedMessage, err.Error())

	})

	t.Run("CIS client error when get zone by domain ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCisToGetZoneId}: {Error: clientError},
			},
		}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07071, fmt.Sprintf(unavailableDNSError, dnsProviderCIS))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("CIS client error when set challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCisToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlCisToSetChallenge}: {Error: clientError},
			},
		}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07076, fmt.Sprintf(unavailableDNSError, dnsProviderCIS))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("CIS client error when get existing challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCisToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlCisToSetChallenge}: {StatusCode: http.StatusBadRequest, JsonBody: "{}"},
				//get existing txt record
				RequestKey{Method: http.MethodGet, Path: urlCisToGetTxtRecord}: {Error: clientError},
			},
		}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07087, fmt.Sprintf(unavailableDNSError, dnsProviderCIS))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("Challenge record not found ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCisToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildCISListResponse(domainId))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlCisToSetChallenge}: {StatusCode: http.StatusBadRequest, JsonBody: "{}"},
				//get existing txt record
				RequestKey{Method: http.MethodGet, Path: urlCisToGetTxtRecord}: {StatusCode: http.StatusOK, JsonBody: string(buildCISListResponse(""))},
			},
		}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07088, internalServerError)
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("No s2s auth to access CIS", func(t *testing.T) {
		providerConfig[dnsConfigCisApikey] = ""
		rc := &RestClientFactoryMock{}
		iamMock.AuthPluginReqErr = true
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07070, obtainCRNTokenError+": "+fakeIamError)
		assert.Equal(t, expectedMessage, err.Error())
	})
}

func Test_CIS_Cleanup(t *testing.T) {
	common.SetLogger(hclog.L())

	providerConfig := map[string]string{dnsConfigCisCrn: cisCrn, dnsConfigCisApikey: cisApikey, dnsConfigSMCrn: smCrn}
	iamMock := &mock.AuthUtilsMock{}

	t.Run("Happy flow - domain in the list", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodDelete, Path: urlCisToRemoveTxtRecord}: {StatusCode: http.StatusOK, JsonBody: `{"Success": true }`},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, fakeIamToken, headers[authUserTokenHeader])
			},
		}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		cisProvider.Domains[domainName] = &expectedCisDomainData
		err := cisProvider.CleanUp(domainName, tokenNotInUse, keyAuth)
		assert.NilError(t, err)
		assert.Equal(t, 0, len(cisProvider.Domains))
	})

	t.Run("Happy flow - domain is not in the list", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodDelete, Path: urlCisToRemoveTxtRecord}: {StatusCode: http.StatusOK, JsonBody: `{"Success": true }`},
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlCisToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildCISListResponse(domainId))},
				//get existing txt record
				RequestKey{Method: http.MethodGet, Path: urlCisToGetTxtRecord}: {StatusCode: http.StatusOK, JsonBody: string(buildCISListResponse(txtRecordId))},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, fakeIamToken, headers[authUserTokenHeader])
			},
		}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		err := cisProvider.CleanUp(domainName, tokenNotInUse, keyAuth)
		assert.NilError(t, err)
		assert.Equal(t, 0, len(cisProvider.Domains))
	})

	t.Run("Authorization error when removing challenge", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodDelete, Path: urlCisToRemoveTxtRecord}: {StatusCode: http.StatusForbidden, JsonBody: `{}`},
			},
		}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		cisProvider.Domains[domainName] = &expectedCisDomainData
		err := cisProvider.CleanUp(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07080, fmt.Sprintf(authorizationError, "to delete txt record from", dnsProviderCISInstance))
		assert.Equal(t, expectedMessage, err.Error())

	})

	t.Run("CIS server error when removing challenge", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodDelete, Path: urlCisToRemoveTxtRecord}: {StatusCode: http.StatusServiceUnavailable, JsonBody: `{}`},
			},
		}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		cisProvider.Domains[domainName] = &expectedCisDomainData
		err := cisProvider.CleanUp(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07081, fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("CIS client error when removing challenge", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodDelete, Path: urlCisToRemoveTxtRecord}: {Error: clientError},
			},
		}
		cisProvider := NewCISDNSProvider(providerConfig, rc, iamMock)
		cisProvider.Domains[domainName] = &expectedCisDomainData
		err := cisProvider.CleanUp(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07079, fmt.Sprintf(unavailableDNSError, dnsProviderCIS))
		assert.Equal(t, expectedMessage, err.Error())
	})
}

func buildCISListResponse(foundId string) []byte {
	cisListResp := CISResponseList{
		Success: true,
		Result:  []CISResult{},
		Errors:  nil,
	}
	if foundId != "" {
		cisListResp.Result = append(cisListResp.Result, CISResult{
			ID:      foundId,
			Type:    "TXT",
			Name:    "_acme-challenge.domainName.",
			Content: "pW9ZKG0xz_PCriK-nCMOjADy9eJcgGWIzkkj2fN4uZM",
		})
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
