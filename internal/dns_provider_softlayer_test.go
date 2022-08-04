package publiccerts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-hclog"
	smErrors "github.ibm.com/security-services/secrets-manager-common-utils/errors"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"gotest.tools/v3/assert"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"testing"
)

const (
	domainIdInt    = 4321
	txtRecordIdInt = 1234
	slUser         = "slUser"
	slPassword     = "slPassword"
)

var (
	slAuth = base64.StdEncoding.EncodeToString([]byte(slUser + ":" + slPassword))

	urlSlToGetZoneId       = fmt.Sprintf("%s/SoftLayer_Dns_Domain/getByDomainName/%s", urlSLApi, domainName)
	urlSlToSetChallenge    = fmt.Sprintf(`%s/SoftLayer_Dns_Domain_ResourceRecord`, urlSLApi)
	urlSlToRemoveTxtRecord = fmt.Sprintf(`%s/SoftLayer_Dns_Domain_ResourceRecord/%d`, urlSLApi, txtRecordIdInt)
	objectFilter           = fmt.Sprintf(`{"resourceRecords":{"host":{"operation": "%s"},"data":{"operation": "%s"}}}`, txtRecName, txtRecValue)
	urlSlToGetTxtRecord    = fmt.Sprintf(`%s/SoftLayer_Dns_Domain/%d/getResourceRecords?objectFilter=%s`, urlSLApi, domainIdInt, url.QueryEscape(objectFilter))

	expectedDomainData = SLDomainData{
		name:           domainName,
		zoneId:         domainIdInt,
		txtRecordName:  txtRecName,
		txtRecordValue: txtRecValue,
		txtRecordId:    txtRecordIdInt,
	}

	expectedChallengeBody = SLRequest{
		Parameters: []SLDNSRecord{{
			Host:     txtRecName,
			Data:     txtRecValue,
			Ttl:      txtRecordTtl,
			Type:     "txt",
			DomainId: domainIdInt,
		}}}
)

func Test_SL_CreateConfig(t *testing.T) {

	rc := &RestClientFactoryMock{}

	t.Run("Happy flow", func(t *testing.T) {
		providerConfig := map[string]string{dnsConfigSLUser: slUser, dnsConfigSLPassword: slPassword}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		expectedConfig := &SoftlayerDNSConfig{
			User:              slUser,
			Password:          slPassword,
			Auth:              slAuth,
			SoftlayerEndpoint: urlSLApi,
			TTL:               txtRecordTtl, //for TXT records
			Domains:           make(map[string]*SLDomainData),
			restClient:        rc,
		}
		assert.Equal(t, true, reflect.DeepEqual(expectedConfig, slProvider))
	})
}

func Test_SL_ValidateConfigStructure(t *testing.T) {
	common.SetLogger(hclog.L())
	t.Run("Happy flow ", func(t *testing.T) {
		providerConfig := map[string]string{dnsConfigSLUser: slUser, dnsConfigSLPassword: slPassword}
		err := validateSoftLayerConfigStructure(providerConfig)
		assert.NilError(t, err)
	})

	t.Run("Missing SL user", func(t *testing.T) {
		providerConfig := map[string]string{}
		err := validateSoftLayerConfigStructure(providerConfig)
		expectedMessage := fmt.Sprintf(configMissingField, providerTypeDNS, dnsConfigSLUser)
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07033, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})

	t.Run("Missing SL password", func(t *testing.T) {
		providerConfig := map[string]string{dnsConfigSLUser: slUser}
		err := validateSoftLayerConfigStructure(providerConfig)
		expectedMessage := fmt.Sprintf(configMissingField, providerTypeDNS, dnsConfigSLPassword)
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07034, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})

	t.Run("Unexpected field", func(t *testing.T) {
		providerConfig := map[string]string{dnsConfigSLUser: slUser, dnsConfigSLPassword: slPassword, "unexpected_field": "value"}
		err := validateSoftLayerConfigStructure(providerConfig)
		expectedMessage := fmt.Sprintf(invalidConfigStruct, providerTypeDNS, dnsConfigTypeCIS, "["+dnsConfigSLUser+","+dnsConfigSLPassword+"]")
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07035, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})
}

func Test_SL_ValidateConfig(t *testing.T) {
	common.SetLogger(hclog.L())
	providerConfig := map[string]string{dnsConfigSLUser: slUser, dnsConfigSLPassword: slPassword}

	t.Run("Happy flow ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				RequestKey{Method: http.MethodGet, Path: urlSLApi}: {StatusCode: http.StatusOK, JsonBody: `{}`},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, "Basic "+slAuth, headers[authorizationHeader])
			}}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.validateConfig()
		assert.NilError(t, err)
	})

	t.Run("Authorization error", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				RequestKey{Method: http.MethodGet, Path: urlSLApi}: {StatusCode: http.StatusForbidden, JsonBody: `{}`},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, "Basic "+slAuth, headers[authorizationHeader])
			}}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.validateConfig()
		expectedMessage := fmt.Sprintf(authorizationError, "to access", dnsProviderSoftLayerAccount)
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07037, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})

	t.Run("SL server error", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				RequestKey{Method: http.MethodGet, Path: urlSLApi}: {StatusCode: http.StatusServiceUnavailable, JsonBody: `{"error":"some error","code":"123456"}`},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, "Basic "+slAuth, headers[authorizationHeader])
			}}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.validateConfig()
		expectedMessage := fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer)
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07038, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})

	t.Run("SL client error", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				RequestKey{Method: http.MethodGet, Path: urlSLApi}: {Error: clientError},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, "Basic "+slAuth, headers[authorizationHeader])
			}}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.validateConfig()
		expectedMessage := fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer)
		assert.Equal(t, expectedMessage, err.(smErrors.SMCodedError).Error())
		assert.Equal(t, logdna.Error07036, err.(smErrors.SMCodedError).ErrCode())
		assert.Equal(t, http.StatusBadRequest, err.(smErrors.SMCodedError).Code())
	})
}

func Test_SL_Present(t *testing.T) {
	common.SetLogger(hclog.L())
	providerConfig := map[string]string{dnsConfigSLUser: slUser, dnsConfigSLPassword: slPassword}

	t.Run("Happy flow ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlSlToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildSLDomainsResponse(domainIdInt, domainName, 3))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlSlToSetChallenge}: {StatusCode: http.StatusCreated, JsonBody: string(buildSLResponse())},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, "Basic "+slAuth, headers[authorizationHeader])
			},
			CheckParameters: func(method string, path string, body interface{}) {
				if method == http.MethodPost {
					actualChallengBody := SLRequest{}
					json.Unmarshal([]byte(body.(*bytes.Buffer).String()), &actualChallengBody)
					assert.DeepEqual(t, expectedChallengeBody, actualChallengBody)
				}
			}}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.Present(domainName, tokenNotInUse, keyAuth)
		assert.NilError(t, err)
		assert.Equal(t, true, reflect.DeepEqual(*slProvider.Domains[domainName], expectedDomainData))
	})

	t.Run("Domain not found ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlSLApi}: {StatusCode: http.StatusOK, JsonBody: string(buildSLDomainsResponse(-1, "", 4))},
			},
		}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.Present(subdomain, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07052, fmt.Sprintf(domainIsNotFound, subdomain, dnsProviderSoftLayerAccount))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("Authorization error when get zone by domain ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlSLApi}: {StatusCode: http.StatusForbidden, JsonBody: "{}"},
			},
		}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07044, fmt.Sprintf(authorizationError, "to get zones from", dnsProviderSoftLayerAccount))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("Authorization error when set challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlSlToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildSLDomainsResponse(domainIdInt, domainName, 3))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlSlToSetChallenge}: {StatusCode: http.StatusForbidden, JsonBody: "{}"},
			},
		}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07048, fmt.Sprintf(authorizationError, "to set txt record in", dnsProviderSoftLayerAccount))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("SL server error when get zone by domain ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlSlToGetZoneId}: {StatusCode: http.StatusServiceUnavailable, JsonBody: `{"error":"Some error message", "code":"Some Code"}`},
			},
		}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07045, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("SL server error when set challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlSlToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildSLDomainsResponse(domainIdInt, domainName, 3))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlSlToSetChallenge}: {StatusCode: http.StatusServiceUnavailable, JsonBody: `{"someOtherStructure":"Some error message"}`},
			},
		}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07049, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("SL client error when get zone by domain ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlSlToGetZoneId}: {Error: clientError},
			},
		}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07058, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("SL client error when set challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlSlToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildSLDomainsResponse(domainIdInt, domainName, 3))},
				//set challenge
				RequestKey{Method: http.MethodPost, Path: urlSlToSetChallenge}: {Error: clientError},
			},
		}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.Present(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07047, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
		assert.Equal(t, expectedMessage, err.Error())
	})

}

func Test_SL_Cleanup(t *testing.T) {
	common.SetLogger(hclog.L())

	providerConfig := map[string]string{dnsConfigSLUser: slUser, dnsConfigSLPassword: slPassword}

	t.Run("Happy flow - domain in the list", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodDelete, Path: urlSlToRemoveTxtRecord}: {StatusCode: http.StatusOK, JsonBody: `{}`},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, "Basic "+slAuth, headers[authorizationHeader])
			},
		}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		slProvider.Domains[domainName] = &expectedDomainData
		err := slProvider.CleanUp(domainName, tokenNotInUse, keyAuth)
		assert.NilError(t, err)
		assert.Equal(t, 0, len(slProvider.Domains))
	})

	t.Run("Happy flow - domain is not in the list", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodDelete, Path: urlSlToRemoveTxtRecord}: {StatusCode: http.StatusOK, JsonBody: `true`},
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlSlToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildSLDomainsResponse(domainIdInt, domainName, 3))},
				//get existing txt record
				RequestKey{Method: http.MethodGet, Path: urlSlToGetTxtRecord}: {StatusCode: http.StatusOK, JsonBody: string(buildSLDnsRecordsResponse(txtRecordIdInt, txtRecName, txtRecValue, 2))},
			},
			CheckHeaders: func(method string, path string, headers map[string]string) {
				assert.Equal(t, "Basic "+slAuth, headers[authorizationHeader])
			},
		}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.CleanUp(domainName, tokenNotInUse, keyAuth)
		assert.NilError(t, err)
		assert.Equal(t, 0, len(slProvider.Domains))
	})

	t.Run("Authorization error when get existing challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlSlToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildSLDomainsResponse(domainIdInt, domainName, 3))},
				//get existing txt record
				RequestKey{Method: http.MethodGet, Path: urlSlToGetTxtRecord}: {StatusCode: http.StatusForbidden, JsonBody: "{}"},
			},
		}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.CleanUp(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07056, fmt.Sprintf(authorizationError, "to get txt record from", dnsProviderSoftLayerAccount))
		assert.Equal(t, expectedMessage, err.Error())

	})

	t.Run("Authorization error when removing challenge", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodDelete, Path: urlSlToRemoveTxtRecord}: {StatusCode: http.StatusForbidden, JsonBody: `{}`},
			},
		}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		slProvider.Domains[domainName] = &expectedDomainData
		err := slProvider.CleanUp(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07051, fmt.Sprintf(authorizationError, "to delete txt record from", dnsProviderSoftLayerAccount))
		assert.Equal(t, expectedMessage, err.Error())

	})

	t.Run("SL server error when removing challenge", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodDelete, Path: urlSlToRemoveTxtRecord}: {StatusCode: http.StatusServiceUnavailable, JsonBody: `false`},
			},
		}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		slProvider.Domains[domainName] = &expectedDomainData
		err := slProvider.CleanUp(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07053, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("SL server error when get zone by domain  ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlSlToGetZoneId}: {StatusCode: http.StatusInternalServerError, JsonBody: `{"error":"Internal server error","code":"123456"}`},
				//get existing txt record
				RequestKey{Method: http.MethodGet, Path: urlSlToGetTxtRecord}: {StatusCode: http.StatusServiceUnavailable, JsonBody: "{}"},
			},
		}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.CleanUp(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07045, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))
		assert.Equal(t, expectedMessage, err.Error())

	})

	t.Run("SL server error when get existing challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlSlToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildSLDomainsResponse(domainIdInt, domainName, 3))},
				//get existing txt record
				RequestKey{Method: http.MethodGet, Path: urlSlToGetTxtRecord}: {StatusCode: http.StatusServiceUnavailable, JsonBody: "{}"},
			},
		}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.CleanUp(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07057, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))
		assert.Equal(t, expectedMessage, err.Error())

	})

	t.Run("SL client error when removing challenge", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodDelete, Path: urlSlToRemoveTxtRecord}: {Error: clientError},
			},
		}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		slProvider.Domains[domainName] = &expectedDomainData
		err := slProvider.CleanUp(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07050, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("SL client error when get existing challenge ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlSlToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildSLDomainsResponse(domainIdInt, domainName, 3))},
				//get existing txt record
				RequestKey{Method: http.MethodGet, Path: urlSlToGetTxtRecord}: {Error: clientError},
			},
		}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.CleanUp(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07054, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("Challenge record not found ", func(t *testing.T) {
		rc := &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				//get zone id by domain name
				RequestKey{Method: http.MethodGet, Path: urlSlToGetZoneId}: {StatusCode: http.StatusOK, JsonBody: string(buildSLDomainsResponse(domainIdInt, domainName, 3))},
				//get existing txt record
				RequestKey{Method: http.MethodGet, Path: urlSlToGetTxtRecord}: {StatusCode: http.StatusOK, JsonBody: string(buildSLDnsRecordsResponse(-1, "", "", 0))},
			},
		}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		err := slProvider.CleanUp(domainName, tokenNotInUse, keyAuth)
		expectedMessage := fmt.Sprintf(errorPattern, logdna.Error07055, internalServerError)
		assert.Equal(t, expectedMessage, err.Error())
	})

	t.Run("Timeout", func(t *testing.T) {
		rc := &RestClientFactoryMock{Results: map[RequestKey]RequestResult{}}
		slProvider := NewSoftlayerDNSProvider(providerConfig, rc)
		propagationTimeout, pollingInterval := slProvider.Timeout()
		assert.Equal(t, PropagationTimeoutSL, propagationTimeout)
		assert.Equal(t, PollingIntervalSL, pollingInterval)
	})
}

func buildSLDomainsResponse(foundId int, foundName string, resultsCount int) []byte {
	var slListResp []SLDomainResponse
	slListResp = make([]SLDomainResponse, resultsCount)
	for i, _ := range slListResp {
		slListResp[i].Id = i + 100
		slListResp[i].Name = "domain" + strconv.Itoa(i+100)
	}
	if foundId != -1 {
		slListResp[1].Name = foundName
		slListResp[1].Id = foundId
	}
	respListStr, _ := json.Marshal(slListResp)
	return respListStr
}

func buildSLDnsRecordsResponse(foundId int, foundName, foundValue string, resultsCount int) []byte {
	var slListResp []SLDnsRecordResponse
	slListResp = make([]SLDnsRecordResponse, resultsCount)
	for i, _ := range slListResp {
		slListResp[i].Id = i
		slListResp[i].Host = "domain" + strconv.Itoa(i)
		slListResp[i].Data = "challenge" + strconv.Itoa(i)
	}
	if foundId != -1 {
		slListResp[1].Id = foundId
		slListResp[1].Host = foundName
		slListResp[1].Data = foundValue
	}
	respListStr, _ := json.Marshal(slListResp)
	return respListStr
}

func buildSLResponse() []byte {
	cisResp := SLDnsRecordResponse{
		Id:   txtRecordIdInt,
		Host: "host",
	}
	respStr, _ := json.Marshal(cisResp)
	return respStr
}
