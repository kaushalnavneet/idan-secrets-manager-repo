package publiccerts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client"
	"github.ibm.com/security-services/secrets-manager-iam/pkg/crn"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	commonErrors "github.ibm.com/security-services/secrets-manager-vault-plugins-common/errors"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/vault_cliient_impl"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type CISDNSConfig struct {
	CRN           string
	CISEndpoint   string
	IAMEndpoint   string
	APIKey        string
	TTL           int
	Domains       map[string]*CISDomainData
	restClient    rest_client.RestClientFactory
	smInstanceCrn string
	iamToken      string
	authUtils     common.AuthUtils
}

type CISDomainData struct {
	name           string
	zoneId         string
	txtRecordName  string
	txtRecordValue string
	txtRecordId    string
}

type CISResult struct {
	ID string `json:"id"`
}

type CISResponseList struct {
	Success bool        `json:"success"`
	Result  []CISResult `json:"result"`
	Errors  interface{} `json:"errors,omitempty"`
}

type CISResponseResult struct {
	Success bool        `json:"success"`
	Result  CISResult   `json:"result"`
	Errors  interface{} `json:"errors,omitempty"`
}

type CISRequest struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Type    string `json:"type"`
	TTL     int    `json:"ttl"`
}

func NewCISDNSProvider(providerConfig map[string]string, cf rest_client.RestClientFactory, auth common.AuthUtils) *CISDNSConfig {
	cisCrn := providerConfig[dnsConfigCisCrn]
	apikey := providerConfig[dnsConfigCisApikey]
	smInstanceCrn := providerConfig[dnsConfigSMCrn]

	if auth == nil { //it's always nil except tests
		auth = &common.AuthUtilsImpl{Client: &vault_cliient_impl.VaultClientFactory{Logger: common.Logger()}}
	}

	var cisURL, iamURL string
	if strings.Contains(cisCrn, "staging") {
		if strings.Contains(cisCrn, serviceCISint) {
			cisURL = urlCISIntegration
		} else {
			cisURL = urlCISStage
		}
		iamURL = urlIamStage
	} else {
		cisURL = urlCISProd
		iamURL = urlIamProd
	}
	return &CISDNSConfig{
		CRN:           cisCrn,
		CISEndpoint:   cisURL,
		IAMEndpoint:   iamURL,
		APIKey:        apikey,
		TTL:           120, //for TXT records
		Domains:       make(map[string]*CISDomainData),
		restClient:    cf,
		smInstanceCrn: smInstanceCrn,
		authUtils:     auth,
	}
}

// Present Implements dns provider interface
func (c *CISDNSConfig) Present(domain, token, keyAuth string) error {
	common.Logger().Info("CIS Present: " + domain + " Trying to set the challenge")
	currentDomain, err := c.getDomainData(domain, domain, keyAuth)
	if err != nil {
		return err
	}
	recordId, err := c.setChallenge(currentDomain)
	if err != nil {
		return err
	}
	currentDomain.txtRecordId = recordId
	c.Domains[domain] = currentDomain
	common.Logger().Info("CIS Present: " + domain + " Challenge was set successfully")
	return nil
}

// CleanUp Implements dns provider interface
func (c *CISDNSConfig) CleanUp(domain, token, keyAuth string) error {
	currentDomain, ok := c.Domains[domain]
	if !ok {
		common.Logger().Info("CIS Cleanup: " + domain + " The domain doesn't exist in the list of current domains, retrieving its data in order to remove txt record")
		var err error
		currentDomain, err = c.getDomainData(domain, domain, keyAuth)
		if err != nil {
			return err
		}
		recordId, err := c.getChallengeRecordId(currentDomain)
		if err != nil {
			return err
		}
		currentDomain.txtRecordId = recordId
	}
	common.Logger().Info("CIS Cleanup: " + domain + " Trying to remove the challenge from domain")
	err := c.removeChallenge(currentDomain)
	if err != nil {
		return err
	}
	delete(c.Domains, domain)
	common.Logger().Info("CIS Cleanup:  " + domain + " The domain was successfully cleaned up")
	return nil
}

func (c *CISDNSConfig) getDomainData(originalDomain, domainToSetChallenge, keyAuth string) (*CISDomainData, error) {
	zoneId, err := c.getZoneIdByDomain(domainToSetChallenge)
	if err != nil {
		//if domain was not found in CIS
		if strings.Contains(err.Error(), logdna.Error07072) {
			//try to look for its parent domain
			domainParts := strings.Split(domainToSetChallenge, ".")
			if len(domainParts) == 2 {
				//we can't dive anymore, return error
				message := fmt.Sprintf(domainIsNotFound, originalDomain, dnsProviderCISInstance)
				common.Logger().Error(logdna.Error07072 + " Couldn't find neither domain " + originalDomain + "  nor its parent domains in " + dnsProviderCISInstance)
				return nil, buildOrderError(logdna.Error07072, message)
			}
			parentDomain := strings.Join(domainParts[1:], ".")
			return c.getDomainData(originalDomain, parentDomain, keyAuth)
		}
		return nil, err
	}
	// Compute the challenge response FQDN and TXT value for the domainToSetChallenge based  on the keyAuth.
	currentDomain := &CISDomainData{name: domainToSetChallenge}
	currentDomain.zoneId = zoneId
	currentDomain.txtRecordName, currentDomain.txtRecordValue = dns01.GetRecord(originalDomain, keyAuth)
	return currentDomain, nil
}

func (c *CISDNSConfig) getZoneIdByDomain(domain string) (string, error) {
	reqUrl := fmt.Sprintf(`%s/%s/zones?name=%s&status=active`, c.CISEndpoint, url.QueryEscape(c.CRN), domain)
	headers, err := c.buildRequestHeader()
	if err != nil {
		common.Logger().Error(logdna.Error07070 + " Couldn't build headers for CIS request: " + err.Error())
		return "", buildOrderError(logdna.Error07070, err.Error())
	}
	response := &CISResponseList{}
	resp, err := c.restClient.SendRequest(reqUrl, http.MethodGet, *headers, nil, response)
	if err != nil {
		common.Logger().Error(logdna.Error07071 + " Couldn't get zone by domain name: " + err.Error())
		return "", buildOrderError(logdna.Error07071, fmt.Sprintf(unavailableDNSError, dnsProviderCIS))
	}
	//success
	if resp.StatusCode() == http.StatusOK && response.Success && response.Result != nil {
		if len(response.Result) > 0 {
			return response.Result[0].ID, nil
		} else {
			//it can happen for subdomains
			message := fmt.Sprintf(domainIsNotFound, domain, dnsProviderCISInstance)
			common.Logger().Warn(logdna.Error07072 + " " + message + " Trying to get its parent domain")
			return "", buildOrderError(logdna.Error07072, message)
		}
	} else if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error(logdna.Error07073 + "Couldn't get zone by domain name: Authorization error ")
		return "", buildOrderError(logdna.Error07073, fmt.Sprintf(authorizationError, "to get zones from", dnsProviderCISInstance))
	}
	common.Logger().Error(logdna.Error07074 + fmt.Sprintf(" Couldn't get zone by domain %s. statusCode=%d, errors='%+v'", domain, resp.StatusCode(), response.Errors))
	return "", buildOrderError(logdna.Error07074, fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS))

}

func (c *CISDNSConfig) setChallenge(domain *CISDomainData) (string, error) {
	requestBody, err := createCISTxtRecordBody(domain.txtRecordName, domain.txtRecordValue, c.TTL)
	if err != nil {
		common.Logger().Error(logdna.Error07075 + " Couldn't build txt record body: " + err.Error())
		return "", buildOrderError(logdna.Error07075, internalServerError)
	}

	reqUrl := fmt.Sprintf(`%s/%s/zones/%s/dns_records`, c.CISEndpoint, url.QueryEscape(c.CRN), url.QueryEscape(domain.zoneId))
	headers, err := c.buildRequestHeader()
	if err != nil {
		common.Logger().Error(logdna.Error07082 + " Couldn't build headers for CIS request: " + err.Error())
		return "", buildOrderError(logdna.Error07082, err.Error())
	}
	response := &CISResponseResult{}
	resp, err := c.restClient.SendRequest(reqUrl, http.MethodPost, *headers, requestBody, response)
	if err != nil {
		common.Logger().Error(logdna.Error07076 + " Couldn't set challenge for domain " + domain.name + ": " + err.Error())
		return "", buildOrderError(logdna.Error07076, fmt.Sprintf(unavailableDNSError, dnsProviderCIS))
	}
	//success
	if resp.StatusCode() == http.StatusOK && response.Success {
		return response.Result.ID, nil
	} else if resp.StatusCode() == http.StatusBadRequest {
		//maybe the record already exists, check it
		id, err := c.getChallengeRecordId(domain)
		if err != nil {
			return "", err
		}
		return id, nil
	} else if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error(logdna.Error07077 + " Couldn't set txt record for domain " + domain.name + ": Authorization error ")
		return "", buildOrderError(logdna.Error07077, fmt.Sprintf(authorizationError, "to set txt record in", dnsProviderCISInstance))
	}
	common.Logger().Error(logdna.Error07078 + fmt.Sprintf(" Couldn't set txt record for domain %s. statusCode=%d, errors='%+v'",
		domain.name, resp.StatusCode(), response.Errors))
	return "", buildOrderError(logdna.Error07078, fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS))
}

func (c *CISDNSConfig) removeChallenge(domain *CISDomainData) error {
	reqUrl := fmt.Sprintf(`%s/%s/zones/%s/dns_records/%s`, c.CISEndpoint, url.QueryEscape(c.CRN), url.QueryEscape(domain.zoneId), url.QueryEscape(domain.txtRecordId))
	headers, err := c.buildRequestHeader()
	if err != nil {
		common.Logger().Error(logdna.Error07084 + "Couldn't build headers for CIS request: " + err.Error())
		return buildOrderError(logdna.Error07084, err.Error())
	}
	response := &CISResponseResult{}
	resp, err := c.restClient.SendRequest(reqUrl, http.MethodDelete, *headers, nil, response)
	if err != nil {
		common.Logger().Error(logdna.Error07079 + "Couldn't remove txt record for domain " + domain.name + ": " + err.Error())
		return buildOrderError(logdna.Error07079, fmt.Sprintf(unavailableDNSError, dnsProviderCIS))
	}
	//success
	if resp.StatusCode() == http.StatusOK && response.Success {
		return nil
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error(logdna.Error07080 + " Couldn't remove txt record for domain " + domain.name + ": Authorization error ")
		return buildOrderError(logdna.Error07080, fmt.Sprintf(authorizationError, "to delete txt record from", dnsProviderCISInstance))
	}
	common.Logger().Error(logdna.Error07081 + fmt.Sprintf(" Couldn't remove txt record for domain %s. statusCode=%d, errors='%+v'", domain.name, resp.StatusCode(), response.Errors))
	return buildOrderError(logdna.Error07081, fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS))
}

func (c *CISDNSConfig) getChallengeRecordId(domain *CISDomainData) (string, error) {
	reqUrl := fmt.Sprintf(`%s/%s/zones/%s/dns_records?type=TXT&name=%s&content=%s`, c.CISEndpoint, url.QueryEscape(c.CRN),
		url.QueryEscape(domain.zoneId), url.QueryEscape(domain.txtRecordName), url.QueryEscape(domain.txtRecordValue))
	headers, err := c.buildRequestHeader()
	if err != nil {
		common.Logger().Error(logdna.Error07086 + " Couldn't build headers for CIS request: " + err.Error())
		return "", buildOrderError(logdna.Error07086, err.Error())
	}
	response := &CISResponseList{}
	resp, err := c.restClient.SendRequest(reqUrl, http.MethodGet, *headers, nil, response)
	if err != nil {
		common.Logger().Error(logdna.Error07087 + " Couldn't get txt record for domain " + domain.name + ": " + err.Error())
		return "", buildOrderError(logdna.Error07087, fmt.Sprintf(unavailableDNSError, dnsProviderCIS))
	}
	if resp.StatusCode() == http.StatusOK && response.Success && response.Result != nil {
		if len(response.Result) > 0 {
			return response.Result[0].ID, nil
		}
		common.Logger().Error(logdna.Error07088 + " TXT record " + domain.txtRecordName + " is not found in the IBM Cloud Internet Services instance")
		return "", buildOrderError(logdna.Error07088, internalServerError)
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error(logdna.Error07089 + " Couldn't remove get record for domain " + domain.name + ": Authorization error ")
		return "", buildOrderError(logdna.Error07089, fmt.Sprintf(authorizationError, "to get txt record from", dnsProviderCISInstance))
	}
	common.Logger().Error(logdna.Error07060 + fmt.Sprintf(" Couldn't get txt record for domain %s: statusCode=%d, errors='%+v'", domain.name, resp.StatusCode(), response.Errors))
	return "", buildOrderError(logdna.Error07060, fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS))
}

func (c *CISDNSConfig) buildRequestHeader() (*map[string]string, error) {
	headers := make(map[string]string)
	var iamToken, msg string
	var err error
	common.Logger().Info("Obtaining IAM token for CIS access.")
	if c.APIKey != "" {
		iamToken, _, err = c.authUtils.ObtainCachedToken(c.IAMEndpoint, c.APIKey, "", "", "")
		msg = obtainTokenError
	} else {
		iamToken, _, err = c.authUtils.ObtainCachedCrnToken(c.IAMEndpoint, c.smInstanceCrn, "")
		msg = obtainCRNTokenError
	}
	if err != nil {
		msg = msg + err.Error()
		common.Logger().Error(msg)
		return &headers, errors.New(msg)
	}
	headers["x-auth-user-token"] = iamToken
	headers[contentTypeHeader] = applicationJson
	return &headers, nil
}

//this func is called synchronous, so errors will be a part of response
func (c *CISDNSConfig) validateConfig() error {
	//try to get domains
	reqUrl := fmt.Sprintf(`%s/%s/zones?per_page=5`, c.CISEndpoint, url.QueryEscape(c.CRN))
	headers, err := c.buildRequestHeader()
	if err != nil {
		message := err.Error()
		common.ErrorLogForCustomer(message, logdna.Error07029, logdna.BadRequestErrorMessage, true)
		return commonErrors.GenerateCodedError(logdna.Error07029, http.StatusBadRequest, message)
	}
	response := &CISResponseList{}
	resp, err := c.restClient.SendRequest(reqUrl, http.MethodGet, *headers, nil, response)
	if err != nil {
		common.ErrorLogForCustomer("Couldn't access CIS instance: "+err.Error(), logdna.Error07030, logdna.BadRequestErrorMessage, true)
		message := fmt.Sprintf(unavailableDNSError, dnsProviderCIS)
		return commonErrors.GenerateCodedError(logdna.Error07030, http.StatusBadRequest, message)
	}
	//success
	if resp.StatusCode() == http.StatusOK {
		common.Logger().Info("Validation succeeded. CIS instance " + c.CRN + " can be accessed with provided credentials")
		return nil
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		message := fmt.Sprintf(authorizationError, "to access", dnsProviderCISInstance)
		common.ErrorLogForCustomer(message, logdna.Error07031, logdna.BadRequestErrorMessage, true)
		return commonErrors.GenerateCodedError(logdna.Error07031, http.StatusBadRequest, message)
	}
	common.ErrorLogForCustomer(logdna.Error07032+fmt.Sprintf(" Couldn't access CIS instance: statusCode=%d, errors='%+v'", resp.StatusCode(), response.Errors), logdna.Error07032, logdna.BadRequestErrorMessage, true)
	message := fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS)
	return commonErrors.GenerateCodedError(logdna.Error07032, http.StatusBadRequest, message)
}

func createCISTxtRecordBody(key, value string, ttl int) (*bytes.Buffer, error) {
	postBody := CISRequest{
		Name:    key,
		Content: value,
		Type:    "TXT",
		TTL:     ttl,
	}
	marshalledPostBody, err := json.Marshal(postBody)
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(marshalledPostBody), nil
}

func validateCISConfigStructure(config map[string]string, smInstanceCrn string) error {
	if crnValue, ok := config[dnsConfigCisCrn]; !ok {
		message := fmt.Sprintf(configMissingField, providerTypeDNS, dnsConfigCisCrn)
		common.ErrorLogForCustomer(message, logdna.Error07025, logdna.BadRequestErrorMessage, true)
		return commonErrors.GenerateCodedError(logdna.Error07025, http.StatusBadRequest, message)
	} else if validCrn, err := crn.ToCRN(crnValue); err != nil {
		common.ErrorLogForCustomer(invalidCISInstanceCrn, logdna.Error07026, logdna.BadRequestErrorMessage, true)
		return commonErrors.GenerateCodedError(logdna.Error07026, http.StatusBadRequest, invalidCISInstanceCrn)
	} else if validCrn.ServiceName != serviceCISint && validCrn.ServiceName != serviceCIS {
		common.ErrorLogForCustomer(invalidCISInstanceCrn, logdna.Error07027, logdna.BadRequestErrorMessage, true)
		return commonErrors.GenerateCodedError(logdna.Error07027, http.StatusBadRequest, invalidCISInstanceCrn)
	}
	for k := range config {
		if k != dnsConfigCisCrn && k != dnsConfigCisApikey {
			message := fmt.Sprintf(invalidConfigStruct, providerTypeDNS, dnsConfigTypeCIS, "["+dnsConfigCisCrn+","+dnsConfigCisApikey+"]")
			common.ErrorLogForCustomer(message, logdna.Error07028, logdna.BadRequestErrorMessage, true)
			return commonErrors.GenerateCodedError(logdna.Error07028, http.StatusBadRequest, message)
		}
	}
	//if cis api key was not provided, add sm crn for s2s tokens
	if _, ok := config[dnsConfigCisApikey]; !ok {
		config[dnsConfigSMCrn] = smInstanceCrn
	}
	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (c *CISDNSConfig) Timeout() (timeout, interval time.Duration) {
	return PropagationTimeout, PollingInterval
}
