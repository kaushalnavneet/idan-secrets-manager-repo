package publiccerts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client_impl"
	"github.ibm.com/security-services/secrets-manager-iam/pkg/crn"
	"github.ibm.com/security-services/secrets-manager-iam/pkg/iam"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"net/http"
	"net/url"
	"strconv"
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

type CISError struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

type CISResponseList struct {
	Success bool        `json:"success"`
	Result  []CISResult `json:"result"`
	Errors  []CISError  `json:"errors,omitempty"`
}

type CISResponseResult struct {
	Success bool       `json:"success"`
	Result  CISResult  `json:"result"`
	Errors  []CISError `json:"errors,omitempty"`
}

type CISRequest struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Type    string `json:"type"`
	TTL     int    `json:"ttl"`
}

func NewCISDNSProvider(providerConfig map[string]string) *CISDNSConfig {
	cisCrn := providerConfig[dnsConfigCisCrn]
	apikey := providerConfig[dnsConfigCisApikey]
	smInstanceCrn := providerConfig[dnsConfigSMCrn]

	//create resty client
	cf := &rest_client_impl.RestClientFactory{}
	//init resty client with not default options
	cf.InitClientWithOptions(rest_client.RestClientOptions{
		Timeout:    10 * time.Second,
		Retries:    2,
		RetryDelay: 1 * time.Second,
	})
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
		common.Logger().Info("CIS Cleanup: " + domain + " The domain is not updated in the list of current domains, retrieving its data in order to remove txt record")
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
				common.Logger().Error(message)
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
		common.Logger().Error("Couldn't build headers for CIS request: " + err.Error())
		return "", buildOrderError(logdna.Error07070, obtainTokenError)
	}
	response := &CISResponseList{}
	resp, err := c.restClient.SendRequest(reqUrl, http.MethodGet, *headers, nil, response)
	if err != nil {
		common.Logger().Error("Couldn't get zone by domain name: " + err.Error())
		return "", buildOrderError(logdna.Error07071, fmt.Sprintf(unavailableDNSError, dnsProviderCIS))
	}
	//success
	if resp.StatusCode() == http.StatusOK && response.Success && response.Result != nil {
		if len(response.Result) > 0 {
			return response.Result[0].ID, nil
		} else {
			//it can happen for subdomains
			message := fmt.Sprintf(domainIsNotFound, domain, dnsProviderCISInstance)
			common.Logger().Warn(message + " We will try to find its parent if it's possible")
			return "", buildOrderError(logdna.Error07072, message)
		}
	} else if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error("Couldn't get zone by domain name: Authorization error ")
		return "", buildOrderError(logdna.Error07073, fmt.Sprintf(authorizationError, "to get zones from", dnsProviderCISInstance))
	}
	cisError := getCISErrors(response.Errors)
	common.Logger().Error("Couldn't get zone by domain " + domain + ": " + cisError)
	return "", buildOrderError(logdna.Error07074, fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS))

}

func (c *CISDNSConfig) setChallenge(domain *CISDomainData) (string, error) {
	requestBody, err := createCISTxtRecordBody(domain.txtRecordName, domain.txtRecordValue, c.TTL)
	if err != nil {
		common.Logger().Error("Couldn't build txt record body: " + err.Error())
		return "", buildOrderError(logdna.Error07075, internalServerError)
	}

	reqUrl := fmt.Sprintf(`%s/%s/zones/%s/dns_records`, c.CISEndpoint, url.QueryEscape(c.CRN), url.QueryEscape(domain.zoneId))
	headers, err := c.buildRequestHeader()
	if err != nil {
		common.Logger().Error("Couldn't build headers for CIS request: " + err.Error())
		return "", buildOrderError(logdna.Error07082, obtainTokenError)
	}
	response := &CISResponseResult{}
	resp, err := c.restClient.SendRequest(reqUrl, http.MethodPost, *headers, requestBody, response)
	if err != nil {
		common.Logger().Error("Couldn't set challenge for domain " + domain.name + ": " + err.Error())
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
		common.Logger().Error("Couldn't set txt record for domain " + domain.name + ": Authorization error ")
		return "", buildOrderError(logdna.Error07077, fmt.Sprintf(authorizationError, "to set txt record in", dnsProviderCISInstance))
	}
	cisError := getCISErrors(response.Errors)
	common.Logger().Error("Couldn't set txt record for domain " + domain.name + ": " + cisError)
	return "", buildOrderError(logdna.Error07078, fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS))
}

func (c *CISDNSConfig) removeChallenge(domain *CISDomainData) error {
	reqUrl := fmt.Sprintf(`%s/%s/zones/%s/dns_records/%s`, c.CISEndpoint, url.QueryEscape(c.CRN), url.QueryEscape(domain.zoneId), url.QueryEscape(domain.txtRecordId))
	headers, err := c.buildRequestHeader()
	if err != nil {
		common.Logger().Error("Couldn't build headers for CIS request: " + err.Error())
		return buildOrderError(logdna.Error07084, obtainTokenError)
	}
	response := &CISResponseResult{}
	resp, err := c.restClient.SendRequest(reqUrl, http.MethodDelete, *headers, nil, response)
	if err != nil {
		common.Logger().Error("Couldn't remove txt record for domain " + domain.name + ": " + err.Error())
		return buildOrderError(logdna.Error07079, fmt.Sprintf(unavailableDNSError, dnsProviderCIS))
	}
	//success
	if resp.StatusCode() == http.StatusOK && response.Success {
		return nil
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error("Couldn't remove txt record for domain " + domain.name + ": Authorization error ")
		return buildOrderError(logdna.Error07080, fmt.Sprintf(authorizationError, "to delete txt record from", dnsProviderCISInstance))
	}
	cisError := getCISErrors(response.Errors)
	common.Logger().Error("Couldn't remove txt record for domain " + domain.name + ": " + cisError)
	return buildOrderError(logdna.Error07081, fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS))
}

func (c *CISDNSConfig) getChallengeRecordId(domain *CISDomainData) (string, error) {
	reqUrl := fmt.Sprintf(`%s/%s/zones/%s/dns_records?type=TXT&name=%s&content=%s`, c.CISEndpoint, url.QueryEscape(c.CRN),
		url.QueryEscape(domain.zoneId), url.QueryEscape(domain.txtRecordName), url.QueryEscape(domain.txtRecordValue))
	headers, err := c.buildRequestHeader()
	if err != nil {
		common.Logger().Error("Couldn't build headers for CIS request: " + err.Error())
		return "", buildOrderError(logdna.Error07086, obtainTokenError)
	}
	response := &CISResponseList{}
	resp, err := c.restClient.SendRequest(reqUrl, http.MethodGet, *headers, nil, response)
	if err != nil {
		common.Logger().Error("Couldn't get txt record for domain " + domain.name + ": " + err.Error())
		return "", buildOrderError(logdna.Error07101, fmt.Sprintf(unavailableDNSError, dnsProviderCIS))
	}
	if resp.StatusCode() == http.StatusOK && response.Success && response.Result != nil {
		if len(response.Result) > 0 {
			return response.Result[0].ID, nil
		}
		common.Logger().Error("TXT record " + domain.txtRecordName + " is not found in the IBM Cloud Internet Services instance")
		return "", buildOrderError(logdna.Error07102, internalServerError)
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		return "", buildOrderError(logdna.Error07103, fmt.Sprintf(authorizationError, "to get txt record from", dnsProviderCISInstance))
	}
	cisError := getCISErrors(response.Errors)
	common.Logger().Error("Couldn't get txt record for domain " + domain.name + ": " + cisError)
	return "", buildOrderError(logdna.Error07104, fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS))
}

func (c *CISDNSConfig) buildRequestHeader() (*map[string]string, error) {
	headers := make(map[string]string)
	if c.iamToken != "" {
		if _, err := iam.GetClaims(c.iamToken); err != nil {
			common.Logger().Info("Cached IAM token for CIS access is not valid.")
			c.iamToken = ""
		}
	}
	if c.iamToken == "" {
		var iamToken, msg string
		var err error
		common.Logger().Info("Obtaining IAM token for CIS access.")
		if c.APIKey != "" {
			iamToken, _, err = iam.ObtainCachedToken(c.IAMEndpoint, c.APIKey, "", "", "")
			msg = obtainTokenError
		} else {
			iamToken, _, err = iam.ObtainCrnToken(c.IAMEndpoint, c.smInstanceCrn)
			msg = obtainCRNTokenError
		}
		if err != nil {
			msg = msg + err.Error()
			common.Logger().Error(msg)
			return &headers, errors.New(msg)
		}
		c.iamToken = iamToken
	}
	headers["x-auth-user-token"] = c.iamToken
	headers["Content-Type"] = "application/json"
	return &headers, nil
}

//this func is called synchronous, so errors will be a part of response
func (c *CISDNSConfig) validateConfig() error {
	//try to get domains
	reqUrl := fmt.Sprintf(`%s/%s/zones?per_page=5`, c.CISEndpoint, url.QueryEscape(c.CRN))
	headers, err := c.buildRequestHeader()
	if err != nil {
		common.Logger().Error("Couldn't build headers for CIS request: " + err.Error())
		return err
	}
	response := &CISResponseList{}
	resp, err := c.restClient.SendRequest(reqUrl, http.MethodGet, *headers, nil, response)
	if err != nil {
		common.Logger().Error("Couldn't access CIS instance: " + err.Error())
		message := fmt.Sprintf(unavailableDNSError, dnsProviderCIS)
		return errors.New(message)
	}
	//success
	if resp.StatusCode() == http.StatusOK {
		return nil
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error("Couldn't access CIS instance:  Authorization error ")
		message := fmt.Sprintf(authorizationError, "to access", dnsProviderCISInstance)
		return errors.New(message)
	}
	cisError := getCISErrors(response.Errors)
	common.Logger().Error("Couldn't access CIS instance: " + cisError)
	message := fmt.Sprintf(errorResponseFromDNS, dnsProviderCIS)
	return errors.New(message)
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

func getCISErrors(errors []CISError) string {
	result := "CIS error/s: "
	for i, cisError := range errors {
		result += strconv.Itoa(i) + ". Code:" + strconv.Itoa(cisError.Code) + " Message:" + cisError.Message + ". "
	}
	return result
}

func validateCISConfigStructure(config map[string]string, smInstanceCrn string) error {
	if crnValue, ok := config[dnsConfigCisCrn]; !ok {
		message := fmt.Sprintf(configMissingField, providerTypeDNS, dnsConfigCisCrn)
		return errors.New(message)
	} else if validCrn, err := crn.ToCRN(crnValue); err != nil {
		return errors.New(invalidCISInstanceCrn)
	} else if validCrn.ServiceName != serviceCISint && validCrn.ServiceName != serviceCIS {
		return errors.New(invalidCISInstanceCrn)
	}
	for k := range config {
		if k != dnsConfigCisCrn && k != dnsConfigCisApikey {
			message := fmt.Sprintf(invalidConfigStruct, providerTypeDNS, dnsConfigTypeCIS, "["+dnsConfigCisCrn+","+dnsConfigCisApikey+"]")
			return errors.New(message)
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
