package publiccerts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-resty/resty/v2"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	commonErrors "github.ibm.com/security-services/secrets-manager-vault-plugins-common/errors"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type SLDomainData struct {
	name           string
	zoneId         int
	txtRecordName  string
	txtRecordValue string
	txtRecordId    int
}

type SoftlayerDNSConfig struct {
	User              string
	Password          string
	Auth              string
	SoftlayerEndpoint string
	IAMEndpoint       string
	TTL               int
	Domains           map[string]*SLDomainData
	restClient        rest_client.RestClientFactory
	iamToken          string
}

type SoftlayerResult struct {
	ID string `json:"id"`
}

type SoftlayerError struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

type SLlistResponse struct {
	Result []SLDomainResponse
}

type SLDomainResponse struct {
	Id         int       `json:"id"`
	Name       string    `json:"name"`
	Serial     int       `json:"serial"`
	UpdateDate time.Time `json:"updateDate"`
}
type SetDnsRecordResponse struct {
	Data         string           `json:"data"`
	DomainId     int              `json:"domainId"`
	Expire       interface{}      `json:"expire"`
	Host         string           `json:"host"`
	Id           int              `json:"id"`
	Ttl          int              `json:"ttl"`
	Type         string           `json:"type"`
	SLDomainData SLDomainResponse `json:"domain"`
}
type SoftlayerResponseResult struct {
	Success bool             `json:"success"`
	Result  SoftlayerResult  `json:"result"`
	Errors  []SoftlayerError `json:"errors,omitempty"`
}

type SLRequest struct {
	Parameters []SLDNSRecord `json:"parameters"`
}
type SLDNSRecord struct {
	Host     interface{} `json:"host"`
	Data     interface{} `json:"data"`
	Ttl      int         `json:"ttl"`
	Type     string      `json:"type"`
	DomainId interface{} `json:"domainId"`
}

func NewSoftlayerDNSProvider(providerConfig map[string]string, cf rest_client.RestClientFactory) *SoftlayerDNSConfig {
	user := providerConfig[dnsConfigSLUser]
	password := providerConfig[dnsConfigSLPassword]
	auth := user + ":" + password
	return &SoftlayerDNSConfig{
		User:              user,
		Password:          password,
		Auth:              base64.StdEncoding.EncodeToString([]byte(auth)),
		SoftlayerEndpoint: urlSLApi,
		TTL:               120, //for TXT records
		Domains:           make(map[string]*SLDomainData),
		restClient:        cf,
	}
}

// Present Implements dns provider interface
func (c *SoftlayerDNSConfig) Present(domain, token, keyAuth string) error {
	common.Logger().Info("SoftLayer Present: " + domain + " Trying to set challenge")
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
	common.Logger().Info("SoftLayer Present: " + domain + " Challenge was set successfully")
	return nil
}

// CleanUp Implements dns provider interface
func (c *SoftlayerDNSConfig) CleanUp(domain, token, keyAuth string) error {
	currentDomain, ok := c.Domains[domain]
	if !ok {
		common.Logger().Info("SoftLayer Cleanup: " + domain + " The domain doesn't exist in the list of current domains, retrieving its data in order to remove txt record")
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
	common.Logger().Info("SoftLayer Cleanup: " + domain + " Trying to remove the challenge from domain")
	err := c.removeChallenge(currentDomain)
	if err != nil {
		return err
	}
	delete(c.Domains, domain)
	common.Logger().Info("SoftLayer Cleanup:  " + domain + " The domain was successfully cleaned up")
	return nil
}

func (c *SoftlayerDNSConfig) getDomainData(originalDomain, domainToSetChallenge, keyAuth string) (*SLDomainData, error) {
	zoneId, err := c.getZoneIdByDomain(domainToSetChallenge)
	if err != nil {
		//if domain was not found in Softlayer
		if strings.Contains(err.Error(), logdna.Error07052) {
			//try to look for its parent domain
			domainParts := strings.Split(domainToSetChallenge, ".")
			if len(domainParts) == 2 {
				//we can't dive anymore, return error
				common.Logger().Error(logdna.Error07052 + " Couldn't find neither domain " + originalDomain + " nor its parent domains in " + dnsProviderSoftLayerAccount)
				return nil, buildOrderError(logdna.Error07052, fmt.Sprintf(domainIsNotFound, originalDomain, dnsProviderSoftLayerAccount))
			}
			parentDomain := strings.Join(domainParts[1:], ".")
			return c.getDomainData(originalDomain, parentDomain, keyAuth)
		}
		return nil, err
	}
	// Compute the challenge response FQDN and TXT value for the domainToSetChallenge based  on the keyAuth.
	currentDomain := &SLDomainData{name: domainToSetChallenge}
	currentDomain.zoneId = zoneId
	currentDomain.txtRecordName, currentDomain.txtRecordValue = dns01.GetRecord(originalDomain, keyAuth)
	return currentDomain, nil
}

func (c *SoftlayerDNSConfig) getZoneIdByDomain(domain string) (int, error) {
	url := fmt.Sprintf("%s/SoftLayer_Dns_Domain/getByDomainName/%s", c.SoftlayerEndpoint, url.QueryEscape(domain))
	headers := c.buildRequestHeader()
	response := make([]*SLDomainResponse, 0)
	resp, err := c.restClient.SendRequest(url, http.MethodGet, *headers, nil, &response)
	if err != nil {
		common.Logger().Error(logdna.Error07058 + " Couldn't get zone by domain name: " + err.Error())
		return -1, buildOrderError(logdna.Error07058, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
	}
	//success
	if resp.StatusCode() == http.StatusOK {
		if len(response) > 0 {
			for _, d := range response {
				if d.Name == domain {
					return d.Id, nil
				}
			}
		}
		//it can happen for subdomains
		message := fmt.Sprintf(domainIsNotFound, domain, dnsProviderSoftLayerAccount)
		common.Logger().Warn(logdna.Error07052 + " " + message + " Trying to get its parent domain.")
		return -1, buildOrderError(logdna.Error07052, message)
	} else if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error(logdna.Error07044 + " Couldn't get zone by domain name: Authorization error ")
		return -1, buildOrderError(logdna.Error07044, fmt.Sprintf(authorizationError, "to get zones from", dnsProviderSoftLayerAccount))
	}
	//softlayerError := getSoftlayerErrors(response.Errors)
	common.Logger().Error(logdna.Error07045 + " Couldn't get zone by domain " + domain + ": ") //+ softlayerError)
	return -1, buildOrderError(logdna.Error07045, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))
}

func (c *SoftlayerDNSConfig) setChallenge(domain *SLDomainData) (int, error) {
	requestBody, err := createTxtRecordBody(domain, c.TTL)
	if err != nil {
		common.Logger().Error(logdna.Error07046 + " Couldn't build txt record body: " + err.Error())
		return -1, buildOrderError(logdna.Error07046, internalServerError)
	}
	url := fmt.Sprintf(`%s/SoftLayer_Dns_Domain_ResourceRecord`, c.SoftlayerEndpoint)
	headers := c.buildRequestHeader()

	response := &SetDnsRecordResponse{}
	resp, err := c.restClient.SendRequest(url, http.MethodPost, *headers, requestBody, response)
	if err != nil {
		common.Logger().Error(logdna.Error07047 + " Couldn't set challenge for domain " + domain.name + ": " + err.Error())
		return -1, buildOrderError(logdna.Error07047, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
	}
	//success
	if resp.StatusCode() == http.StatusCreated {
		return response.Id, nil
	} else if resp.StatusCode() == http.StatusBadRequest {
		//maybe the record already exists, check it
		id, err := c.getChallengeRecordId(domain)
		if err != nil {
			return -1, err
		}
		return id, nil
	} else if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error(logdna.Error07048 + " Couldn't set txt record for domain " + domain.name + ": Authorization error ")
		return -1, buildOrderError(logdna.Error07048, fmt.Sprintf(authorizationError, "to set txt record in", dnsProviderSoftLayerAccount))
	}
	softlayerError := getSoftlayerErrors(resp)
	common.Logger().Error(logdna.Error07049 + " Couldn't set txt record for domain " + domain.name + ": " + softlayerError)
	return -1, buildOrderError(logdna.Error07049, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))
}

func (c *SoftlayerDNSConfig) removeChallenge(domain *SLDomainData) error {
	////todo if domain.cisTxtRecordId is nil, try to get it
	url := fmt.Sprintf(`%s/SoftLayer_Dns_Domain_ResourceRecord/%d`, c.SoftlayerEndpoint, domain.txtRecordId)
	headers := c.buildRequestHeader()

	resp, err := c.restClient.SendRequest(url, http.MethodDelete, *headers, nil, nil)
	if err != nil {
		common.Logger().Error(logdna.Error07050 + " Couldn't remove txt record for domain " + domain.name + ": " + err.Error())
		return buildOrderError(logdna.Error07050, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
	}
	//success
	if resp.StatusCode() == http.StatusOK {
		return nil
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error(logdna.Error07051 + " Couldn't remove txt record for domain " + domain.name + ": Authorization error ")
		return buildOrderError(logdna.Error07051, fmt.Sprintf(authorizationError, "to delete txt record from", dnsProviderSoftLayerAccount))
	}
	softlayerError := getSoftlayerErrors(resp)
	common.Logger().Error(logdna.Error07053 + " Couldn't remove txt record for domain " + domain.name + ": " + softlayerError)
	return buildOrderError(logdna.Error07053, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))

}

func (c *SoftlayerDNSConfig) getChallengeRecordId(domain *SLDomainData) (int, error) {
	url := fmt.Sprintf(`%s/SoftLayer_Dns_Domain/%d/getResourceRecords?objectFilter={"resourceRecords":{"host":{"operation": "%s"},"data":{"operation": "%s"}}}`,
		c.SoftlayerEndpoint, domain.zoneId, url.QueryEscape(domain.txtRecordName), url.QueryEscape(domain.txtRecordValue))
	headers := c.buildRequestHeader()

	response := &SLlistResponse{}
	resp, err := c.restClient.SendRequest(url, http.MethodGet, *headers, nil, nil)
	if err != nil {
		common.Logger().Error(logdna.Error07054 + " Couldn't get txt record for domain " + domain.name + ": " + err.Error())
		return -1, buildOrderError(logdna.Error07054, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
	}
	if resp.StatusCode() == http.StatusOK {
		if len(response.Result) > 0 {
			return response.Result[0].Id, nil
		}
		common.Logger().Error(logdna.Error07055 + " TXT record " + domain.txtRecordName + " is not found in the IBM Cloud Internet Services instance")
		return -1, buildOrderError(logdna.Error07055, internalServerError)
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error(logdna.Error07056 + " Couldn't get txt record for domain " + domain.name + ": Authorization error ")
		return -1, buildOrderError(logdna.Error07056, fmt.Sprintf(authorizationError, "to get txt record from", dnsProviderSoftLayerAccount))
	}
	softlayerError := getSoftlayerErrors(resp)
	common.Logger().Error(logdna.Error07057 + " Couldn't get txt record for domain " + domain.name + ": " + softlayerError)
	return -1, buildOrderError(logdna.Error07057, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))
}

func (c *SoftlayerDNSConfig) buildRequestHeader() *map[string]string {
	headers := make(map[string]string)
	headers[authorizationHeader] = "Basic " + c.Auth
	headers[contentTypeHeader] = applicationJson
	headers[acceptHeader] = applicationJson
	return &headers
}

//this func is called synchronous, so errors will be a part of response
func (c *SoftlayerDNSConfig) validateConfig() error {
	//try to get domains
	url := fmt.Sprintf("%s/SoftLayer_Dns_Domain/getByDomainName/domain.com", c.SoftlayerEndpoint)
	headers := c.buildRequestHeader()
	resp, err := c.restClient.SendRequest(url, http.MethodGet, *headers, nil, nil)
	if err != nil {
		message := fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer)
		common.ErrorLogForCustomer("Couldn't access SoftLayer: "+err.Error(), logdna.Error07036, logdna.BadRequestErrorMessage, true)
		return commonErrors.GenerateCodedError(logdna.Error07036, http.StatusBadRequest, message)
	}
	//success
	if resp.StatusCode() == http.StatusOK {
		common.Logger().Info("Validation succeeded. User " + c.User + " has an access to Softalyer")
		return nil
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		message := fmt.Sprintf(authorizationError, "to access", dnsProviderSoftLayerAccount)
		common.ErrorLogForCustomer(message, logdna.Error07037, logdna.BadRequestErrorMessage, true)
		return commonErrors.GenerateCodedError(logdna.Error07037, http.StatusBadRequest, message)
	}
	softlayerError := getSoftlayerErrors(resp)
	message := fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer)
	common.ErrorLogForCustomer("Couldn't access SoftLayer: "+softlayerError, logdna.Error07038, logdna.BadRequestErrorMessage, true)
	return commonErrors.GenerateCodedError(logdna.Error07038, http.StatusBadRequest, message)
}

func createTxtRecordBody(domain *SLDomainData, ttl int) (*bytes.Buffer, error) {
	postBody := &SLRequest{
		Parameters: []SLDNSRecord{{
			Host:     domain.txtRecordName,
			Data:     domain.txtRecordValue,
			Ttl:      ttl,
			Type:     "txt",
			DomainId: domain.zoneId,
		}}}
	marshalledPostBody, err := json.Marshal(postBody)
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(marshalledPostBody), nil
}

func getSoftlayerErrors(resp *resty.Response) string {
	var result string
	slError := &SoftlayerError{}
	err := json.Unmarshal(resp.Body(), slError)
	if err != nil {
		result = "Softlayer response: " + string(resp.Body())
	} else {
		result = "Softlayer error/s: " + slError.Code + slError.Error
	}
	return result
}

func validateSoftLayerStructure(config map[string]string) error {
	if user, ok := config[dnsConfigSLUser]; !ok || len(strings.TrimSpace(user)) == 0 {
		message := fmt.Sprintf(configMissingField, providerTypeDNS, dnsConfigSLUser)
		common.ErrorLogForCustomer(message, logdna.Error07033, logdna.BadRequestErrorMessage, true)
		return commonErrors.GenerateCodedError(logdna.Error07033, http.StatusBadRequest, message)
	}
	if password, ok := config[dnsConfigSLPassword]; !ok || len(strings.TrimSpace(password)) == 0 {
		message := fmt.Sprintf(configMissingField, providerTypeDNS, dnsConfigSLPassword)
		common.ErrorLogForCustomer(message, logdna.Error07034, logdna.BadRequestErrorMessage, true)
		return commonErrors.GenerateCodedError(logdna.Error07034, http.StatusBadRequest, message)
	}
	for k, _ := range config {
		if k != dnsConfigSLUser && k != dnsConfigSLPassword {
			message := fmt.Sprintf(invalidConfigStruct, providerTypeDNS, dnsConfigTypeCIS, "["+dnsConfigSLUser+","+dnsConfigSLPassword+"]")
			common.ErrorLogForCustomer(message, logdna.Error07035, logdna.BadRequestErrorMessage, true)
			return commonErrors.GenerateCodedError(logdna.Error07035, http.StatusBadRequest, message)
		}
	}
	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (c *SoftlayerDNSConfig) Timeout() (timeout, interval time.Duration) {
	return PropagationTimeout, PollingInterval
}
