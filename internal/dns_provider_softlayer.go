package publiccerts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-resty/resty/v2"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client_impl"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type SLDomainData struct {
	name           string
	domainId       int
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

func NewSoftlayerDNSProvider(providerConfig map[string]string) *SoftlayerDNSConfig {
	user := providerConfig[dnsConfigSLUser]
	password := providerConfig[dnsConfigSLPassword]
	auth := user + ":" + password

	//create resty client
	cf := &rest_client_impl.RestClientFactory{}
	//init resty client with not default options
	cf.InitClientWithOptions(rest_client.RestClientOptions{
		Timeout:    10 * time.Second,
		Retries:    2,
		RetryDelay: 1 * time.Second,
	})

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
		common.Logger().Info("SoftLayer Cleanup: " + domain + " The domain is not updated in the list of current domains, retrieving its data in order to remove txt record")
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
		if strings.Contains(err.Error(), logdna.Error07072) {
			//try to look for its parent domain
			domainParts := strings.Split(domainToSetChallenge, ".")
			if len(domainParts) == 2 {
				//we can't dive anymore, return error
				return nil, buildOrderError(logdna.Error07072, fmt.Sprintf(domainIsNotFound, originalDomain, dnsProviderSoftLayerAccount))
			}
			parentDomain := strings.Join(domainParts[1:], ".")
			return c.getDomainData(originalDomain, parentDomain, keyAuth)
		}
		return nil, err
	}
	// Compute the challenge response FQDN and TXT value for the domainToSetChallenge based  on the keyAuth.
	currentDomain := &SLDomainData{name: domainToSetChallenge}
	currentDomain.domainId = zoneId
	currentDomain.txtRecordName, currentDomain.txtRecordValue = dns01.GetRecord(originalDomain, keyAuth)
	return currentDomain, nil
}

func (c *SoftlayerDNSConfig) getZoneIdByDomain(domain string) (int, error) {
	url := fmt.Sprintf("%s/SoftLayer_Dns_Domain/getByDomainName/%s", c.SoftlayerEndpoint, domain)
	headers := c.buildRequestHeader()
	response := make([]*SLDomainResponse, 0)
	resp, err := c.restClient.SendRequest(url, http.MethodGet, *headers, nil, &response)
	if err != nil {
		common.Logger().Error("Couldn't get zone by domain name: " + err.Error())
		return -1, buildOrderError(logdna.Error07071, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
	}
	//success
	if resp.StatusCode() == http.StatusOK {
		if len(response) > 0 {
			return response[0].Id, nil
		} else {
			//it can happen for subdomains
			return -1, buildOrderError(logdna.Error07072, fmt.Sprintf(domainIsNotFound, domain, dnsProviderSoftLayerAccount))
		}
	} else if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error("Couldn't get zone by domain name: Authorization error ")
		return -1, buildOrderError(logdna.Error07073, fmt.Sprintf(authorizationError, "to get zones from", dnsProviderSoftLayerAccount))
	}
	//softlayerError := getSoftlayerErrors(response.Errors)
	common.Logger().Error("Couldn't get zone by domain " + domain + ": ") //+ softlayerError)
	return -1, buildOrderError(logdna.Error07074, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))
}

func (c *SoftlayerDNSConfig) setChallenge(domain *SLDomainData) (int, error) {
	requestBody, err := createTxtRecordBody(domain, c.TTL)
	if err != nil {
		common.Logger().Error("Couldn't build txt record body: " + err.Error())
		return -1, buildOrderError(logdna.Error07075, internalServerError)
	}
	url := fmt.Sprintf(`%s/SoftLayer_Dns_Domain_ResourceRecord`, c.SoftlayerEndpoint)
	headers := c.buildRequestHeader()

	response := &SetDnsRecordResponse{}
	resp, err := c.restClient.SendRequest(url, http.MethodPost, *headers, requestBody, response)
	if err != nil {
		common.Logger().Error("Couldn't set challenge for domain " + domain.name + ": " + err.Error())
		return -1, buildOrderError(logdna.Error07076, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
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
		common.Logger().Error("Couldn't set txt record for domain " + domain.name + ": Authorization error ")
		return -1, buildOrderError(logdna.Error07077, fmt.Sprintf(authorizationError, "to set txt record in", dnsProviderSoftLayerAccount))
	}
	softlayerError := getSoftlayerErrors(resp)
	common.Logger().Error("Couldn't set txt record for domain " + domain.name + ": " + softlayerError)
	return -1, buildOrderError(logdna.Error07078, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))
}

func (c *SoftlayerDNSConfig) removeChallenge(domain *SLDomainData) error {
	////todo if domain.cisTxtRecordId is nil, try to get it
	url := fmt.Sprintf(`%s/SoftLayer_Dns_Domain_ResourceRecord/%d`, c.SoftlayerEndpoint, domain.txtRecordId)
	headers := c.buildRequestHeader()

	resp, err := c.restClient.SendRequest(url, http.MethodDelete, *headers, nil, nil)
	if err != nil {
		common.Logger().Error("Couldn't remove txt record for domain " + domain.name + ": " + err.Error())
		return buildOrderError(logdna.Error07079, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
	}
	//success
	if resp.StatusCode() == http.StatusOK {
		return nil
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error("Couldn't remove txt record for domain " + domain.name + ": Authorization error ")
		return buildOrderError(logdna.Error07080, fmt.Sprintf(authorizationError, "to delete txt record from", dnsProviderSoftLayerAccount))
	}
	softlayerError := getSoftlayerErrors(resp)
	common.Logger().Error("Couldn't remove txt record for domain " + domain.name + ": " + softlayerError)
	return buildOrderError(logdna.Error07081, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))

}

func (c *SoftlayerDNSConfig) getChallengeRecordId(domain *SLDomainData) (int, error) {
	url := fmt.Sprintf(`%s/SoftLayer_Dns_Domain/%d/getResourceRecords?objectFilter={"resourceRecords":{"host":{"operation": "%s"},"data":{"operation": "%s"}}}`,
		c.SoftlayerEndpoint, domain.domainId, url.QueryEscape(domain.txtRecordName), url.QueryEscape(domain.txtRecordValue))
	headers := c.buildRequestHeader()

	response := &SLlistResponse{}
	resp, err := c.restClient.SendRequest(url, http.MethodGet, *headers, nil, nil)
	if err != nil {
		common.Logger().Error("Couldn't get txt record for domain " + domain.name + ": " + err.Error())
		return -1, buildOrderError(logdna.Error07101, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
	}
	if resp.StatusCode() == http.StatusOK {
		if len(response.Result) > 0 {
			return response.Result[0].Id, nil
		}
		common.Logger().Error("TXT record " + domain.txtRecordName + " is not found in the IBM Cloud Internet Services instance")
		return -1, buildOrderError(logdna.Error07102, internalServerError)
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		return -1, buildOrderError(logdna.Error07103, fmt.Sprintf(authorizationError, "to get txt record from", dnsProviderSoftLayerAccount))
	}
	softlayerError := getSoftlayerErrors(resp)
	common.Logger().Error("Couldn't get txt record for domain " + domain.name + ": " + softlayerError)
	return -1, buildOrderError(logdna.Error07104, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))
}

func (c *SoftlayerDNSConfig) buildRequestHeader() *map[string]string {
	headers := make(map[string]string)
	headers["Authorization"] = "Basic " + c.Auth
	headers["Content-Type"] = "application/json"
	headers["Accept"] = "application/json"
	return &headers
}

//this func is called synchronous, so errors will be a part of response
func (c *SoftlayerDNSConfig) validateConfig() error {
	//try to get domains
	url := fmt.Sprintf("%s/SoftLayer_Dns_Domain/getByDomainName/getByDomainName/domain.com", c.SoftlayerEndpoint)
	headers := c.buildRequestHeader()
	resp, err := c.restClient.SendRequest(url, http.MethodGet, *headers, nil, nil)
	if err != nil {
		common.Logger().Error("Couldn't access  account: " + err.Error())
		message := fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer)
		return errors.New(message)
	}
	//success
	if resp.StatusCode() == http.StatusOK {
		return nil
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error("Couldn't access account: Authorization error ")
		message := fmt.Sprintf(authorizationError, "to access", dnsProviderSoftLayerAccount)
		return errors.New(message)
	}
	//	softlayerError := getSoftlayerErrors(response.Errors)
	common.Logger().Error("Couldn't access account: ") //+ softlayerError)
	message := fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer)
	return errors.New(message)
}

func createTxtRecordBody(domain *SLDomainData, ttl int) (*bytes.Buffer, error) {
	postBody := &SLRequest{
		Parameters: []SLDNSRecord{{
			Host:     domain.txtRecordName,
			Data:     domain.txtRecordValue,
			Ttl:      ttl,
			Type:     "txt",
			DomainId: domain.domainId,
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
	if user, ok := config[dnsConfigSLUser]; !ok || len(user) < 2 {
		message := fmt.Sprintf(configMissingField, providerTypeDNS, dnsConfigSLUser)
		return errors.New(message)
	}
	if password, ok := config[dnsConfigSLPassword]; !ok || len(password) < 2 {
		message := fmt.Sprintf(configMissingField, providerTypeDNS, dnsConfigSLPassword)
		return errors.New(message)
	}
	for k, _ := range config {
		if k != dnsConfigSLUser && k != dnsConfigSLPassword {
			common.Logger().Error("DNS config contains field " + k + " that is not valid")
			message := fmt.Sprintf(invalidConfigStruct, providerTypeDNS, dnsConfigTypeCIS, "["+dnsConfigSLUser+","+dnsConfigSLPassword+"]")
			return errors.New(message)
		}
	}
	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (c *SoftlayerDNSConfig) Timeout() (timeout, interval time.Duration) {
	return PropagationTimeout, PollingInterval
}
