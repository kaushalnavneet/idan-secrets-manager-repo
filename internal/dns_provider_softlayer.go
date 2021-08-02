package publiccerts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client_impl"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type SoftlayerDNSConfig struct {
	User              string
	Password          string
	Auth              string
	SoftlayerEndpoint string
	IAMEndpoint       string
	TTL               int
	Domains           map[string]*Domain
	restClient        rest_client.RestClientFactory
	iamToken          string
}

type SoftlayerResult struct {
	ID string `json:"id"`
}

type SoftlayerError struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

type SoftlayerResponseList struct {
	Success bool              `json:"success"`
	Result  []SoftlayerResult `json:"result"`
	Errors  []SoftlayerError  `json:"errors,omitempty"`
}

type SoftlayerResponseResult struct {
	Success bool             `json:"success"`
	Result  SoftlayerResult  `json:"result"`
	Errors  []SoftlayerError `json:"errors,omitempty"`
}

type SoftlayerRequest struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Type    string `json:"type"`
	TTL     int    `json:"ttl"`
}

const ()

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
		Domains:           make(map[string]*Domain),
		restClient:        cf,
	}
}

// Present Implements dns provider interface
func (c *SoftlayerDNSConfig) Present(domain, token, keyAuth string) error {
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
	return nil
}

// CleanUp Implements dns provider interface
func (c *SoftlayerDNSConfig) CleanUp(domain, token, keyAuth string) error {
	currentDomain, ok := c.Domains[domain]
	if !ok {
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
	err := c.removeChallenge(currentDomain)
	if err != nil {
		return err
	}
	delete(c.Domains, domain)
	return nil
}

func (c *SoftlayerDNSConfig) getDomainData(originalDomain, domainToSetChallenge, keyAuth string) (*Domain, error) {
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
	currentDomain := &Domain{name: domainToSetChallenge}
	currentDomain.zoneId = zoneId
	currentDomain.txtRecordName, currentDomain.txtRecordValue = dns01.GetRecord(originalDomain, keyAuth)
	return currentDomain, nil
}

func (c *SoftlayerDNSConfig) getZoneIdByDomain(domain string) (string, error) {
	url := fmt.Sprintf(`%s/zones?name=%s&status=active`, c.SoftlayerEndpoint, domain)
	headers := c.buildRequestHeader()
	response := &SoftlayerResponseList{}
	resp, err := c.restClient.SendRequest(url, http.MethodGet, *headers, nil, response)
	if err != nil {
		common.Logger().Error("Couldn't get zone by domain name: " + err.Error())
		return "", buildOrderError(logdna.Error07071, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
	}
	//success
	if resp.StatusCode() == http.StatusOK && response.Success && response.Result != nil {
		if len(response.Result) > 0 {
			return response.Result[0].ID, nil
		} else {
			//it can happen for subdomains
			return "", buildOrderError(logdna.Error07072, fmt.Sprintf(domainIsNotFound, domain, dnsProviderSoftLayerAccount))
		}
	} else if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error("Couldn't get zone by domain name: Authorization error ")
		return "", buildOrderError(logdna.Error07073, fmt.Sprintf(authorizationError, "to get zones from", dnsProviderSoftLayerAccount))
	}
	softlayerError := getSoftlayerErrors(response.Errors)
	common.Logger().Error("Couldn't get zone by domain " + domain + ": " + softlayerError)
	return "", buildOrderError(logdna.Error07074, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))
}

func (c *SoftlayerDNSConfig) setChallenge(domain *Domain) (string, error) {
	requestBody, err := createTxtRecordBody(domain.txtRecordName, domain.txtRecordValue, c.TTL)
	if err != nil {
		common.Logger().Error("Couldn't build txt record body: " + err.Error())
		return "", buildOrderError(logdna.Error07075, internalServerError)
	}

	url := fmt.Sprintf(`%s/zones/%s/dns_records`, c.SoftlayerEndpoint, url.QueryEscape(domain.zoneId))
	headers := c.buildRequestHeader()

	response := &SoftlayerResponseResult{}
	resp, err := c.restClient.SendRequest(url, http.MethodPost, *headers, requestBody, response)
	if err != nil {
		common.Logger().Error("Couldn't set challenge for domain " + domain.name + ": " + err.Error())
		return "", buildOrderError(logdna.Error07076, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
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
		return "", buildOrderError(logdna.Error07077, fmt.Sprintf(authorizationError, "to set txt record in", dnsProviderSoftLayerAccount))
	}
	softlayerError := getSoftlayerErrors(response.Errors)
	common.Logger().Error("Couldn't set txt record for domain " + domain.name + ": " + softlayerError)
	return "", buildOrderError(logdna.Error07078, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))
}

func (c *SoftlayerDNSConfig) removeChallenge(domain *Domain) error {
	//todo if domain.txtRecordId is nil, try to get it
	url := fmt.Sprintf(`%s/zones/%s/dns_records/%s`, c.SoftlayerEndpoint, url.QueryEscape(domain.zoneId), url.QueryEscape(domain.txtRecordId))
	headers := c.buildRequestHeader()

	response := &SoftlayerResponseResult{}
	resp, err := c.restClient.SendRequest(url, http.MethodDelete, *headers, nil, response)
	if err != nil {
		common.Logger().Error("Couldn't remove txt record for domain " + domain.name + ": " + err.Error())
		return buildOrderError(logdna.Error07079, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
	}
	//success
	if resp.StatusCode() == http.StatusOK && response.Success {
		return nil
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error("Couldn't remove txt record for domain " + domain.name + ": Authorization error ")
		return buildOrderError(logdna.Error07080, fmt.Sprintf(authorizationError, "to delete txt record from", dnsProviderSoftLayerAccount))
	}
	softlayerError := getSoftlayerErrors(response.Errors)
	common.Logger().Error("Couldn't remove txt record for domain " + domain.name + ": " + softlayerError)
	return buildOrderError(logdna.Error07081, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))

}

func (c *SoftlayerDNSConfig) getChallengeRecordId(domain *Domain) (string, error) {
	url := fmt.Sprintf(`%s/zones/%s/dns_records?type=TXT&name=%s&content=%s`, c.SoftlayerEndpoint,
		url.QueryEscape(domain.zoneId), url.QueryEscape(domain.txtRecordName), url.QueryEscape(domain.txtRecordValue))
	headers := c.buildRequestHeader()

	response := &SoftlayerResponseList{}
	resp, err := c.restClient.SendRequest(url, http.MethodGet, *headers, nil, response)
	if err != nil {
		common.Logger().Error("Couldn't get txt record for domain " + domain.name + ": " + err.Error())
		return "", buildOrderError(logdna.Error07101, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
	}
	if resp.StatusCode() == http.StatusOK && response.Success && response.Result != nil {
		if len(response.Result) > 0 {
			return response.Result[0].ID, nil
		}
		common.Logger().Error("TXT record " + domain.txtRecordName + " is not found in the IBM Cloud Internet Services instance")
		return "", buildOrderError(logdna.Error07102, internalServerError)
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		return "", buildOrderError(logdna.Error07103, fmt.Sprintf(authorizationError, "to get txt record from", dnsProviderSoftLayerAccount))
	}
	softlayerError := getSoftlayerErrors(response.Errors)
	common.Logger().Error("Couldn't get txt record for domain " + domain.name + ": " + softlayerError)
	return "", buildOrderError(logdna.Error07104, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))
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

	//response := &SoftlayerResponseList{}
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

func createTxtRecordBody(key, value string, ttl int) (*bytes.Buffer, error) {
	postBody := SoftlayerRequest{
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

func getSoftlayerErrors(errors []SoftlayerError) string {
	result := "Softlayer error/s: "
	for i, softlayerError := range errors {
		result += strconv.Itoa(i) + ". Code:" + strconv.Itoa(softlayerError.Code) + " Message:" + softlayerError.Message + ". "
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
