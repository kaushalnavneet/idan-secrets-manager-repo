package publiccerts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-acme/lego/v4/challenge/dns01"
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

type SLErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

type SLDomainResponse struct {
	Id         int       `json:"id"`
	Name       string    `json:"name"`
	Serial     int       `json:"serial"`
	UpdateDate time.Time `json:"updateDate"`
}

type SLDnsRecordResponse struct {
	Id       int    `json:"id"`
	Data     string `json:"data"`
	Host     string `json:"host"`
	Ttl      int    `json:"ttl"`
	Type     string `json:"type"`
	DomainId int    `json:"domainId"`
}

type SLRequest struct {
	Parameters []SLDNSRecord `json:"parameters"`
}

type SLDNSRecord struct {
	Data     string `json:"data"`
	Host     string `json:"host"`
	Ttl      int    `json:"ttl"`
	Type     string `json:"type"`
	DomainId int    `json:"domainId"`
}

func NewSoftlayerDNSProvider(providerConfig map[string]string, rc rest_client.RestClientFactory) *SoftlayerDNSConfig {
	user := providerConfig[dnsConfigSLUser]
	password := providerConfig[dnsConfigSLPassword]
	auth := user + ":" + password
	return &SoftlayerDNSConfig{
		User:              user,
		Password:          password,
		Auth:              base64.StdEncoding.EncodeToString([]byte(auth)),
		SoftlayerEndpoint: urlSLApi,
		TTL:               txtRecordTtl, //for TXT records
		Domains:           make(map[string]*SLDomainData),
		restClient:        rc,
	}
}

// Present Implements dns provider interface
func (c *SoftlayerDNSConfig) Present(domain, token, keyAuth string) error {
	logStart := dnsProviderSoftLayer + presentFunc + domain
	common.Logger().Info(logStart + startSetChallenge)
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
	common.Logger().Info(logStart + endSetChallenge)
	return nil
}

// CleanUp Implements dns provider interface
func (c *SoftlayerDNSConfig) CleanUp(domain, token, keyAuth string) error {
	logStart := dnsProviderSoftLayer + cleanupFunc + domain
	common.Logger().Info(logStart + startCleanup)
	currentDomain, ok := c.Domains[domain]
	if !ok {
		common.Logger().Info(logStart + " The domain doesn't exist in the list of current domains, retrieving its data in order to remove txt record")
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
	common.Logger().Info(logStart + endCleanup)
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
				common.Logger().Error(logdna.Error07052 + " Couldn't find either domain " + originalDomain + " or its parent domains in " + dnsProviderSoftLayerAccount)
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
	errorLog := errorGetZoneByDomain + domain + ": "
	url := fmt.Sprintf("%s/SoftLayer_Dns_Domain/getByDomainName/%s", c.SoftlayerEndpoint, url.QueryEscape(domain))
	headers := c.buildRequestHeader()
	response := &SLCombinedResponse{}
	resp, err := c.restClient.SendRequest(url, http.MethodGet, *headers, nil, response)
	if err != nil {
		common.Logger().Error(logdna.Error07058 + errorLog + err.Error())
		return -1, buildOrderError(logdna.Error07058, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
	}
	//success
	if resp.StatusCode() == http.StatusOK && response.Domains != nil {
		if len(response.Domains) > 0 {
			for _, d := range response.Domains {
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
		common.Logger().Error(logdna.Error07044 + errorLog + errorAuthorization)
		return -1, buildOrderError(logdna.Error07044, fmt.Sprintf(authorizationError, "to get zones from", dnsProviderSoftLayerAccount))
	}
	common.Logger().Error(logdna.Error07045 + errorLog + response.getErrorMessage())
	return -1, buildOrderError(logdna.Error07045, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))
}

func (c *SoftlayerDNSConfig) setChallenge(domain *SLDomainData) (int, error) {
	errorLog := errorSetTxtRec + domain.name + ": "
	requestBody := createTxtRecordBody(domain, c.TTL)
	url := fmt.Sprintf(`%s/SoftLayer_Dns_Domain_ResourceRecord`, c.SoftlayerEndpoint)
	headers := c.buildRequestHeader()
	response := &SLCombinedResponse{}
	resp, err := c.restClient.SendRequest(url, http.MethodPost, *headers, requestBody, response)
	if err != nil {
		common.Logger().Error(logdna.Error07047 + errorLog + err.Error())
		return -1, buildOrderError(logdna.Error07047, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
	}
	//success
	if resp.StatusCode() == http.StatusCreated && response.DnsRecord != nil {
		return response.DnsRecord.Id, nil
	} else if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error(logdna.Error07048 + errorLog + errorAuthorization)
		return -1, buildOrderError(logdna.Error07048, fmt.Sprintf(authorizationError, "to set txt record in", dnsProviderSoftLayerAccount))
	}
	common.Logger().Error(logdna.Error07049 + errorLog + response.getErrorMessage())
	return -1, buildOrderError(logdna.Error07049, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))
}

func (c *SoftlayerDNSConfig) removeChallenge(domain *SLDomainData) error {
	errorLog := errorRemoveTxtRec + domain.name + ": "
	url := fmt.Sprintf(`%s/SoftLayer_Dns_Domain_ResourceRecord/%d`, c.SoftlayerEndpoint, domain.txtRecordId)
	headers := c.buildRequestHeader()
	response := &SLCombinedResponse{}
	resp, err := c.restClient.SendRequest(url, http.MethodDelete, *headers, nil, response)
	if err != nil {
		common.Logger().Error(logdna.Error07050 + errorLog + err.Error())
		return buildOrderError(logdna.Error07050, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
	}
	//success
	if resp.StatusCode() == http.StatusOK {
		return nil
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error(logdna.Error07051 + errorLog + errorAuthorization)
		return buildOrderError(logdna.Error07051, fmt.Sprintf(authorizationError, "to delete txt record from", dnsProviderSoftLayerAccount))
	}
	common.Logger().Error(logdna.Error07053 + errorLog + response.getErrorMessage())
	return buildOrderError(logdna.Error07053, fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer))
}

func (c *SoftlayerDNSConfig) getChallengeRecordId(domain *SLDomainData) (int, error) {
	errorLog := errorGetTxtRec + domain.name + ": "
	objectFilter := fmt.Sprintf(`{"resourceRecords":{"host":{"operation": "%s"},"data":{"operation": "%s"}}}`, domain.txtRecordName, domain.txtRecordValue)
	url := fmt.Sprintf(`%s/SoftLayer_Dns_Domain/%d/getResourceRecords?objectFilter=%s`, c.SoftlayerEndpoint, domain.zoneId, url.QueryEscape(objectFilter))
	headers := c.buildRequestHeader()
	response := &SLCombinedResponse{}
	resp, err := c.restClient.SendRequest(url, http.MethodGet, *headers, nil, response)
	if err != nil {
		common.Logger().Error(logdna.Error07054 + errorLog + err.Error())
		return -1, buildOrderError(logdna.Error07054, fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer))
	}
	if resp.StatusCode() == http.StatusOK {
		//if an array is empty our unmarshal method can't distinguish between domains and dns records
		//so here we can get empty response.Domains instead of response.DnsRecords
		//in this case we know that nothing was found
		if response.DnsRecords != nil && len(response.DnsRecords) > 0 {
			for _, d := range response.DnsRecords {
				if d.Host == domain.txtRecordName && d.Data == domain.txtRecordValue {
					return d.Id, nil
				}
			}
		}
		common.Logger().Error(logdna.Error07055 + " TXT record " + domain.txtRecordName + " is not found in " + dnsProviderSoftLayerAccount)
		return -1, buildOrderError(logdna.Error07055, internalServerError)
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error(logdna.Error07056 + errorLog + errorAuthorization)
		return -1, buildOrderError(logdna.Error07056, fmt.Sprintf(authorizationError, "to get txt record from", dnsProviderSoftLayerAccount))
	}
	common.Logger().Error(logdna.Error07057 + errorLog + response.getErrorMessage())
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
	domainsResponse := &SLCombinedResponse{}
	resp, err := c.restClient.SendRequest(url, http.MethodGet, *headers, nil, domainsResponse)
	if err != nil {
		message := fmt.Sprintf(unavailableDNSError, dnsProviderSoftLayer)
		common.ErrorLogForCustomer("Couldn't access "+dnsProviderSoftLayerAccount+": "+err.Error(), logdna.Error07036, logdna.BadRequestErrorMessage, true)
		return commonErrors.GenerateCodedError(logdna.Error07036, http.StatusBadRequest, message)
	}
	//success
	if resp.StatusCode() == http.StatusOK {
		common.Logger().Info("Validation succeeded. User " + c.User + " has an access to " + dnsProviderSoftLayerAccount)
		return nil
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		message := fmt.Sprintf(authorizationError, "to access", dnsProviderSoftLayerAccount)
		common.ErrorLogForCustomer(message, logdna.Error07037, logdna.BadRequestErrorMessage, true)
		return commonErrors.GenerateCodedError(logdna.Error07037, http.StatusBadRequest, message)
	}
	message := fmt.Sprintf(errorResponseFromDNS, dnsProviderSoftLayer)
	common.ErrorLogForCustomer("Couldn't access "+dnsProviderSoftLayerAccount+": "+domainsResponse.getErrorMessage(), logdna.Error07038, logdna.BadRequestErrorMessage, true)
	return commonErrors.GenerateCodedError(logdna.Error07038, http.StatusBadRequest, message)
}

func createTxtRecordBody(domain *SLDomainData, ttl int) *bytes.Buffer {
	postBody := &SLRequest{
		Parameters: []SLDNSRecord{{
			Host:     domain.txtRecordName,
			Data:     domain.txtRecordValue,
			Ttl:      ttl,
			Type:     "txt",
			DomainId: domain.zoneId,
		}}}
	marshalledPostBody, _ := json.Marshal(postBody)
	return bytes.NewBuffer(marshalledPostBody)
}

func validateSoftLayerConfigStructure(config map[string]string) error {
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
	common.Logger().Info(fmt.Sprintf("The timeout and interval to use when checking for DNS propagation for SoftLayer is set to %s and %s accordingly ", PropagationTimeoutSL, PollingIntervalSL))
	return PropagationTimeoutSL, PollingIntervalSL
}

type SLCombinedResponse struct {
	Domains    []SLDomainResponse
	DnsRecords []SLDnsRecordResponse
	DnsRecord  *SLDnsRecordResponse
	Error      *SLErrorResponse
	Other      []byte
}

func (r *SLCombinedResponse) UnmarshalJSON(data []byte) error {
	var domains []SLDomainResponse
	var dnsRec SLDnsRecordResponse
	var dnsRecs []SLDnsRecordResponse
	var errResp SLErrorResponse
	//in order to distinguish between array of domains and array of dns records
	//need to check that an item has a name (it's mandatory in domain but dns record doesn't have it)
	//if the array is empty we can't check it and empty domains always will be returned
	if err := json.Unmarshal(data, &domains); err == nil && (len(domains) == 0 || domains[0].Name != "") {
		r.Domains = domains
	} else if err = json.Unmarshal(data, &dnsRecs); err == nil && (len(dnsRecs) == 0 || dnsRecs[0].Host != "") {
		r.DnsRecords = dnsRecs
	} else if err = json.Unmarshal(data, &dnsRec); err == nil && dnsRec.Host != "" {
		r.DnsRecord = &dnsRec
	} else if err = json.Unmarshal(data, &errResp); err == nil && errResp.Error != "" {
		r.Error = &errResp
	} else {
		r.Other = data
	}
	return nil
}

func (r *SLCombinedResponse) getErrorMessage() string {
	if r.Error != nil {
		return fmt.Sprintf(dnsProviderSoftLayer+" error code: %s, message: %s ", r.Error.Code, r.Error.Error)
	} else {
		return fmt.Sprintf(dnsProviderSoftLayer+" response: %s", string(r.Other))
	}
}
