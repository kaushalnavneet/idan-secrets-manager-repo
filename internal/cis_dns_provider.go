package publiccerts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client_impl"
	"github.ibm.com/security-services/secrets-manager-iam/pkg/iam"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type CISDNSConfig struct {
	Endpoint   string
	CRN        string
	IAM        *Credential
	TTL        int
	Domains    map[string]*Domain
	restClient rest_client.RestClientFactory
}

type Domain struct {
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

type Credential struct {
	AccessToken string // Required if APIKey nor Endpoint are specified - IBM Cloud IAM access token
	APIKey      string // Required if AccessToken is not specified - IBM Cloud API key
	Endpoint    string // Required if AccessToken is not specified - IBM Cloud IAM endpoint
}

func NewCISDNSProvider(providerConfig map[string]string) *CISDNSConfig {
	crn := providerConfig["crn"]
	apikey := providerConfig["apikey"]

	//create resty client
	cf := &rest_client_impl.RestClientFactory{}
	//init resty client with not default options
	cf.InitClientWithOptions(rest_client.RestClientOptions{
		Timeout:    10 * time.Second,
		Retries:    2,
		RetryDelay: 1 * time.Second,
	})
	//TODO if crn in prod - endpoints of prod, otherwise - staging
	return &CISDNSConfig{
		Endpoint: "https://api.cis.cloud.ibm.com/v1",
		CRN:      crn,
		IAM: &Credential{
			APIKey:   apikey,
			Endpoint: "https://IAM.cloud.ibm.com",
		},
		TTL:        120,
		Domains:    make(map[string]*Domain),
		restClient: cf,
	}
}

// Present Implements dns provider interface
func (c *CISDNSConfig) Present(domain, token, keyAuth string) error {
	// Compute the challenge response FQDN and TXT value for the domain based  on the keyAuth.
	currentDomain := &Domain{name: domain}
	currentDomain.txtRecordName, currentDomain.txtRecordValue = dns01.GetRecord(domain, keyAuth)
	log.Printf("txtRecord Name: %s, Value: %s \n", currentDomain.txtRecordName, currentDomain.txtRecordValue)

	zoneId, err := c.getZoneIdByDomain(domain)
	if err != nil {
		return err
	}
	currentDomain.zoneId = zoneId
	recordId, err := c.setChallenge(currentDomain)
	if err != nil {
		return err
	}
	currentDomain.txtRecordId = recordId
	c.Domains[domain] = currentDomain
	return nil

}

// CleanUp Implements dns provider interface
func (c *CISDNSConfig) CleanUp(domain, token, keyAuth string) error {
	currentDomain, ok := c.Domains[domain]
	if !ok {
		return fmt.Errorf("no record ID exists for the domain " + domain)
	}
	err := c.removeChallenge(currentDomain)
	delete(c.Domains, domain)
	return err
}

func createTxtRecordBody(key, value string, ttl int) (*bytes.Buffer, error) {
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

func (c *CISDNSConfig) getZoneIdByDomain(domain string) (string, error) {
	url := fmt.Sprintf(`%s/%s/zones?name=%s&status=active`, c.Endpoint, url.QueryEscape(c.CRN), domain)
	headers, _ := c.buildRequestHeader()
	response := &CISResponseList{}
	resp, err := c.restClient.SendRequest(url, http.MethodGet, *headers, nil, response)
	if err != nil {
		return "", err
	}
	if resp.StatusCode() == http.StatusOK && response.Success && response.Result != nil {
		if len(response.Result) > 0 {
			return response.Result[0].ID, nil
		} else {
			return "", errors.New("domain " + domain + " is not found in the IBM Cloud Internet Services instance")
		}
	} else {
		if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
			return "", errors.New("authorization error when trying to get zones from the IBM Cloud Internet Services instance")
		}
	}
	return "", err
}

func (c *CISDNSConfig) buildRequestHeader() (*map[string]string, error) {
	err := iam.CheckConfigured()
	headers := make(map[string]string)
	iamToken, _, err := iam.ObtainCachedToken(c.IAM.Endpoint, c.IAM.APIKey, "", "", "")
	if err != nil {
		return &headers, err
	}
	headers["x-auth-user-token"] = iamToken
	headers["Content-Type"] = "application/json"
	return &headers, nil

}

func (c *CISDNSConfig) setChallenge(domain *Domain) (string, error) {
	requestBody, err := createTxtRecordBody(domain.txtRecordName, domain.txtRecordValue, c.TTL)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf(`%s/%s/zones/%s/dns_records`, c.Endpoint, url.QueryEscape(c.CRN), url.QueryEscape(domain.zoneId))
	headers, _ := c.buildRequestHeader()
	response := &CISResponseResult{}
	resp, err := c.restClient.SendRequest(url, http.MethodPost, *headers, requestBody, response)
	if err != nil {
		return "", err
	}
	if resp.StatusCode() == http.StatusOK && response.Success {
		return response.Result.ID, nil
	} else if resp.StatusCode() == http.StatusBadRequest {
		//	print	 response.Errors[0].Message,"Record already exists."
		id, err := c.getChallengeRecordId(domain)
		if err != nil {
			return "", err
		} else {
			return id, nil
		}
	} else if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		return "", errors.New("authorization error when trying to get txt record from the IBM Cloud Internet Services instance")
	}
	return "", errors.New(getCISErrors(response.Errors))
}

func getCISErrors(errors []CISError) string {
	result := "CIS error/s: "
	for i, cisError := range errors {
		result += strconv.Itoa(i) + ". Code:" + strconv.Itoa(cisError.Code) + " Message:" + cisError.Message + ". "
	}
	return result
}

func (c *CISDNSConfig) removeChallenge(domain *Domain) error {
	//todo if domain.txtRecordId is nil, try to get it
	url := fmt.Sprintf(`%s/%s/zones/%s/dns_records/%s`, c.Endpoint, url.QueryEscape(c.CRN), url.QueryEscape(domain.zoneId), url.QueryEscape(domain.txtRecordId))
	headers, _ := c.buildRequestHeader()
	response := &CISResponseResult{}
	resp, err := c.restClient.SendRequest(url, http.MethodDelete, *headers, nil, response)
	if err != nil {
		return err
	}
	if resp.StatusCode() == http.StatusOK && response.Success {
		return nil
	} else if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		return errors.New("authorization error when trying to delete txt record from the IBM Cloud Internet Services instance")
	}
	return errors.New(getCISErrors(response.Errors))
}

func (c *CISDNSConfig) getChallengeRecordId(domain *Domain) (string, error) {
	url := fmt.Sprintf(`%s/%s/zones/%s/dns_records?type=TXT&name=%s&content=%s`, c.Endpoint, url.QueryEscape(c.CRN),
		url.QueryEscape(domain.zoneId), url.QueryEscape(domain.txtRecordName), url.QueryEscape(domain.txtRecordValue))
	headers, _ := c.buildRequestHeader()
	response := &CISResponseList{}
	resp, err := c.restClient.SendRequest(url, http.MethodGet, *headers, nil, response)
	if err != nil {
		return "", err
	}
	if resp.StatusCode() == http.StatusOK && response.Success && response.Result != nil {
		if len(response.Result) > 0 {
			return response.Result[0].ID, nil
		} else {
			return "", errors.New("TXT record " + domain.txtRecordName + " is not found in the IBM Cloud Internet Services instance")
		}
	} else if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		return "", errors.New("authorization error when trying to get txt record from the IBM Cloud Internet Services instance")

	} else {
		return "", errors.New(getCISErrors(response.Errors))
	}
}

//TODO: Enable timeout!
//// Timeout returns the timeout and interval to use when checking for DNS propagation.
//// Adjusting here to cope with spikes in propagation times.
//func (c *CISDNSConfig) Timeout() (timeout, interval time.Duration) {
//	return d.config.PropagationTimeout, d.config.PollingInterval
//}
