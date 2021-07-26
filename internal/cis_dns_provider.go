package publiccerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client_impl"
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
	CRN         string
	CISEndpoint string
	IAMEndpoint string
	APIKey      string
	TTL         int
	Domains     map[string]*Domain
	restClient  rest_client.RestClientFactory
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

func NewCISDNSProvider(providerConfig map[string]string) *CISDNSConfig {
	crn := providerConfig["CIS_CRN"]
	apikey := providerConfig["CIS_APIKEY"]

	//create resty client
	cf := &rest_client_impl.RestClientFactory{}
	//init resty client with not default options
	cf.InitClientWithOptions(rest_client.RestClientOptions{
		Timeout:    10 * time.Second,
		Retries:    2,
		RetryDelay: 1 * time.Second,
	})
	var cisURL, iamURL string
	if strings.Contains(crn, "staging") {
		cisURL = "https://api.int.cis.cloud.ibm.com/v1"
		iamURL = "https://iam.test.cloud.ibm.com"
	} else {
		cisURL = "https://api.cis.cloud.ibm.com/v1"
		iamURL = "https://iam.cloud.ibm.com"
	}
	return &CISDNSConfig{
		CRN:         crn,
		CISEndpoint: cisURL,
		IAMEndpoint: iamURL,
		APIKey:      apikey,
		TTL:         120, //for TXT records
		Domains:     make(map[string]*Domain),
		restClient:  cf,
	}
}

// Present Implements dns provider interface
func (c *CISDNSConfig) Present(domain, token, keyAuth string) error {
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
func (c *CISDNSConfig) CleanUp(domain, token, keyAuth string) error {
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

func (c *CISDNSConfig) getDomainData(originalDomain, domainToSetChallenge, keyAuth string) (*Domain, error) {
	zoneId, err := c.getZoneIdByDomain(domainToSetChallenge)
	if err != nil {
		//if domain was not found in CIS
		if strings.Contains(err.Error(), logdna.Error07072) {
			//try to look for its parent domain
			domainParts := strings.Split(domainToSetChallenge, ".")
			if len(domainParts) == 2 {
				//we can't dive anymore, return error
				return nil, buildError(logdna.Error07072, fmt.Sprintf(domainIsNotFoundInCIS, originalDomain))
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

func (c *CISDNSConfig) getZoneIdByDomain(domain string) (string, error) {
	url := fmt.Sprintf(`%s/%s/zones?name=%s&status=active`, c.CISEndpoint, url.QueryEscape(c.CRN), domain)
	headers, err := c.buildRequestHeader()
	if err != nil {
		common.Logger().Error("Couldn't build headers for CIS request: " + err.Error())
		return "", buildError(logdna.Error07070, internalServerError)
	}
	response := &CISResponseList{}
	resp, err := c.restClient.SendRequest(url, http.MethodGet, *headers, nil, response)
	if err != nil {
		common.Logger().Error("Couldn't get zone by domain name: " + err.Error())
		return "", buildError(logdna.Error07071, unavailableCISError)
	}
	//success
	if resp.StatusCode() == http.StatusOK && response.Success && response.Result != nil {
		if len(response.Result) > 0 {
			return response.Result[0].ID, nil
		} else {
			//it can happen for subdomains
			return "", buildError(logdna.Error07072, fmt.Sprintf(domainIsNotFoundInCIS, domain))
		}
	} else if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error("Couldn't get zone by domain name: Authorization error ")
		return "", buildError(logdna.Error07073, fmt.Sprintf(authorizationErrorCIS, "to get zones from"))
	}
	cisError := getCISErrors(response.Errors)
	common.Logger().Error("Couldn't get zone by domain " + domain + ": " + cisError)
	return "", buildError(logdna.Error07074, errorResponseFromCIS)

}

func (c *CISDNSConfig) setChallenge(domain *Domain) (string, error) {
	requestBody, err := createTxtRecordBody(domain.txtRecordName, domain.txtRecordValue, c.TTL)
	if err != nil {
		common.Logger().Error("Couldn't build txt record body: " + err.Error())
		return "", buildError(logdna.Error07075, internalServerError)
	}

	url := fmt.Sprintf(`%s/%s/zones/%s/dns_records`, c.CISEndpoint, url.QueryEscape(c.CRN), url.QueryEscape(domain.zoneId))
	headers, _ := c.buildRequestHeader()
	response := &CISResponseResult{}
	resp, err := c.restClient.SendRequest(url, http.MethodPost, *headers, requestBody, response)
	if err != nil {
		common.Logger().Error("Couldn't set challenge for domain " + domain.name + ": " + err.Error())
		return "", buildError(logdna.Error07076, unavailableCISError)
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
		return "", buildError(logdna.Error07077, fmt.Sprintf(authorizationErrorCIS, "to set txt record in"))
	}
	cisError := getCISErrors(response.Errors)
	common.Logger().Error("Couldn't set txt record for domain " + domain.name + ": " + cisError)
	return "", buildError(logdna.Error07078, errorResponseFromCIS)
}

func (c *CISDNSConfig) removeChallenge(domain *Domain) error {
	//todo if domain.txtRecordId is nil, try to get it
	url := fmt.Sprintf(`%s/%s/zones/%s/dns_records/%s`, c.CISEndpoint, url.QueryEscape(c.CRN), url.QueryEscape(domain.zoneId), url.QueryEscape(domain.txtRecordId))
	headers, _ := c.buildRequestHeader()
	response := &CISResponseResult{}
	resp, err := c.restClient.SendRequest(url, http.MethodDelete, *headers, nil, response)
	if err != nil {
		common.Logger().Error("Couldn't remove txt record for domain " + domain.name + ": " + err.Error())
		return buildError(logdna.Error07079, unavailableCISError)
	}
	//success
	if resp.StatusCode() == http.StatusOK && response.Success {
		return nil
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		common.Logger().Error("Couldn't remove txt record for domain " + domain.name + ": Authorization error ")
		return buildError(logdna.Error07080, fmt.Sprintf(authorizationErrorCIS, "to delete txt record from"))
	}
	cisError := getCISErrors(response.Errors)
	common.Logger().Error("Couldn't remove txt record for domain " + domain.name + ": " + cisError)
	return buildError(logdna.Error07081, errorResponseFromCIS)

}

func (c *CISDNSConfig) getChallengeRecordId(domain *Domain) (string, error) {
	url := fmt.Sprintf(`%s/%s/zones/%s/dns_records?type=TXT&name=%s&content=%s`, c.CISEndpoint, url.QueryEscape(c.CRN),
		url.QueryEscape(domain.zoneId), url.QueryEscape(domain.txtRecordName), url.QueryEscape(domain.txtRecordValue))
	headers, _ := c.buildRequestHeader()
	response := &CISResponseList{}
	resp, err := c.restClient.SendRequest(url, http.MethodGet, *headers, nil, response)
	if err != nil {
		common.Logger().Error("Couldn't get txt record for domain " + domain.name + ": " + err.Error())
		return "", buildError(logdna.Error07101, unavailableCISError)
	}
	if resp.StatusCode() == http.StatusOK && response.Success && response.Result != nil {
		if len(response.Result) > 0 {
			return response.Result[0].ID, nil
		}
		common.Logger().Error("TXT record " + domain.txtRecordName + " is not found in the IBM Cloud Internet Services instance")
		return "", buildError(logdna.Error07102, internalServerError)
	}
	if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusUnauthorized {
		return "", buildError(logdna.Error07103, fmt.Sprintf(authorizationErrorCIS, "to get txt record from"))
	}
	cisError := getCISErrors(response.Errors)
	common.Logger().Error("Couldn't get txt record for domain " + domain.name + ": " + cisError)
	return "", buildError(logdna.Error07104, errorResponseFromCIS) //TODO to add error itself?
}

func (c *CISDNSConfig) buildRequestHeader() (*map[string]string, error) {
	headers := make(map[string]string)
	iamToken, _, err := iam.ObtainCachedToken(c.IAMEndpoint, c.APIKey, "", "", "")
	if err != nil {
		common.Logger().Error("Failed to obtain cached token", "error", err)
		return &headers, err
	}
	headers["x-auth-user-token"] = iamToken
	headers["Content-Type"] = "application/json"
	return &headers, nil
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

func getCISErrors(errors []CISError) string {
	result := "CIS error/s: "
	for i, cisError := range errors {
		result += strconv.Itoa(i) + ". Code:" + strconv.Itoa(cisError.Code) + " Message:" + cisError.Message + ". "
	}
	return result
}

func buildError(code, message string) error {
	return fmt.Errorf(errorPattern, code, message)
}

//TODO: Enable timeout!
//// Timeout returns the timeout and interval to use when checking for DNS propagation.
//// Adjusting here to cope with spikes in propagation times.
//func (c *CISDNSConfig) Timeout() (timeout, interval time.Duration) {
//	return d.config.PropagationTimeout, d.config.PollingInterval
//}
