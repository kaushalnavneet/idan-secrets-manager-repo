package publiccerts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.ibm.com/security-services/secrets-manager-vault-plugin-public-cert-secret/iam"
	"io/ioutil"
	"log"
	"net/http"
)

type CISDNSConfig struct {
	Endpoint string
	CRN      string
	ZoneID   string // Also called DomainID and can be found in the CIS overview page
	IAM      *iam.Credential
	TTL      int
	RecordID map[string]string // Stores the record ID of each FQDN as a map FQDN -> ID

}

type CISRequest struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Type    string `json:"type"`
	TTL     int    `json:"ttl"`
}

func NewCISDNSProvider(crn string, zoneID string, iamAPIKey string) *CISDNSConfig {
	return &CISDNSConfig{
		Endpoint: "https://api.cis.cloud.ibm.com/v1/",
		CRN:      crn,
		ZoneID:   zoneID,
		IAM: &iam.Credential{
			APIKey:   iamAPIKey,
			Endpoint: "https://IAM.cloud.ibm.com",
		},
		TTL:      60, //TODO: Make this configurable
		RecordID: make(map[string]string),
	}
}

func CreateCISRequestBody(fqdn, value string, ttl int) (*bytes.Buffer, error) {
	postBody := CISRequest{
		Name:    fqdn,
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

func (c *CISDNSConfig) Present(domain, token, keyAuth string) error {
	// Compute the challenge response FQDN and TXT value for the domain based
	// on the keyAuth.
	fqdn, value := dns01.GetRecord(domain, keyAuth)

	log.Printf("FQDN: %s, value: %s \n", fqdn, value)

	requestBody, err := CreateCISRequestBody(fqdn, value, c.TTL)
	if err != nil {
		return err
	}

	var req *http.Request
	client := http.Client{}

	req, err = http.NewRequest("POST", c.Endpoint+c.CRN+"/zones/"+c.ZoneID+"/dns_records", requestBody)
	if err != nil {
		return err
	}

	iamToken, err := c.IAM.GetToken()
	if err != nil {
		return err
	}
	req.Header.Set("x-auth-user-token", iamToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %s", err)
	}
	defer resp.Body.Close()

	type CISResult struct {
		ID string `json:"id"`
	}
	type CISResponse struct {
		Result  json.RawMessage `json:"result"` //Note - this can be null, so we use RawMessage and delay unmarshalling
		Success bool            `json:"success"`
		Errors  json.RawMessage `json:"errors"`
	}
	cisResponse := CISResponse{}

	err = json.Unmarshal(respBody, &cisResponse)
	if err != nil {
		return err
	}

	if cisResponse.Success == false {
		return errors.New(string(cisResponse.Errors))
	}

	//Reaching here means the call succeeded without any error
	cisResult := CISResult{}
	err = json.Unmarshal(cisResponse.Result, &cisResult)

	log.Printf("[Present] Record ID: %s", cisResult.ID)

	c.RecordID[fqdn] = cisResult.ID

	return nil

}

func (c *CISDNSConfig) CleanUp(domain, token, keyAuth string) error {
	fqdn, _ := dns01.GetRecord(domain, keyAuth)

	//TODO: if no such record exists in memory, then read and find record from CIS??
	if _, ok := c.RecordID[fqdn]; !ok {
		return fmt.Errorf("no record ID exists for the fqdn " + fqdn)
	}

	var req *http.Request
	client := http.Client{}

	req, err := http.NewRequest("DELETE", c.Endpoint+c.CRN+"/zones/"+c.ZoneID+"/dns_records/"+c.RecordID[fqdn],
		nil)
	if err != nil {
		return err
	}

	iamToken, err := c.IAM.GetToken()
	if err != nil {
		return err
	}
	req.Header.Set("x-auth-user-token", iamToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %s", err)
	}
	defer resp.Body.Close()

	type CISResult struct {
		ID string `json:"id"`
	}
	type CISResponse struct {
		Result  json.RawMessage `json:"result"`
		Success bool            `json:"success"`
		Errors  json.RawMessage `json:"errors"`
	}
	cisResponse := CISResponse{}

	err = json.Unmarshal(respBody, &cisResponse)
	if err != nil {
		return fmt.Errorf("error unmarshalling response from CIS")
	}

	if cisResponse.Success == false {
		return errors.New(string(cisResponse.Errors))
	}

	//Reaching here means the call succeeded without any error
	cisResult := CISResult{}
	err = json.Unmarshal(cisResponse.Result, &cisResult)

	log.Printf("[CleanUp] Record ID: %s", cisResult.ID)

	delete(c.RecordID, fqdn)

	return nil
}

//TODO: Enable timeout!
//// Timeout returns the timeout and interval to use when checking for DNS propagation.
//// Adjusting here to cope with spikes in propagation times.
//func (c *CISDNSConfig) Timeout() (timeout, interval time.Duration) {
//	return d.config.PropagationTimeout, d.config.PollingInterval
//}
