package iam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

// Credential type defines the fields required for IBM Cloud IAM authentication
type Credential struct {
	expiration  time.Time
	updateLock  sync.Mutex
	AccessToken string // Required if APIKey nor Endpoint are specified - IBM Cloud IAM access token
	APIKey      string // Required if AccessToken is not specified - IBM Cloud API key
	Endpoint    string // Required if AccessToken is not specified - IBM Cloud IAM endpoint
}

func (cr *Credential) GetToken() (string, error) {
	// Set token if empty or Set token if expired
	if len(cr.APIKey) != 0 && len(cr.Endpoint) != 0 && time.Now().After(cr.expiration) {
		if err := cr.getToken(); err != nil {
			return "", err
		}
	}

	return cr.AccessToken, nil
}

// getToken obtains a bearer token and its expiration
func (cr *Credential) getToken() (err error) {
	cr.updateLock.Lock()
	defer cr.updateLock.Unlock()

	// Check if another thread has updated the token
	if time.Now().Before(cr.expiration) {
		return nil
	}

	var req *http.Request
	client := http.Client{}
	requestBody := []byte("grant_type=urn:ibm:params:oauth:grant-type:apikey&apikey=" + cr.APIKey)

	req, err = http.NewRequest("POST", cr.Endpoint+"/identity/token", bytes.NewBuffer(requestBody))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %s", err)
	}
	defer resp.Body.Close()

	iamToken := struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int32  `json:"expires_in"`
	}{}

	err = json.Unmarshal(respBody, &iamToken)
	if err != nil {
		return fmt.Errorf("error unmarshaling response body: %s", err)
	}

	cr.AccessToken = fmt.Sprintf("Bearer %s", iamToken.AccessToken)
	cr.expiration = time.Now().Add((time.Duration(iamToken.ExpiresIn - 60)) * time.Second)

	return nil
}
