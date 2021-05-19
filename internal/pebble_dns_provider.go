package publiccerts

import (
	"bytes"
	"encoding/json"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"io/ioutil"
	"log"
	"net/http"
)

type PebbleDNS struct {
	ip       string
	mgmtPort string
}

func NewPebbleDNSClient(ip, mgmtPort string) *PebbleDNS {
	return &PebbleDNS{
		ip:       ip,
		mgmtPort: mgmtPort,
	}
}

func (p *PebbleDNS) Present(domain, token, keyAuth string) error {
	// Compute the challenge response FQDN and TXT value for the domain based
	// on the keyAuth.
	fqdn, value := dns01.GetRecord(domain, keyAuth)

	//log.Printf("FQDN: %s, value: %s", fqdn,value)

	postBody, _ := json.Marshal(map[string]string{
		"host":  fqdn,
		"value": value,
	})
	requestBody := bytes.NewBuffer(postBody)

	url := "http://" + p.ip + ":" + p.mgmtPort + "/set-txt"
	resp, err := http.Post(url, "application/json", requestBody)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
		return err
	}
	//sb := string(body)
	//log.Printf(sb)

	return nil
}

func (p *PebbleDNS) CleanUp(domain, token, keyAuth string) error {
	fqdn, _ := dns01.GetRecord(domain, keyAuth)

	postBody, _ := json.Marshal(map[string]string{
		"host": fqdn,
	})
	responseBody := bytes.NewBuffer(postBody)

	url := "http://" + p.ip + ":" + p.mgmtPort + "/clear-txt"
	resp, err := http.Post(url, "application/json", responseBody)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
		return err
	}
	//sb := string(body)
	//log.Printf(sb)

	return nil

}
