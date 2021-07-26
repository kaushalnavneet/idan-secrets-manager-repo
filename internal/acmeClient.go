package publiccerts

import (
	"crypto/x509"
	"fmt"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	"net/http"
	"time"
)

type Client struct {
	LegoClient *lego.Client
}

func NewACMEClient(CAUserConfig *CAUserConfig, keyType certcrypto.KeyType) (*Client, error) {
	// Get an HTTPS client configured to trust our root certificate.
	httpClient, err := GetHTTPSClient(CAUserConfig.CARootCert)
	if err != nil {
		return nil, err
	}
	return NewACMEClientWithCustomHttpClient(CAUserConfig, keyType, httpClient)
}

func NewACMEClientWithCustomHttpClient(CAUserConfig *CAUserConfig, keyType certcrypto.KeyType, httpClient *http.Client) (*Client, error) {
	legoConfig := &lego.Config{
		CADirURL:   CAUserConfig.DirectoryURL,
		User:       CAUserConfig,
		HTTPClient: httpClient,
		Certificate: lego.CertificateConfig{
			KeyType: keyType,
			Timeout: 30 * time.Second,
		},
	}
	legoClient, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, err
	}
	return &Client{LegoClient: legoClient}, nil
}

func (client *Client) setDNSProvider(dnsProvider *DnsProviderConfig, domains []string, challengeOption dns01.ChallengeOption) error {
	providerType := dnsProvider.Type
	providerConfiguration := dnsProvider.Config
	if providerType == "pebble" {
		host, found := providerConfiguration["host"]
		if !found {
			return fmt.Errorf("host for pebble DNS challenge is not provided")
		}
		port, found := providerConfiguration["port"]
		if !found {
			return fmt.Errorf("port for pebble DNS challenge is not provided")
		}

		err := client.LegoClient.Challenge.SetDNS01Provider(NewPebbleDNSClient(host, port), challengeOption)
		return err

	} else if providerType == "cis" {
		err := client.LegoClient.Challenge.SetDNS01Provider(NewCISDNSProvider(providerConfiguration, dnsProvider.smInstanceCrn), challengeOption)
		return err

	} else {
		//TODO: Consider a more secure alternative of writing to file instead of env
		err := CreateEnvVariable(providerConfiguration)
		if err != nil {
			return err
		}

		provider, err := dns.NewDNSChallengeProviderByName(providerType)
		if err != nil {
			return err
		}
		err = client.LegoClient.Challenge.SetDNS01Provider(provider, challengeOption)
		return err
	}
}

func (client *Client) SetChallengeProviders(dnsProvider *DnsProviderConfig, domains []string) error {
	challengeOption := dns01.DisableCompletePropagationRequirement()
	err := client.setDNSProvider(dnsProvider, domains, challengeOption)
	return err
}

func (client *Client) RegisterUser(userConfig *CAUserConfig) error {
	// New users will need to register
	reg, err := client.LegoClient.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	userConfig.Registration = reg
	return nil
}

// RegisterUserWithKey This will retrieve the account information using the private key (passed through user config) registered with the
//  ACME server and then set the registration resource and email to the user config
// https://tools.ietf.org/html/rfc8555#section-7.3
func (client *Client) RegisterUserWithKey(CAUserConfig *CAUserConfig) error {
	retrievedAccount, err := client.LegoClient.Registration.ResolveAccountByKey()
	if err != nil {
		return err
	}
	email, err := ExtractFirstEmailFromAccount(retrievedAccount)
	if err != nil {
		return err
	}
	CAUserConfig.Registration = retrievedAccount
	CAUserConfig.Email = email
	return nil
}

func (client *Client) QueryRegistration() (*registration.Resource, error) {
	return client.LegoClient.Registration.QueryRegistration()
}

func (client *Client) ObtainCertificate(domain []string, isBundle bool) (*certificate.Resource, error) {
	request := certificate.ObtainRequest{
		Domains: domain,
		Bundle:  isBundle,
	}

	return client.LegoClient.Certificate.Obtain(request)
}

func (client *Client) ObtainCertificateForCSR(csr *x509.CertificateRequest, isBundle bool) (*certificate.Resource, error) {
	request := certificate.ObtainForCSRRequest{
		CSR:    csr,
		Bundle: isBundle,
	}

	return client.LegoClient.Certificate.ObtainForCSR(request)
}
