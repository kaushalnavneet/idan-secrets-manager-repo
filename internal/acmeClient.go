package publiccerts

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client_impl"
	"net/http"
	"sort"
	"time"
)

type Client struct {
	LegoCore   *api.Core
	LegoClient *lego.Client
	RestClient rest_client.RestClientFactory
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

	privateKey := CAUserConfig.GetPrivateKey()
	if privateKey == nil {
		return nil, errors.New("private key was nil")
	}

	var kid string
	if reg := CAUserConfig.GetRegistration(); reg != nil {
		kid = reg.URI
	}
	core, err := api.New(legoConfig.HTTPClient, legoConfig.UserAgent, legoConfig.CADirURL, kid, privateKey)
	if err != nil {
		return nil, err
	}

	//create resty client for communication with dns provider
	rc := &rest_client_impl.RestClientFactory{}
	//init resty client with not default options
	rc.InitClientWithOptions(rest_client.RestClientOptions{
		Timeout:    10 * time.Second,
		Retries:    2,
		RetryDelay: 1 * time.Second,
	})
	return &Client{LegoClient: legoClient, RestClient: rc, LegoCore: core}, nil
}

func (client *Client) setDNSProvider(dnsProvider *ProviderConfig, domains []string, challengeOption dns01.ChallengeOption) error {
	providerType := dnsProvider.Type
	providerConfiguration := dnsProvider.Config
	if providerType == dnsConfigTypeCIS {
		err := client.LegoClient.Challenge.SetDNS01Provider(NewCISDNSProvider(providerConfiguration, client.RestClient, nil), challengeOption)
		return err

	} else if providerType == dnsConfigTypeSoftLayer {
		err := client.LegoClient.Challenge.SetDNS01Provider(NewSoftlayerDNSProvider(providerConfiguration, client.RestClient), challengeOption)
		return err
	} else if providerType == dnsConfigTypeManual {
		err := client.LegoClient.Challenge.SetDNS01Provider(NewManualDNSProvider(), challengeOption)
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

func (client *Client) SetChallengeProviders(dnsProvider *ProviderConfig, domains []string) error {
	challengeOption := dns01.WrapPreCheck(nil)
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

func (client *Client) ObtainCertificate(domain []string, isBundle bool, preferredChain string) (*certificate.Resource, error) {
	request := certificate.ObtainRequest{
		Domains:        domain,
		Bundle:         isBundle,
		PreferredChain: preferredChain,
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

// PrepareChallenges is used only for manual dns provider
func (client *Client) PrepareChallenges(workItem WorkItem) ([]Challenge, error) {
	order, err := client.LegoCore.Orders.New(workItem.domains)
	if err != nil {
		return nil, err
	}

	authorizations, err := client.getAuthorizations(order)
	if err != nil {
		// If any challenge fails, return. Do not generate partial SAN certificates.
		//client.deactivateAuthorizations(order, request.AlwaysDeactivateAuthorizations)
		return nil, err
	}
	challenges := make([]Challenge, len(authorizations))
	for i, authz := range authorizations {
		chlng, err := challenge.FindChallenge(challenge.DNS01, authz)
		if err != nil {
			return nil, err
		}

		// Generate the Key Authorization for the challenge
		keyAuth, err := client.LegoCore.GetKeyAuthorization(chlng.Token)
		if err != nil {
			return nil, err
		}
		challenges[i].Domain = authz.Identifier.Value
		challenges[i].Expiration = authz.Expires
		challenges[i].Status = chlng.Status
		challenges[i].TXTRecordName, challenges[i].TXTRecordValue = dns01.GetRecord(authz.Identifier.Value, keyAuth)
	}
	return challenges, nil
}

//this code is copied from Lego since it's not exposed
//https://github.com/go-acme/lego/blob/6d0e0e16b43db37b9e0b675125e2ad4258d00047/certificate/authorization.go#L18
func (client *Client) getAuthorizations(order acme.ExtendedOrder) ([]acme.Authorization, error) {
	resc, errc := make(chan acme.Authorization), make(chan domainError)
	delay := time.Second / overallRequestLimit
	for _, authzURL := range order.Authorizations {
		time.Sleep(delay)

		go func(authzURL string) {
			authz, err := client.LegoCore.Authorizations.Get(authzURL)
			if err != nil {
				errc <- domainError{Domain: authz.Identifier.Value, Error: err}
				return
			}

			resc <- authz
		}(authzURL)
	}

	var responses []acme.Authorization
	failures := make(obtainError)
	for i := 0; i < len(order.Authorizations); i++ {
		select {
		case res := <-resc:
			responses = append(responses, res)
		case err := <-errc:
			failures[err.Domain] = err.Error
		}
	}

	//for i, auth := range order.Authorizations {
	//	log.Infof("[%s] AuthURL: %s", order.Identifiers[i].Value, auth)
	//}

	close(resc)
	close(errc)

	// be careful to not return an empty failures map;
	// even if empty, they become non-nil error values
	if len(failures) > 0 {
		return responses, failures
	}
	return responses, nil
}

type domainError struct {
	Domain string
	Error  error
}

const (
	// overallRequestLimit is the overall number of request per second
	// limited on the "new-reg", "new-authz" and "new-cert" endpoints.
	// From the documentation the limitation is 20 requests per second,
	// but using 20 as value doesn't work but 18 do.
	overallRequestLimit = 18
)

// obtainError is returned when there are specific errors available per domain.
type obtainError map[string]error

func (e obtainError) Error() string {
	buffer := bytes.NewBufferString("error: one or more domains had a problem:\n")

	var domains []string
	for domain := range e {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	for _, domain := range domains {
		buffer.WriteString(fmt.Sprintf("[%s] %s\n", domain, e[domain]))
	}
	return buffer.String()
}
