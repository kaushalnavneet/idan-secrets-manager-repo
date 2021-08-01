package publiccerts

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/registration"
)

type CAUserConfig struct {
	Name         string `json:"name"`
	CAType       string `json:"type"`
	CARootCert   string `json:"ca_cert"`
	DirectoryURL string `json:"directory_url"`
	Email        string `json:"email"`
	Registration *registration.Resource
	key          crypto.PrivateKey
	byoa         bool
}

var caProviders map[string]string
var validCaProviders []interface{}

func init() {
	caProviders = map[string]string{
		CATypeLetsEncryptProd:  DirectoryLetsEncryptProd,
		CaTypeLetsEncryptStage: DirectoryLetsEncryptStage,
	}
	validCaProviders = make([]interface{}, 0, len(caProviders))
	for k, _ := range caProviders {
		validCaProviders = append(validCaProviders, k)
	}
}

func GetCATypesAllowedValues() []interface{} {
	return validCaProviders
}

func (u *CAUserConfig) GetEmail() string {
	return u.Email
}

func (u *CAUserConfig) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *CAUserConfig) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func NewCAUserConfig(caType, privateKeyPEM, caRootCertPath, email string) (*CAUserConfig, error) {
	//set directory url according to ca
	directoryUrl, ok := caProviders[caType]
	if !ok { //should not happen because of input validation
		return nil, fmt.Errorf("%s is not valid CA. Should be one of %s", caType, validCaProviders)
	}
	var privateKey crypto.PrivateKey
	var err error
	byoa := privateKeyPEM != ""
	if byoa {
		//validate private key
		privateKey, err = DecodePrivateKey(privateKeyPEM)
	} else {
		// Create a user. New accounts need an email and private key to start.
		// Note - Always use a secp256r1 curve for registering a user to the ACME server
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return nil, err
	}
	userConfig := &CAUserConfig{
		CAType:       caType,
		Email:        email,
		key:          privateKey,
		DirectoryURL: directoryUrl,
		CARootCert:   caRootCertPath,
		byoa:         byoa,
	}
	return userConfig, nil
}

func (u *CAUserConfig) initCAAccount() error {
	client, err := NewACMEClient(u, certcrypto.RSA2048)
	if err != nil {
		return err
	}

	if u.byoa {
		//retrieve the account information and fill fields in u
		err = client.RegisterUserWithKey(u)
	} else {
		err = client.RegisterUser(u)
	}
	if err != nil {
		return err
	}

	return nil
}

func (u *CAUserConfig) getConfigToStore() (map[string]string, error) {
	x509Encoded, err := x509.MarshalPKCS8PrivateKey(u.key)
	if err != nil {
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	storageEntry := map[string]string{
		caConfigRegistration: u.Registration.URI,
		caConfigEmail:        u.Email,
		caConfigPrivateKey:   string(pemEncoded),
		caConfigDirectoryUrl: u.DirectoryURL,
		caConfigCARootCert:   u.CARootCert,
	}
	return storageEntry, nil
}

//providerConfig type in this case maybe letsencrypt or letsencrypt-stage
func prepareCAConfigToStore(p *ProviderConfig) error {
	var err error
	privateKeyPEM, ok := p.Config[caConfigPrivateKey]
	if !ok || len(privateKeyPEM) == 0 {
		return fmt.Errorf(missingField, caConfigPrivateKey)
	}
	email := p.Config[caConfigEmail]
	//it's not expected to get this field
	//we can fill it with constant LE root cert if needed
	caCert := p.Config[caConfigCARootCert]
	ca, err := NewCAUserConfig(p.Type, privateKeyPEM, caCert, email)
	if err != nil {
		return err
	}
	err = ca.initCAAccount()
	if err != nil {
		return err
	}
	p.Config, err = ca.getConfigToStore()
	if err != nil {
		return err
	}
	return nil
}

func getCAConfigForResponse(p *ProviderConfig) map[string]string {
	result := make(map[string]string)
	result[caConfigPrivateKey] = p.Config[caConfigPrivateKey]
	return result
}
