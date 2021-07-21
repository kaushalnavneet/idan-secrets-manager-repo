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

type CAUserConfigToStore struct {
	Name            string `json:"name"`
	CAType          string `json:"type"`
	CARootCert      string `json:"ca_cert"`
	DirectoryURL    string `json:"directory_url"`
	Email           string `json:"email"`
	RegistrationURL string `json:"registration_url"`
	PrivateKey      string `json:"private_key"`
}

var caProviders map[string]string
var validCaProviders []interface{}

func init() {
	caProviders = map[string]string{
		DirectoryLetsEncryptProdAlias:  DirectoryLetsEncryptProd,
		DirectoryLetsEncryptStageAlias: DirectoryLetsEncryptStage,
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

func NewCAAccountConfig(name, caType, caRootCertPath, privateKeyPEM, email string) (*CAUserConfig, error) {
	directoryUrl, ok := caProviders[caType]
	if !ok { //should not happen because of input validation
		return nil, fmt.Errorf("%s is not valid CA. Should be one of %s", caType, validCaProviders)
	}
	var privateKey crypto.PrivateKey
	var err error
	byoa := privateKeyPEM != ""
	if byoa {
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
		Name:         name,
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
	// Note - This client is used only for registering the user
	// and the keyType does not matter (keyType relevant only when issuing certificates).
	// Lego internally uses a default value of RSA2048, hence use that.
	client, err := NewACMEClient(u, certcrypto.RSA2048)
	if err != nil {
		return err
	}

	if u.byoa {
		err = client.RegisterUserWithKey(u)
	} else {
		err = client.RegisterUser(u)
	}
	if err != nil {
		return err
	}

	return nil
}

func (u *CAUserConfig) getConfigToStore() (*CAUserConfigToStore, error) {

	storageEntry := &CAUserConfigToStore{}
	x509Encoded, err := x509.MarshalPKCS8PrivateKey(u.key)
	if err != nil {
		return storageEntry, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	storageEntry = &CAUserConfigToStore{
		Name:            u.Name,
		CAType:          u.CAType,
		RegistrationURL: u.Registration.URI,
		Email:           u.Email,
		PrivateKey:      string(pemEncoded),
		DirectoryURL:    u.DirectoryURL,
		CARootCert:      u.CARootCert,
	}

	return storageEntry, nil
}
