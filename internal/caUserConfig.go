package publiccerts

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/registration"
)

type CAUserConfig struct {
	Name         string `json:"name"`
	CARootCert   string `json:"ca_cert"`
	DirectoryURL string `json:"directory_url"`
	Email        string `json:"email"`
	Registration *registration.Resource
	key          crypto.PrivateKey
}

type CAUserConfigToStore struct {
	Name            string `json:"name"`
	CARootCert      string `json:"ca_cert"`
	DirectoryURL    string `json:"directory_url"`
	Email           string `json:"email"`
	RegistrationURL string `json:"registration_url"`
	PrivateKey      string `json:"private_key"`
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

func NewCAAccountConfig(name, directoryUrl, caRootCertPath, privateKeyPEM string) (*CAUserConfig, error) {
	privateKey, err := DecodePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	userConfig := &CAUserConfig{
		Name:         name,
		key:          privateKey,
		DirectoryURL: directoryUrl,
		CARootCert:   caRootCertPath,
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
	err = client.RegisterUserWithKey(u)
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
		RegistrationURL: u.Registration.URI,
		Email:           u.Email,
		PrivateKey:      string(pemEncoded),
		DirectoryURL:    u.DirectoryURL,
		CARootCert:      u.CARootCert,
	}

	return storageEntry, nil
}

//func (b *backend) GetCAAccountConfigFromVaultAsKVPairs(ctx context.Context, storage logical.Storage,
//	path string) (map[string]interface{}, error) {
//
//	if storage == nil {
//		return nil, fmt.Errorf("nil storage for user config")
//	}
//
//	b.configMutex.RLock()
//	defer b.configMutex.RUnlock()
//
//	entry, err := storage.Get(ctx, path)
//	if err != nil {
//		return nil, err
//	}
//	if entry == nil {
//		return nil, nil
//	}
//
//	var d map[string]interface{}
//	if err = entry.DecodeJSON(&d); err != nil {
//		return nil, err
//	}
//
//	return d, nil
//}
//
//func (b *backend) GetCAAccountConfigFromVault(ctx context.Context, storage logical.Storage, path string) (*CAUserConfig, error) {
//	d, err := b.GetCAAccountConfigFromVaultAsKVPairs(ctx, storage, path)
//	if err != nil {
//		return nil, err
//	}
//
//	if len(d) == 0 {
//		return nil, fmt.Errorf("config does not exist in store")
//	}
//
//	block, _ := pem.Decode([]byte(d["private_key"].(string)))
//	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
//	if err != nil {
//		return nil, err
//	}
//
//	reg := &registration.Resource{
//		URI: d["registration_uri"].(string),
//	}
//
//	CAUserConfig := &CAUserConfig{
//		CARootCert:           d["ca_cert"].(string),
//		DirectoryURL:         d["directory_url"].(string),
//		Email:                d["email"].(string),
//		TermsOfServiceAgreed: d["terms_of_service_agreed"].(bool),
//		Registration:         reg,
//		key:                  privateKey,
//	}
//
//	return CAUserConfig, nil
//}
