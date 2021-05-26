package publiccerts

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"
	"golang.org/x/net/http2"
	"golang.org/x/net/idna"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

//func (b *backend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
//	out, err := req.Storage.Get(ctx, req.Path)
//	if err != nil {
//		return false, fmt.Errorf("existence check failed: %v", err)
//	}
//
//	return out != nil, nil
//}

func GetKeyType(keyType string, keyBits int) (certcrypto.KeyType, error) {
	switch keyType {
	case "rsa":
		{
			if keyBits == 2048 {
				return certcrypto.RSA2048, nil
			}
			if keyBits == 4096 {
				return certcrypto.RSA4096, nil
			}
			if keyBits == 8192 {
				return certcrypto.RSA8192, nil
			}
			return "", errors.New("invalid key bits for RSA")
		}
	case "ec":
		{
			if keyBits == 256 {
				return certcrypto.EC256, nil
			}
			if keyBits == 384 {
				return certcrypto.EC384, nil
			}
			return "", errors.New("invalid key bits for EC")
		}
	default:
		return "", errors.New("invalid key type")
	}
}

// LoadRootCertPoolFromPath builds a trust store (cert pool) containing our CA's root
// certificate.
func LoadRootCertPoolFromPath(rootCertPath string) (*x509.CertPool, error) {
	root, err := ioutil.ReadFile(rootCertPath)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool() // [Navaneeth] Note: Change this to SystemCertPool to also add certs from system
	if ok := pool.AppendCertsFromPEM(root); !ok {
		return nil, errors.New("missing or invalid root certificate")
	}

	return pool, nil
}

// LoadRootCertPool builds a trust store (cert pool) containing our CA's root
// certificate.
func LoadRootCertPool(rootCert string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if rootCert != "" {
		if ok := pool.AppendCertsFromPEM([]byte(rootCert)); !ok {
			return nil, errors.New("missing or invalid root certificate")
		}
	}

	return pool, nil
}

// GetHTTPSClient gets an HTTPS client configured to trust our CA's root
// certificate.
func GetHTTPSClient(rootCert string) (*http.Client, error) {
	pool, err := LoadRootCertPool(rootCert)
	if err != nil {
		return nil, err
	}

	// TODO: Instead of creating a new transport instance, share the transport instance
	// so that the TCP connection is shared when a new client is created.
	// This will avoid opening new connection every time a new client is requested
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			RootCAs:                  pool,
		},
	}
	if err := http2.ConfigureTransport(tr); err != nil {
		return nil, errors.New("error configuring transport")
	}
	return &http.Client{
		Transport: tr,
	}, nil
}

// https://tools.ietf.org/html/rfc8555#section-7.1.4
// The domain name MUST be encoded in the form in which it would appear in a certificate.
// That is, it MUST be encoded according to the rules in Section 7 of [RFC5280].
//
// https://tools.ietf.org/html/rfc5280#section-7
func sanitizeDomain(domains []string) []string {
	var sanitizedDomains []string
	for _, domain := range domains {
		sanitizedDomain, err := idna.ToASCII(domain)
		if err != nil {
			log.Infof("skip domain %q: unable to sanitize: %v", domain, err)
		} else {
			sanitizedDomains = append(sanitizedDomains, sanitizedDomain)
		}
	}
	return sanitizedDomains
}

func getNames(cn string, altNames []string) []string {
	names := make([]string, len(altNames)+1)
	names[0] = cn
	for i, n := range altNames {
		names[i+1] = n
	}

	return names
}

func CreateEnvVariable(envMap map[string]string) error {
	var err error
	for k, v := range envMap {
		err = os.Setenv(k, v)
		if err != nil {
			return err
		}
	}
	return nil
}

func GetEnv(key string, fallback interface{}) interface{} {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func DecodeECDSAKey(pemEncoded string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, err := x509.ParseECPrivateKey(x509Encoded)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func DecodePrivateKey(pemEncoded string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemEncoded))
	if block == nil {
		return nil, fmt.Errorf("private key is not valid PEM formatted value")
	}
	x509Encoded := block.Bytes
	privateKey, err := x509.ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func ExtractFirstEmailFromAccount(retrievedAccount *registration.Resource) (string, error) {
	if retrievedAccount == nil {
		return "", fmt.Errorf("retrieved account is nil")
	}
	for _, contact := range retrievedAccount.Body.Contact {
		if strings.HasPrefix(contact, "mailto:") {
			email := strings.TrimPrefix(contact, "mailto:")
			return email, nil
		}
	}
	return "", fmt.Errorf("no email address in retrieved account")
}

func IsTimeExpired(timeNow time.Time, timeExpiry time.Time) bool {
	return timeNow.After(timeExpiry)
}
