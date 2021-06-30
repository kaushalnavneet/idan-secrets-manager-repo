package publiccerts

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/registration"
	"golang.org/x/net/http2"
	"golang.org/x/net/idna"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	idnaValidator = idna.New(
		idna.StrictDomainName(true),
		idna.VerifyDNSLength(true),
	)
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

func getNames(cn string, altNames []string) []string {
	//altNames contains common name too, we want to remove it to prevent domains duplication
	names := make([]string, 0)
	names = append(names, cn)
	for _, n := range altNames {
		if n != cn {
			names = append(names, n)
		}
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

func validateNames(names []string) error {
	//regex copied from here - https://github.com/hashicorp/vault/blob/abfc7a844517c87d5dcd32069e6baf682dfa580d/builtin/logical/pki/cert_util.go#L44
	// A note on hostnameRegex: although we set the StrictDomainName option
	// when doing the idna conversion, this appears to only affect output, not
	// input, so it will allow e.g. host^123.example.com straight through. So
	// we still need to use this to check the output.
	var hostnameRegex = regexp.MustCompile(`^(\*\.)?(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])\.?$`)
	uniqueDomains := make(map[string]bool)
	for _, name := range names {
		sanitizedName := name
		// If we have an asterisk as the first part of the domain name, mark it
		// as wildcard and set the sanitized name to the remainder of the  domain
		if strings.HasPrefix(name, "*.") {
			sanitizedName = sanitizedName[2:]
		}
		// The domain name MUST be encoded in the form in which it would appear in a certificate.
		// That is, it MUST be encoded according to the rules in Section 7 of [RFC5280].
		// https://tools.ietf.org/html/rfc5280#section-7
		converted, err := idnaValidator.ToASCII(sanitizedName)
		if err != nil {
			return err
		}
		if !hostnameRegex.MatchString(converted) {
			return errors.New(" Domain " + name + " is not valid")
		}
		if uniqueDomains[converted] {
			return errors.New(" Domain " + name + " is duplicated")
		}
		uniqueDomains[converted] = true
	}
	return nil
}

var keyTypes = map[string]certcrypto.KeyType{
	"rsaEncryption 2048 bit": certcrypto.RSA2048, //UI presentation
	"rsaEncryption 4096 bit": certcrypto.RSA4096,
	"rsaEncryption 8192 bit": certcrypto.RSA8192,
	"SHA256-RSA":             certcrypto.RSA2048, // certificate in fact presentation
}

func getKeyType(keyAlgorithm string) (certcrypto.KeyType, error) {
	keyType, ok := keyTypes[keyAlgorithm]
	if !ok {
		return "", errors.New("key algorithm is not valid ")
	}
	return keyType, nil
}

func getOrderID(names []string) string {
	nameHash := sha256.Sum256([]byte(strings.Join(names, "")))
	return hex.EncodeToString(nameHash[:])
}

func getOrderError(res Result) *OrderError {
	pat := regexp.MustCompile(fmt.Sprintf(errorPattern, "(.*?)", "(.*?)"))
	errorJson := pat.FindString(res.Error.Error())
	errorObj := &OrderError{}
	err := json.Unmarshal([]byte(errorJson), errorObj)
	if err != nil {
		errorObj.Code = "ACME_Error"
		errorObj.Message = res.Error.Error()
	}
	return errorObj
}
