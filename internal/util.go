package publiccerts

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
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
	"github.ibm.com/security-services/secrets-manager-common-utils/feature_util"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	commonErrors "github.ibm.com/security-services/secrets-manager-vault-plugins-common/errors"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"golang.org/x/net/http2"
	"golang.org/x/net/idna"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	idnaValidator = idna.New(
		idna.StrictDomainName(true),
		idna.VerifyDNSLength(true),
	)
)

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

func GetEnvInt(key string, fallback int) int {
	if value, ok := os.LookupEnv(key); ok {
		attemptsString := fmt.Sprintf("%v", value)
		intVal, err := strconv.Atoi(attemptsString)
		if err != nil {
			return fallback
		}

		return intVal
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
	var privateKey crypto.PrivateKey
	var err error
	if block.Type == "PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS8PrivateKey(x509Encoded)
		if err == nil {
			switch privateKey.(type) {
			case *rsa.PrivateKey, *ecdsa.PrivateKey:
			default:
				err = fmt.Errorf("unknown private key type in PKCS#8 wrapping")
			}
		}
	} else if block.Type == "RSA PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS1PrivateKey(x509Encoded)
	} else if block.Type == "EC PRIVATE KEY" {
		privateKey, err = x509.ParseECPrivateKey(x509Encoded)
	} else {
		err = fmt.Errorf("private key should be in unencrypted PKCS#1 or PKCS#8 format")
	}
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func EncodePrivateKeyToPKCS8PEM(privateKey crypto.PrivateKey) (string, error) {
	privateKeyDer, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDer})
	return string(pemEncoded), nil
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
	return "", nil
}

func validateNames(names []string) error {
	if len(names) > 100 {
		msg := tooManyDomain
		common.ErrorLogForCustomer(msg, logdna.Error07101, logdna.BadRequestErrorMessage, true)
		return commonErrors.GenerateCodedError(logdna.Error07101, http.StatusBadRequest, msg)
	}
	//regex copied from here - https://github.com/hashicorp/vault/blob/abfc7a844517c87d5dcd32069e6baf682dfa580d/builtin/logical/pki/cert_util.go#L44
	// A note on hostnameRegex: although we set the StrictDomainName option
	// when doing the idna conversion, this appears to only affect output, not
	// input, so it will allow e.g. host^123.example.com straight through. So
	// we still need to use this to check the output.
	var hostnameRegex = regexp.MustCompile(`^(\*\.)?(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])\.?$`)
	uniqueDomains := make(map[string]bool)
	wildcardDomains := make([]string, 0)
	directChildDomains := make(map[string]int)
	for i, name := range names {
		sanitizedName := name
		if uniqueDomains[name] {
			msg := fmt.Sprintf(duplicateDomain, name)
			common.ErrorLogForCustomer(msg, logdna.Error07108, logdna.BadRequestErrorMessage, true)
			return commonErrors.GenerateCodedError(logdna.Error07108, http.StatusBadRequest, msg)
		}
		uniqueDomains[name] = true
		// If we have an asterisk as the first part of the domain name, mark it
		// as wildcard and set the sanitized name to the remainder of the  domain
		if strings.HasPrefix(name, "*.") {
			sanitizedName = sanitizedName[2:]
			//add it to the list of wildcard domains but without *
			wildcardDomains = append(wildcardDomains, sanitizedName)
		} else {
			//count this domain in its parent domain
			point := strings.Index(name, ".")
			parent := name[point+1:]
			if _, ok := directChildDomains[parent]; !ok {
				directChildDomains[parent] = 0
			}
			directChildDomains[parent]++
		}
		// The domain name MUST be encoded in the form in which it would appear in a certificate.
		// That is, it MUST be encoded according to the rules in Section 7 of [RFC5280].
		// https://tools.ietf.org/html/rfc5280#section-7
		converted, err := idnaValidator.ToASCII(sanitizedName)
		if err != nil {
			msg := fmt.Sprintf(invalidDomain, sanitizedName)
			common.ErrorLogForCustomer(msg+": "+err.Error(), logdna.Error07105, logdna.BadRequestErrorMessage, true)
			return commonErrors.GenerateCodedError(logdna.Error07105, http.StatusBadRequest, msg)
		}
		//this check is for common name only (the first in the array)
		if i == 0 && len(converted) > 64 {
			common.ErrorLogForCustomer(commonNameTooLong, logdna.Error07106, logdna.BadRequestErrorMessage, true)
			return commonErrors.GenerateCodedError(logdna.Error07106, http.StatusBadRequest, commonNameTooLong)
		}
		if !hostnameRegex.MatchString(converted) {
			msg := fmt.Sprintf(invalidDomain, name)
			common.ErrorLogForCustomer(msg, logdna.Error07107, logdna.BadRequestErrorMessage, true)
			return commonErrors.GenerateCodedError(logdna.Error07107, http.StatusBadRequest, msg)
		}
	}
	for _, wildcard := range wildcardDomains {
		if directChildDomains[wildcard] > 0 {
			common.ErrorLogForCustomer(redundantDomain, logdna.Error07109, logdna.BadRequestErrorMessage, true)
			return commonErrors.GenerateCodedError(logdna.Error07109, http.StatusBadRequest, redundantDomain)
		}
	}
	return nil
}

var keyTypes = map[string]certcrypto.KeyType{
	"RSA2048":  certcrypto.RSA2048,
	"RSA4096":  certcrypto.RSA4096,
	"ECDSA256": certcrypto.EC256,
	"ECDSA384": certcrypto.EC384,
}

func getKeyType(keyAlgorithm string) (certcrypto.KeyType, error) {
	keyType, ok := keyTypes[keyAlgorithm]
	if !ok {
		common.ErrorLogForCustomer(invalidKeyAlgorithm, logdna.Error07040, logdna.BadRequestErrorMessage, true)
		return "", commonErrors.GenerateCodedError(logdna.Error07040, http.StatusBadRequest, invalidKeyAlgorithm)
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

func IsManualDnsFeatureEnabled() bool {
	return feature_util.IsFeatureEnabled("manualDns")
	//instCrn := os.Getenv("CRN")
	//allowList := os.Getenv("publicCertAccountAllowList")
	//crnParts := strings.Split(instCrn, ":")
	////in case of invalid crn or empty allow list return false
	//if len(crnParts) < 8 || strings.Trim(allowList, " ") == "" {
	//	printAllowListLog(allowList, instCrn, false)
	//	return false
	//}
	//account := strings.Replace(strings.Split(instCrn, ":")[6], "a/", "", 1)
	//inAllowList := strings.Contains(allowList, account)
	//printAllowListLog(allowList, instCrn, inAllowList)
	//return inAllowList
}

func printAllowListLog(allowList string, instCrn string, isInAllowList bool) {
	if common.Logger() != nil {
		common.Logger().Info(fmt.Sprintf("Allow list is %s. The instance is in allow list: %v. Instance CRN is %s.", allowList, isInAllowList, instCrn))
	}
}
