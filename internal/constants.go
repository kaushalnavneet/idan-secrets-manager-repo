package publiccerts

import (
	"github.com/hashicorp/vault/sdk/framework"
	"time"
)

//todo move to common
const (
	PluginMountPath = "/v1/ibmcloud/public_cert/"
	FieldName       = "name"
	FieldConfig     = "config"
	FieldType       = "type"
	FieldCAConfig   = "ca"
	FieldDNSConfig  = "dns"
	FieldBundleCert = "bundle_certs"
	FieldRotation   = "rotation"

	FieldOrderedOn    = "ordered_on"
	FieldErrorCode    = "error_code"
	FieldErrorMessage = "error_message"
	FieldAutoRotated  = "auto_rotated"
	FieldIssuanceInfo = "issuance_info"

	endCertificate = "-----END CERTIFICATE-----"
	errorPattern   = `{"error_code":"%s","error_message":"%s"}`
)

const (
	MaxWorkers                           = 1
	MaxCertRequest                       = 50
	CertRequestTimeout     time.Duration = 600
	RenewalExecutionPeriod time.Duration = 3
	RenewalThreshold       time.Duration = 30 * 24 //((365 * 24 * 5) + 24) to always renew every renewal period
)

//configs
const (
	CA             = "certificate_authorities"
	DNS            = "dns_providers"
	Root           = "root"
	ConfigCAPath   = "config/" + CA
	ConfigDNSPath  = "config/" + DNS
	ConfigRootPath = "config/" + Root

	PropagationTimeout = 5 * time.Minute
	PollingInterval    = 2 * time.Second
	MaxNumberConfigs   = 10

	CATypeLetsEncryptProd     = "letsencrypt"
	CaTypeLetsEncryptStage    = "letsencrypt-stage"
	DirectoryLetsEncryptProd  = "https://acme-v02.api.letsencrypt.org/directory"
	DirectoryLetsEncryptStage = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

const (
	dnsConfigCisCrn      = "CIS_CRN"
	dnsConfigCisApikey   = "CIS_APIKEY"
	caConfigPrivateKey   = "PRIVATE_KEY"
	caConfigRegistration = "REGISTRATION"
	caConfigEmail        = "EMAIL"
	caConfigDirectoryUrl = "DIRECTORY_URL"
	caConfigCARootCert   = "CA_ROOT_CERT"
	serviceCISint        = "internet-svcs-ci"
	serviceCIS           = "internet-svcs"
	dnsConfigTypeCIS     = "cis"
)

var (
	configFields = map[string]*framework.FieldSchema{
		FieldName: {
			Type:        framework.TypeString,
			Description: "Specifies the config name.",
			Required:    true,
		},
		FieldType: {
			Type:        framework.TypeString,
			Description: "Specifies the provider type.",
			Required:    true,
		},
		FieldConfig: {
			Type:        framework.TypeKVPairs,
			Description: "Specifies the set of config properties.",
			Required:    true,
		},
	}
)
