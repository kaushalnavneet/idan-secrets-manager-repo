package publiccerts

import (
	"github.com/hashicorp/vault/sdk/framework"
	"time"
)

const (
	PluginMountPath   = "/v1/ibmcloud/public_cert/"
	FieldName         = "name"
	FieldConfig       = "config"
	FieldType         = "type"
	FieldCAConfig     = "ca"
	FieldDNSConfig    = "dns"
	FieldBundleCert   = "bundle_certs"
	FieldRotation     = "rotation"
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

//cofigs common
const (
	Root             = "root"
	ConfigRootPath   = "config/" + Root
	MaxNumberConfigs = 10
)

//CA configuration
const (
	CA           = "certificate_authorities"
	ConfigCAPath = "config/" + CA

	caConfigTypeLEProd  = "letsencrypt"
	caConfigTypeLEStage = "letsencrypt-stage"

	caConfigPrivateKey   = "PRIVATE_KEY"
	caConfigRegistration = "REGISTRATION"
	caConfigEmail        = "EMAIL"
	caConfigDirectoryUrl = "DIRECTORY_URL"
	caConfigCARootCert   = "CA_ROOT_CERT"

	UrlLetsEncryptProd  = "https://acme-v02.api.letsencrypt.org/directory"
	UrlLetsEncryptStage = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

//dns configuration
const (
	DNS           = "dns_providers"
	ConfigDNSPath = "config/" + DNS

	dnsConfigTypeCIS   = "cis"
	dnsConfigCisCrn    = "CIS_CRN"
	dnsConfigCisApikey = "CIS_APIKEY"
	dnsConfigSMCrn     = "SM_CRN"
	serviceCISint      = "internet-svcs-ci"
	serviceCIS         = "internet-svcs"
	urlCISIntegration  = "https://api.int.cis.cloud.ibm.com/v1"
	urlCISStage        = "https://api.stage.cis.cloud.ibm.com/v1"
	urlCISProd         = "https://api.cis.cloud.ibm.com/v1"
	urlIamStage        = "https://iam.test.cloud.ibm.com"
	urlIamProd         = "https://iam.cloud.ibm.com"

	dnsConfigTypeSoftLayer = "softlayer"
	dnsConfigSLUser        = "SOFTLAYER_USER"
	dnsConfigSLPassword    = "SOFTLAYER_PASSWORD"
	urlSLApi               = "https://api.softlayer.com/rest/v3"

	PropagationTimeout = 60 * time.Minute
	PollingInterval    = 2 * time.Second
)

//internal errors
const (
	failedToSaveConfigError = "Failed to save configuration to the storage: %s"
	failedToGetConfigError  = "Failed to get configuration from the storage: %s"
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
