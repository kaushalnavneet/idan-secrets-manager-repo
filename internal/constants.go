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

	endCertificate       = "-----END CERTIFICATE-----"
	errorPattern         = `{"error_code":"%s","error_message":"%s"}`
	AutoRenewPath        = "autorenew"
	AutoRenewCleanupPath = "autorenew/final"
)

const (
	vaultTokenHeader    = "X-Vault-Token"
	acceptHeader        = "Accept"
	contentTypeHeader   = "Content-Type"
	authorizationHeader = "Authorization"
	authUserTokenHeader = "x-auth-user-token"
	applicationJson     = "application/json"
)

const (
	MaxWorkers                              = 1
	MaxCertRequest                          = 50
	CertRequestTimeout        time.Duration = 60 * 20 //wait 20 minutes till fail order
	RenewIfExpirationIsInDays               = 88
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

	caConfigPrivateKey   = "private_key"
	caConfigRegistration = "registration"
	caConfigEmail        = "email"
	caConfigDirectoryUrl = "directory_url"
	caConfigCARootCert   = "ca_root_cert"

	UrlLetsEncryptProd  = "https://acme-v02.api.letsencrypt.org/directory"
	UrlLetsEncryptStage = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

//dns configuration
const (
	DNS           = "dns_providers"
	ConfigDNSPath = "config/" + DNS

	dnsConfigTypeCIS   = "cis"
	dnsConfigCisCrn    = "cis_crn"
	dnsConfigCisApikey = "cis_apikey"
	dnsConfigSMCrn     = "sm_crn"
	serviceCISint      = "internet-svcs-ci"
	serviceCIS         = "internet-svcs"
	urlCISIntegration  = "https://api.int.cis.cloud.ibm.com/v1"
	urlCISStage        = "https://api.stage.cis.cloud.ibm.com/v1"
	urlCISProd         = "https://api.cis.cloud.ibm.com/v1"
	urlIamStage        = "https://iam.test.cloud.ibm.com"
	urlIamProd         = "https://iam.cloud.ibm.com"

	dnsConfigTypeSoftLayer = "classic_infrastructure"
	dnsConfigSLUser        = "classic_infrastructure_username"
	dnsConfigSLPassword    = "classic_infrastructure_password"
	urlSLApi               = "https://api.softlayer.com/rest/v3"

	PropagationTimeout = 15 * time.Minute
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
			Description: fieldConfigNameDescription,
			Required:    true,
		},
		FieldType: {
			Type:        framework.TypeString,
			Description: fieldConfigTypeDescription,
			Required:    true,
		},
		FieldConfig: {
			Type:        framework.TypeKVPairs,
			Description: fieldConfigSettingsDescription,
			Required:    true,
		},
	}
)
