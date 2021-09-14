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

	endCertificate        = "-----END CERTIFICATE-----"
	errorPattern          = `{"error_code":"%s","error_message":"%s"}`
	AutoRotatePath        = "autorotate"
	AutoRotateCleanupPath = "autorotate/final"
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
	MaxWorkers                               = 1
	MaxCertRequest                           = 50
	CertRequestTimeout         time.Duration = 60 * 20 //wait 20 minutes till fail order
	RotateIfExpirationIsInDays               = 30
	txtRecordTtl                             = 120
)

//paths
const (
	PathConfig       = "config/"
	PathSecrets      = "secrets/"
	PathSecretGroups = "secrets/groups/"
	PathVersions     = "/versions/"
	PathMetadata     = "/metadata"
	PathRotate       = "/rotate"

	PathOrdersInProgress = "orders"
)

//cofigs common
const (
	Root             = "root"
	ConfigRootPath   = PathConfig + Root
	MaxNumberConfigs = 10
)

//CA configuration
const (
	CA           = "certificate_authorities"
	ConfigCAPath = PathConfig + CA

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
	ConfigDNSPath = PathConfig + DNS

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
	workerPoolIsFull        = "too many pending requests! Try again later"
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

//logs
const (
	errorAuthorization     = "Authorization error"
	presentFunc            = " Present: "
	startSetChallenge      = " Trying to set the challenge"
	endSetChallenge        = " Challenge was set successfully"
	startCleanup           = " Trying to remove the challenge from domain"
	endCleanup             = " The domain was successfully cleaned up"
	cleanupFunc            = " Cleanup: "
	errorBuildHeaderFailed = " Couldn't build headers for CIS request: "
	errorRemoveTxtRec      = " Couldn't remove txt record for domain "
	errorGetTxtRec         = " Couldn't get txt record for domain "
	errorSetTxtRec         = " Couldn't set txt record for domain "
	errorGetZoneByDomain   = " Couldn't get zone id by domain name "
	CisServerError         = "statusCode=%d, errors='%+v'"
)

type ResponseBody struct {
	RequestId     string                 `json:"request_id"`
	LeaseId       string                 `json:"lease_id"`
	Renewable     bool                   `json:"renewable"`
	LeaseDuration int                    `json:"lease_duration"`
	Data          map[string]interface{} `json:"data"`
	WrapInfo      interface{}            `json:"wrap_info"`
	Warnings      interface{}            `json:"warnings"`
	Auth          interface{}            `json:"auth"`
}
