package publiccerts

import (
	"time"
)

//todo move to common
const (
	PluginMountPath      = "/v1/ibmcloud/public_cert/"
	FieldRegistrationUrl = "registration_uri"
	FieldCAType          = "type"
	FieldCaCert          = "ca-cert"
	FieldEmail           = "email"
	FieldConfig          = "config"
	FieldType            = "type"
	FieldCAConfig        = "ca"
	FieldDNSConfig       = "dns"
	FieldBundleCert      = "bundle_certs"
	FieldRotation        = "rotation"

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

	MaxNumberCAConfigs             = 10
	MaxNumberDNSConfigs            = 10
	DirectoryLetsEncryptProdAlias  = "letsencrypt"
	DirectoryLetsEncryptStageAlias = "letsencrypt-stage"
	DirectoryLetsEncryptProd       = "https://acme-v02.api.letsencrypt.org/directory"
	DirectoryLetsEncryptStage      = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

const (
	cisCrn             = "CIS_CRN"
	cisApikey          = "CIS_APIKEY"
	PropagationTimeout = 5 * time.Minute
	PollingInterval    = 2 * time.Second
	serviceCISint      = "internet-svcs-ci"
	serviceCIS         = "internet-svcs"
)
