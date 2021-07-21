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

	CA             = "certificate_authorities"
	DNS            = "dns_providers"
	Root           = "root"
	ConfigCAPath   = "config/" + CA
	ConfigDNSPath  = "config/" + DNS
	ConfigRootPath = "config/" + Root
	ListPath       = "secrets"

	FieldOrderedOn    = "ordered_on"
	FieldErrorCode    = "error_code"
	FieldErrorMessage = "error_message"
	FieldAutoRotated  = "auto_rotated"
	FieldIssuanceInfo = "issuance_info"

	endCertificate = "-----END CERTIFICATE-----"
	errorPattern   = `{"error_code":"%s","error_message":"%s"}`
	// to common
	DeleteEngineConfigAction    = "secrets-manager.secret-engine-config.delete" //to common
	SecretMetadataTargetTypeURI = "secrets-manager/secret-metadata"
	ConfigTargetTypeURI         = "secrets-manager/secret-engine-config"

	MaxNumberCAConfigs             = 10
	MaxNumberDNSConfigs            = 10
	DirectoryLetsEncryptProdAlias  = "letsencrypt"
	DirectoryLetsEncryptStageAlias = "letsencrypt-stage"
	DirectoryLetsEncryptProd       = "https://acme-v02.api.letsencrypt.org/directory"
	DirectoryLetsEncryptStage      = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

const (
	MaxWorkers                           = 1
	MaxCertRequest                       = 50
	CertRequestTimeout     time.Duration = 600
	RenewalExecutionPeriod time.Duration = 3
	RenewalThreshold       time.Duration = 30 * 24 //((365 * 24 * 5) + 24) to always renew every renewal period
)
