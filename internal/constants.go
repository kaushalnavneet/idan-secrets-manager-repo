package publiccerts

import (
	"time"
)

//todo move to common
const (
	PluginMountPath      = "/v1/ibmcloud/public_cert/"
	FieldRegistrationUrl = "registration_uri"
	FieldName            = "name"
	FieldDirectoryUrl    = "directory_url"
	FieldCaCert          = "ca-cert"
	FieldEmail           = "email"
	FieldPrivateKey      = "private_key"
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
	FieldRotateKeys   = "rotate_keys"
	FieldEnabled      = "enabled"
	endCertificate    = "-----END CERTIFICATE-----"
	errorPattern      = `{"error_code":"%s","error_message":"%s"}`
	// to common
	SecretTypePublicCert        = "public_cert"                                 //to common
	DeleteEngineConfigAction    = "secrets-manager.secret-engine-config.delete" //to common
	SecretMetadataTargetTypeURI = "secrets-manager/secret-metadata"
	ConfigTargetTypeURI         = "secrets-manager/secret-engine-config"
)

const (
	MaxWorkers                           = 1
	MaxCertRequest                       = 50
	CertRequestTimeout     time.Duration = 600
	RenewalExecutionPeriod time.Duration = 3
	RenewalThreshold       time.Duration = 30 * 24 //((365 * 24 * 5) + 24) to always renew every renewal period
)

const VersionMetaReadOpDesc = `The versions metadata read operation receives the secretId parameter as part of the path.
It returns all of the secret's version metadata.`

const VersionReadOpDesc = `The versions read operation receives the secretId parameter as part of the path.
It returns all of the secret's version.`

const VersionOperationsHelpSyn = `Read secrets version in the Imported certificate Secrets store.`
const VersionOperationsHelpDesc = `This path takes a secretId and attempts to perform the version read operation on the secret with this secretId.` +
	"\n" + VersionReadOpDesc

const VersionMetaOperationsHelpSyn = `Read metadata for secrets version in the Imported certificate Secrets store.`
const VersionMetaOperationsHelpDesc = `This path takes a secretId and attempts to perform the version metadata read operation on the secret with this secretId.` +
	"\n" + VersionMetaReadOpDesc
const issueConfigSyn = "Issue certificate."
const issueConfigDesc = "Issue certificate."
const RotateHelpSyn = "Renew certificate"
const RotateHelpDesc = "Renew certificate"
const ListHelpSyn = "List certificate"
const ListHelpDesc = "List certificate"
const ListOpDesc = `The List operation returns the secrets that are in the Imported certificate Secrets store.
It receives the following optional parameters: labels, limit and offset.
The labels parameter can be used to apply a tag-filter on the result of the operation, returning only the secrets that
have these required labels.
The limit and offset parameters are used for pagination.`

const secretsRootHelpSyn = `Create and List secrets in the Public c Certificates Secrets store.`
const secretsRootHelpDesc = `This path supports creating a new public certificate secret, and listing the secrets of the User Credentials Secrets store.`
