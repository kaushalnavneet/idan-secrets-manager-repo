package publiccerts

// PluginMountPath usage path
const (
	PluginMountPath              = "/v1/ibmcloud/public_cert/"
	FieldRegistrationUrl         = "registration_uri"
	FieldName                    = "name"
	FieldDirectoryUrl            = "directory_url"
	FieldCaCert                  = "ca-cert"
	FieldEmail                   = "email"
	FieldTermsOfServiceAgreed    = "terms_of_service_agreed"
	FieldPrivateKey              = "private_key"
	scopePrefixForAccountIdInCRN = "a/"
	ConfigStoragePath            = "config/root"
	SecretTypePublicCert         = "public_cert"
	ConfigPath                   = "config/ca"
)
