package publiccerts

// PluginMountPath usage path
const (
	PluginMountPath              = "/v1/ibmcloud/public_cert/"
	FieldRegistrationUrl         = "registration_uri"
	FieldName                    = "name"
	FieldDirectoryUrl            = "directory_url"
	FieldCaCert                  = "ca-cert"
	FieldEmail                   = "email"
	FieldPrivateKey              = "private_key"
	FieldConfig                  = "config"
	scopePrefixForAccountIdInCRN = "a/"
	ConfigStoragePath            = "config/root"
	SecretTypePublicCert         = "public_cert"
	ConfigCAPath                 = "config/certificate_authorities"
	ConfigDNSPath                = "config/dns_providers"
	ConfigRootPath               = "config/root"
)
