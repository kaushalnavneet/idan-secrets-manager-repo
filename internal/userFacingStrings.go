package publiccerts

//errors in Configs
const (
	providerTypeCA  = "Certificate Authority"
	providerTypeDNS = "DNS Provider"
	//this type ^ is added to the following messages
	reachedTheMaximum    = "%s configuration couldn't be added because you have reached the maximum number of configurations (%d)"
	nameAlreadyExists    = "%s configuration with name '%s' already exists"
	configNotFound       = "%s configuration with name '%s' was not found"
	configMissingField   = "%s configuration missing property %s"
	invalidConfigStruct  = "%s configuration of type '%s' has a wrong structure. It may contain only properties %s"
	configWrongStructure = "'config' field is not valid. It should be key-value map"
	invalidConfigType    = "Config type should be one of [%s]"
	configNameWithSpace  = "Config name mustn't contain spaces"

	//specific CA
	invalidKey     = "Certificate Authority Private Key is not valid : %s"
	wrongCAAccount = "Failed to retrieve the Certificate Authority account information: %s"
)

//config fields description
const (
	fieldConfigNameDescription     = "The config name"
	fieldConfigTypeDescription     = "The config type"
	fieldConfigSettingsDescription = "The set of config properties"
)

// Certificate Authorities config create and list path
const (
	pathCAConfigHelpSynopsis    = "Create and List the Certificate Authority configuration."
	pathCAConfigHelpDescription = `This path supports creating a new Certificate Authority configuration, 
and listing the existing Certificate Authority configuration of the Public certificate Secrets store.`

	listCAConfigOperationSummary     = "Get all the Certificate Authority configurations"
	listCAConfigOperationDescription = `The List operation returns the Certificate Authority configurations that are in the Public certificate Secrets store.`

	createCAConfigOperationSummary     = "Create the Certificate Authority configuration"
	createCAConfigOperationDescription = `The Create operation creates a new Certificate Authority configuration. The following parameters are used to create a new secret:
name (required), type (required), config (required).
The created config is returned in the response.`
)

// Certificate Authorities config  get update delete path
const (
	pathCAConfigWithNameHelpSynopsis    = "Read, Update and Delete the Certificate Authority configuration."
	pathCAConfigWithNameHelpDescription = `This path takes config name and attempts to perform reading, updating and deleting of the Certificate Authority configuration.`

	getCAConfigOperationSummary     = "Read the Certificate Authority configuration"
	getCAConfigOperationDescription = `The read operation receives the config name parameter as part of the path.
It returns the Certificate Authority configuration.`

	updateCAConfigOperationSummary     = "Update the Certificate Authority configuration"
	updateCAConfigOperationDescription = `The update operation receives the config name parameter as part of the path and the new payload as a required parameter.
It updates the Certificate Authority configuration, and returns the updated configuration.`

	deleteCAConfigOperationSummary     = "Delete the Certificate Authority configuration"
	deleteCAConfigOperationDescription = `The delete operation receives config name parameter as part of the path.
It deletes the configuration with the given name.`
)

// DNS provider config create and list path
const (
	pathDNSConfigHelpSynopsis    = "Create and List the DNS Provider configuration."
	pathDNSConfigHelpDescription = `This path supports creating a new DNS Provider configuration, 
and listing the existing DNS Provider configuration of the Public certificate Secrets store.`

	listDNSConfigOperationSummary     = "Get all the DNS Provider configurations"
	listDNSConfigOperationDescription = `The List operation returns the DNS Provider configurations that are in the Public certificate Secrets store.`

	createDNSConfigOperationSummary     = "Create the DNS Provider configuration"
	createDNSConfigOperationDescription = `The Create operation creates a new DNS Provider configuration. The following parameters are used to create a new secret:
name (required), type (required), config (required).
The created config is returned in the response.`
)

// DNS provider config  get update delete path
const (
	pathDNSConfigWithNameHelpSynopsis    = "Read, Update and Delete the DNS Provider configuration."
	pathDNSConfigWithNameHelpDescription = `This path takes config name and attempts to perform reading, updating and deleting of the DNS Provider configuration.`

	getDNSConfigOperationSummary     = "Read the DNS Provider configuration"
	getDNSConfigOperationDescription = `The read operation receives the config name parameter as part of the path.
It returns the DNS Provider configuration.`

	updateDNSConfigOperationSummary     = "Update the DNS Provider configuration"
	updateDNSConfigOperationDescription = `The update operation receives the config name parameter as part of the path and the new payload as a required parameter.
It updates the DNS Provider configuration, and returns the updated configuration.`

	deleteDNSConfigOperationSummary     = "Delete the DNS Provider configuration"
	deleteDNSConfigOperationDescription = `The delete operation receives config name parameter as part of the path.
It deletes the configuration with the given name.`
)

// Root config get path
const (
	pathRootConfigHelpSynopsis    = "Read the root configuration."
	pathRootConfigHelpDescription = `This path supports listing all the existing DNS Provider  and Certificate Authority configurations of the Public certificate Secrets store.`

	getRootConfigOperationSummary     = "Get all the configuration values"
	getRootConfigOperationDescription = `The List operation returns all DNS Provider and Certificate Authority configurations of the Public certificate Secrets store.`
)

//path get / delete secret
const (
	pathSecretHelpSynopsis    = "Get and delete certificate ."
	pathSecretHelpDescription = `This path supports get certificate and delete certificate data.`

	getSecretOperationSummary     = "Get certificate data"
	getSecretOperationDescription = `The Get operation returns Certificate secret data.`

	deleteSecretOperationSummary     = "Get certificate data"
	deleteSecretOperationDescription = `The Get operation returns Certificate secret data.`
)

//path get version
const (
	pathVersionHelpSynopsis    = `Read secrets version in the Public certificate Secrets store.`
	pathVersionHelpDescription = `This path takes a secretId and attempts to perform the version read operation on the secret with this secretId.` +
		"\n" + getVersionOperationDescription

	getVersionOperationSummary     = "Reads a version of a secret"
	getVersionOperationDescription = `The versions read operation receives the secretId parameter as part of the path.
It returns all of the secret's version.`
)

// path get / update metadata
const (
	pathMetadataHelpSynopsis    = "Get and update certificate metadata."
	pathMetadataHelpDescription = `This path supports get certificate metadata and update certificate name, description or labels.`

	getMetadataOperationSummary     = "Get certificate metadata"
	getMetadataOperationDescription = `The Get operation returns Certificate metadata.`

	updateMetadataOperationSummary     = "Update secret metadata"
	updateMetadataOperationDescription = "Update certificate name, description or labels"
)

// path get version metadata
const (
	pathVersionMetaHelpSynopsis    = `Read metadata for secrets version in the Public certificate Secrets store.`
	pathVersionMetaHelpDescription = `This path takes a secretId and attempts to perform the version metadata read operation on the secret with this secretId.` +
		"\n" + getVersionMetaOperationDescription

	getVersionMetaOperationSummary     = "Reads a version metadata of a secret"
	getVersionMetaOperationDescription = `The versions metadata read operation receives the secretId parameter as part of the path.
It returns all of the secret's version metadata.`
)

//path issue and list certificates
const (
	pathIssueListHelpSynopsis    = `Create and List secrets in the Public c Certificates Secrets store.`
	pathIssueListHelpDescription = `This path supports creating a new public certificate secret, and listing the secrets of the User Credentials Secrets store.`

	issueCertOperationSummary     = "Issue a certificate"
	issueCertOperationDescription = "Issue a certificate"

	listCertsOperationSummary      = "List certificates"
	lListCertsOperationDescription = `The List operation returns the secrets that are in the Public certificate Secrets store.
It receives the following optional parameters: labels, limit and offset.
The labels parameter can be used to apply a tag-filter on the result of the operation, returning only the secrets that
have these required labels.
The limit and offset parameters are used for pagination.`

	fieldCAConfigDescription          = "The Certificate Authority configuration name."
	fieldDNSProviderConfigDescription = "The DNS provider configuration name."
	fieldCommonNameDescription        = "The certificate Common Name (main domain)."
	fieldAltNamesDescription          = "The certificate Alt Names (additional domains)."
	fieldBundleCertDescription        = "Set to `true` to bundle the issuer certificate with the public certificate (full  chain cert file). Default value true"
	fieldKeyAlgorithmDescription      = "The certificate key algorithm. Default value RSA2048"
	fieldRotationDescription          = `The set of rotation settings. Default value {"auto_rotate":false, "rotate_keys":false}`
)

//path  Rotate certificate
const (
	pathRotateHelpSynopsis    = "Renew certificate"
	pathRotateHelpDescription = "Renew certificate"

	rotateOperationSummary     = "Rotate a secrets."
	rotateOperationDescription = "Rotate a secrets."

	fieldRotateKeyDescription = "Specify if a private key should be rotated."
)

//policies operations
const (
	pathPoliciesHelpSynopsis    = `Read and update a secret's policy for secrets in the Public Certificates Secrets store.`
	pathPoliciesHelpDescription = `This path takes a secretId and attempts to perform the policy read/update operation for the secret with this secretId.` +
		"\n" + policyReadOpDesc +
		"\n" + policyUpdateOpDesc

	policyReadOpSummary = "Reads the rotation policy of a secret."
	policyReadOpDesc    = `The policy read operation receives the secretId parameter as part of the path. It returns the secret's policy.`

	policyUpdateOpSummary = "Updates the policy of a secret."
	policyUpdateOpDesc    = `The update operation receives the secretId parameter as part of the path.
It updates the secret's policy with the parameters that were provided, and returns the updated policy.`

	fieldPolicyTypeDesc = "The type of policy that is associated with the specified secret."
	fieldPoliciesDesc   = "The new policies value for the secret."
)

//activity tracker actions
const (
	atSetConfigAction    = "Set secret engine configuration"
	atGetConfigAction    = "Get secret engine configuration"
	atDeleteConfigAction = "Delete secret engine configuration"
	atGetSecretData      = "Get a certificate"
	atDeleteSecret       = "Delete a certificate"
	atGetCertMetadata    = "Get a certificate metadata"
	atUpdateCertMetadata = "Update a certificate metadata"
	atGetVersionMetadata = "Get version metadata"
	atOrderCertificate   = "Issue a new certificate"
	atListCertificates   = "List certificates"
	atRotateCertificate  = "Rotate a certificate"
	atGetSecretPolicy    = "Get secret policies"
	atSetSecretPolicy    = "Set secret policies"
)

//policies validation errors
const (
	policiesMoreThanOne       = "Received more than one policy"
	policiesNotValidStructure = "Rotation policy has not valid structure"
	policiesNotValidField     = "Field %s in rotation policy is not valid. "
)

//Order validation errors
const (
	commonNameTooLong     = "A primary domain name cannot be longer than 64 bytes"
	redundantDomain       = "At least one of the domains is redundant with a wildcard domain in the same certificate. Remove one or the other from the certificate order."
	invalidDomain         = "Domain %s is not valid"
	duplicateDomain       = "Domain %s is duplicated"
	invalidKeyAlgorithm   = "Key algorithm is not valid. The valid options are: RSA2048, RSA4096, ECDSA256, ECDSA384"
	orderAlreadyInProcess = "Order for these domains is already in process"
)

//Errors in communication with DNS providers
const (
	dnsProviderCISInstance      = "the IBM Cloud Internet Services instance"
	dnsProviderSoftLayerAccount = "the SoftLayer account"
	dnsProviderCIS              = "IBM Cloud Internet Services"
	dnsProviderSoftLayer        = "SoftLayer"

	domainIsNotFound     = "Domain %s is not found in %s"
	authorizationError   = "Authorization error when trying %s %s"
	errorResponseFromDNS = "%s responded with an error"
	unavailableDNSError  = "Couldn't call %s. Try again later"

	//specific CIS
	obtainTokenError      = "Couldn't obtain IAM token for provided ApiKey in order to access IBM Cloud Internet Services"
	obtainCRNTokenError   = "Couldn't obtain IAM S2S token in order to access IBM Cloud Internet Services"
	invalidCISInstanceCrn = "IBM Cloud Internet Services instance crn is not valid"
)

//common error
const internalServerError = "Internal server Error"
