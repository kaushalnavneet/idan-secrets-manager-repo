package publiccerts

//errors in Configs
const (
	providerTypeCA  = "Certificate authority"
	providerTypeDNS = "DNS provider"
	//this type ^ is added to the following messages
	reachedTheMaximum    = "%s configuration couldn't be added because you have reached the maximum number of configurations (%d)" //Error07002
	nameAlreadyExists    = "%s configuration with name '%s' already exists"                                                        //Error07003
	configNotFound       = "%s configuration with name '%s' was not found"                                                         //Error07006, Error07009, Error07012
	configMissingField   = "%s configuration missing property %s"                                                                  //Error07025, Error07033, Error07034, Error07018
	invalidConfigStruct  = "%s configuration of type '%s' has an invalid structure. It can contain only properties %s"             //Error07028, Error07035, Error07019
	configWrongStructure = "'config' field is not valid. It should be key-value map"                                               //Error07017
	invalidConfigType    = "Configuration type should be one of [%s]"                                                                     //Error07020
	configNameWithSpace  = "Configuration name can't contain spaces"                                                                      //Error07043

	//specific CA
	invalidKey     = "Certificate authority private key is not valid: %s"                  //Error07039, Error07041, Error07021, Error07024
	wrongCAAccount = "Failed to retrieve the certificate authority account information: %s" //Error07023
)

//policies validation errors
const (
	policiesMoreThanOne       = "Received more than one policy"                  // Error07094
	policiesNotValidStructure = "Rotation policy doesn't have a valid structure" // Error07095, Error07096, Error07097
	policiesNotValidField     = "Field %s in rotation policy is not valid"       //Error07098, Error07099
)

//Order validation errors
const (
	commonNameTooLong = "A primary domain name can't be longer than 64 bytes" //Error07106
	redundantDomain   = `At least one of the specified domains is already covered by a wildcard domain for this certificate. 
Remove the extra domain or the wildcard domain from the certificate order.`  //Error07109
	invalidDomain               = "Domain %s is not valid"                                                                  //Error07105, Error07107
	duplicateDomain             = "Domain %s is duplicated"                                                                 //Error07108
	invalidKeyAlgorithm         = "Key algorithm is not valid. The valid options are: RSA2048, RSA4096, ECDSA256, ECDSA384" //Error07040
	orderAlreadyInProcess       = "A certificate order for these domains is already in process."                            //Error07042
	secretShouldBeInActiveState = "Secret should be in the Active state"                                                    //Error07062
)

//Errors in communication with DNS providers
const (
	dnsProviderCISInstance      = "the Cloud Internet Services (CIS) instance"
	dnsProviderSoftLayerAccount = "the classic infrastructure (SoftLayer) account"
	dnsProviderCIS              = "Cloud Internet Services (CIS)"
	dnsProviderSoftLayer        = "Classic infrastructure (SoftLayer)"

	domainIsNotFound     = "Domain %s is not found in %s"          //Error07072, Error07052
	authorizationError   = "Authorization error when trying %s %s" //Error07073, Error07077, Error07080, Error07089, Error07031, Error07044, Error07048, Error07051, Error07056, Error07037
	errorResponseFromDNS = "%s responded with an error"            //Error07074, Error07078, Error07081, Error07060, Error07032, Error07045, Error07049, Error07053, Error07057, Error07038
	unavailableDNSError  = "Couldn't call %s. Try again later"     //Error07030, Error07036, Error07047, Error07050, Error07054, Error07058, Error07071, Error07076, Error07079, Error07087

	//specific CIS
	obtainTokenError      = "Couldn't obtain IAM token for provided API key in order to access Cloud Internet Services (CIS)"   // Error07070, Error07082, Error07084, Error07086, Error07029
	obtainCRNTokenError   = "Couldn't obtain IAM service to service CRN token in order to access Cloud Internet Services (CIS)" // Error07070, Error07082, Error07084, Error07086, Error07029
	invalidCISInstanceCrn = "Cloud Internet Services (CIS) instance CRN is not valid"                                           //Error07026, Error07027
)

//info messages
const (
	configCreated = "%s configuration with name '%s' has been created"
	configUpdated = "%s configuration with name '%s' has been updated"
	configDeleted = "%s configuration with name '%s' has been deleted"
)

//config fields description
const (
	fieldConfigNameDescription     = "The configuration name"
	fieldConfigTypeDescription     = "The configuration type"
	fieldConfigSettingsDescription = "The set of configuration properties"
)

// Certificate Authorities config create and list path
const (
	pathCAConfigHelpSynopsis    = "Create and the list certificate authority configuration"
	pathCAConfigHelpDescription = `This path supports creating a new certificate authority configuration, 
and listing the existing certificate authority configurations of the public certificate secrets store.`

	listCAConfigOperationSummary     = "List certificate authority configurations"
	listCAConfigOperationDescription = `The list operation returns the certificate authority configurations that are in the Public certificate Secrets store.`

	createCAConfigOperationSummary     = "Create a certificate authority configuration"
	createCAConfigOperationDescription = `The create operation creates a new certificate authority configuration. The following parameters are used to create a new configuration:
name (required), type (required), config (required).
The created config is returned in the response.`
)

// Certificate Authorities config  get update delete path
const (
	pathCAConfigWithNameHelpSynopsis    = "Read, update, and delete a certificate authority configuration"
	pathCAConfigWithNameHelpDescription = `This path takes the config name and attempts to read, update, and delete the certificate authority configuration.`

	getCAConfigOperationSummary     = "Read the certificate authority configuration"
	getCAConfigOperationDescription = `The read operation receives the config name parameter as part of the path.
It returns the certificate authority configuration.`

	updateCAConfigOperationSummary     = "Update the certificate authority configuration"
	updateCAConfigOperationDescription = `The update operation receives the config name parameter as part of the path and the new payload as a required parameter.
It updates the certificate authority configuration, and returns the updated configuration.`

	deleteCAConfigOperationSummary     = "Delete the certificate authority configuration"
	deleteCAConfigOperationDescription = `The delete operation receives the config name parameter as part of the path.
It deletes the configuration with the given name.`
)

// DNS provider config create and list path
const (
	pathDNSConfigHelpSynopsis    = "Create and list the DNS provider configuration"
	pathDNSConfigHelpDescription = `This path supports creating a new DNS provider configuration, 
and listing the existing DNS provider configuration of the public certificates secrets store.`

	listDNSConfigOperationSummary     = "List DNS provider configurations"
	listDNSConfigOperationDescription = `The list operation returns the DNS provider configurations that are in the public certificate secrets store.`

	createDNSConfigOperationSummary     = "Create a DNS provider configuration"
	createDNSConfigOperationDescription = `The create operation creates a new DNS provider configuration. The following parameters are used to create a new configuration:
name (required), type (required), config (required).
The created config is returned in the response.`
)

// DNS provider config  get update delete path
const (
	pathDNSConfigWithNameHelpSynopsis    = "Read, update, and delete the DNS provider configuration"
	pathDNSConfigWithNameHelpDescription = `This path takes the config name and attempts to read, udpate, and delete the DNS provider configuration.`

	getDNSConfigOperationSummary     = "Read the DNS provider configuration"
	getDNSConfigOperationDescription = `The read operation receives the config name parameter as part of the path.
It returns the DNS provider configuration.`

	updateDNSConfigOperationSummary     = "Update the DNS provider configuration"
	updateDNSConfigOperationDescription = `The update operation receives the config name parameter as part of the path and the new payload as a required parameter.
It updates the DNS provider configuration, and returns the updated configuration.`

	deleteDNSConfigOperationSummary     = "Delete the DNS provider configuration"
	deleteDNSConfigOperationDescription = `The delete operation receives the config name parameter as part of the path.
It deletes the configuration with the given name.`
)

// Root config get path
const (
	pathRootConfigHelpSynopsis    = "Read the root configuration"
	pathRootConfigHelpDescription = `This path supports listing all of the existing DNS provider and certificate authority configurations of the public certificate secrets store.`

	getRootConfigOperationSummary     = "Get all of the configuration values"
	getRootConfigOperationDescription = `The list operation returns all DNS provider and certificate authority configurations of the public certificate secrets store.`
)

//path get / delete secret
const (
	pathSecretHelpSynopsis    = "Get and delete a certificate"
	pathSecretHelpDescription = `This path supports retrieving a certificate and deleting certificate data.`

	getSecretOperationSummary     = "Get a certificate"
	getSecretOperationDescription = `The get operation returns the secret data that is associated with the certificate.`

	deleteSecretOperationSummary     = "Delete a certificate"
	deleteSecretOperationDescription = `The delete operation receives the secretId parameter as part of the path.
	It deletes the certificate with the given secretId.`
)

//path get version
const (
	pathVersionHelpSynopsis    = `Read secrets version in the public certificate secrets store.`
	pathVersionHelpDescription = `This path takes a secretId and attempts to perform the version read operation on the secret with this secretId.` +
		"\n" + getVersionOperationDescription

	getVersionOperationSummary     = "Read a version of a secret"
	getVersionOperationDescription = `The versions read operation receives the secretId parameter as part of the path.
It returns all of the secret's version.`
)

// path get / update metadata
const (
	pathMetadataHelpSynopsis    = "Get and update certificate metadata"
	pathMetadataHelpDescription = `This path supports get certificate metadata and update certificate name, description or labels.`

	getMetadataOperationSummary     = "Get certificate metadata"
	getMetadataOperationDescription = `The get operation returns the metadata that is associated with the certificate.`

	updateMetadataOperationSummary     = "Update certificate metadata"
	updateMetadataOperationDescription = "The update operation updates the name, description, or labels that are associated with a certificate."
)

// path get version metadata
const (
	pathVersionMetaHelpSynopsis    = `Read metadata for secrets version in the public certificate secrets store.`
	pathVersionMetaHelpDescription = `This path takes a secretId and attempts to perform the version metadata read operation on the secret with this secretId.` +
		"\n" + getVersionMetaOperationDescription

	getVersionMetaOperationSummary     = "Reads a version metadata of a secret"
	getVersionMetaOperationDescription = `The versions metadata read operation receives the secretId parameter as part of the path.
It returns all of the secret's version metadata.`
)

//path issue and list certificates
const (
	pathIssueListHelpSynopsis    = `Create and list secrets in the public certificates secrets store.`
	pathIssueListHelpDescription = `This path supports creating a new public certificate secret, and listing the secrets of the public certificate secrets store.`

	issueCertOperationSummary     = "Issue a certificate"
	issueCertOperationDescription = "Issue a certificate"

	listCertsOperationSummary      = "List certificates"
	lListCertsOperationDescription = `The list operation returns the secrets that are in the public certificate secrets store.
It receives the following optional parameters: labels, limit, and offset.
The labels parameter can be used to apply a tag-filter on the result of the operation, returning only the secrets that
have these required labels.
The limit and offset parameters are used for pagination.`

	fieldCAConfigDescription          = "The certificate authority configuration name."
	fieldDNSProviderConfigDescription = "The DNS provider configuration name."
	fieldCommonNameDescription        = "The certificate Common Name (main domain)."
	fieldAltNamesDescription          = "The certificate Subject Alternative Names (additional domains)."
	fieldBundleCertDescription        = "Set to `true` to bundle the issuer certificate with the public certificate (full chain cert file). Default value true"
	fieldKeyAlgorithmDescription      = "The certificate key algorithm. Default value RSA2048"
	fieldRotationDescription          = `The set of rotation settings. Default value {"auto_rotate":false, "rotate_keys":false}`
)

//path  Rotate certificate
const (
	pathRotateHelpSynopsis    = "Renew a certificate"
	pathRotateHelpDescription = "This path takes a secretId and attempts to perform a rotate operation on the secret with this secretId."

	rotateOperationSummary     = "Rotate a certificate"
	rotateOperationDescription = "This operation rotates the secret data that is associated with the given certifcate."

	fieldRotateKeyDescription = "Specify if a private key should be rotated."
)

//policies operations
const (
	pathPoliciesHelpSynopsis    = `Read and update the policy of a secret in the public certificates secrets store.`
	pathPoliciesHelpDescription = `This path takes a secretId and attempts to perform the policy read/update operation for the secret with this secretId.` +
		"\n" + policyReadOpDesc +
		"\n" + policyUpdateOpDesc

	policyReadOpSummary = "Read the rotation policy of a secret"
	policyReadOpDesc    = `The policy read operation receives the secretId parameter as part of the path. It returns the secret's policy.`

	policyUpdateOpSummary = "Update the rotation policy of a secret"
	policyUpdateOpDesc    = `The update operation receives the secretId parameter as part of the path.
It updates the secret's policy with the parameters that were provided, and returns the updated policy.`

	fieldPolicyTypeDesc = "The type of policy that is associated with the specified secret."
	fieldPoliciesDesc   = "The new policies value for the secret."
)

//activity tracker actions
const (
	atSetConfigAction    = "Set secrets engine configuration"
	atGetConfigAction    = "Get secrets engine configuration"
	atDeleteConfigAction = "Delete secrets engine configuration"
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

//common error
const internalServerError = "Internal server error. Your request couldn't be processed. If the issue persists, note the correlation-id in the response header and contact IBM Cloud support."
