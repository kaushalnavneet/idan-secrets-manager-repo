package publiccerts

//errors in Configs
const (
	providerTypeCA  = "Certificate Authority"
	providerTypeDNS = "DNS Provider"
	//this type ^ is added to the following messages
	reachedTheMaximum    = "%s configuration couldn't be added because you have reached the maximum number of configurations (%d)" //Error07002
	nameAlreadyExists    = "%s configuration with name '%s' already exists"                                                        //Error07003
	configNotFound       = "%s configuration with name '%s' was not found"                                                         //Error07006, Error07009, Error07012
	configMissingField   = "%s configuration missing property %s"                                                                  //Error07025, Error07033, Error07034, Error07018
	invalidConfigStruct  = "%s configuration of type '%s' has a wrong structure. It may contain only properties %s"                //Error07028, Error07035, Error07019
	configWrongStructure = "'config' field is not valid. It should be key-value map"                                               //Error07017
	invalidConfigType    = "Config type should be one of [%s]"                                                                     //Error07020
	configNameWithSpace  = "Config name mustn't contain spaces"                                                                    //Error07043

	//specific CA
	invalidKey     = "Certificate Authority Private Key is not valid : %s"                  //Error07039, Error07041, Error07021, Error07024
	wrongCAAccount = "Failed to retrieve the Certificate Authority account information: %s" //Error07023
)

//policies validation errors
const (
	policiesMoreThanOne       = "Received more than one policy"            // Error07094
	policiesNotValidStructure = "Rotation policy has not valid structure"  // Error07095, Error07096, Error07097
	policiesNotValidField     = "Field %s in rotation policy is not valid" //Error07098, Error07099
)

//Order validation errors
const (
	commonNameTooLong     = "A primary domain name cannot be longer than 64 bytes"                                                                                         //Error07106
	redundantDomain       = "At least one of the domains is redundant with a wildcard domain in the same certificate. Remove one or the other from the certificate order." //Error07109
	invalidDomain         = "Domain %s is not valid"                                                                                                                       //Error07105, Error07107
	duplicateDomain       = "Domain %s is duplicated"                                                                                                                      //Error07108
	invalidKeyAlgorithm   = "Key algorithm is not valid. The valid options are: RSA2048, RSA4096, ECDSA256, ECDSA384"                                                      //Error07040
	orderAlreadyInProcess = "Order for these domains is already in process"                                                                                                //Error07042
)

//Errors in communication with DNS providers
const (
	dnsProviderCISInstance      = "the IBM Cloud Internet Services instance"
	dnsProviderSoftLayerAccount = "the SoftLayer account"
	dnsProviderCIS              = "IBM Cloud Internet Services"
	dnsProviderSoftLayer        = "SoftLayer"

	domainIsNotFound     = "Domain %s is not found in %s"          //Error07072, Error07052
	authorizationError   = "Authorization error when trying %s %s" //Error07073, Error07077, Error07080, Error07089, Error07031, Error07044, Error07048, Error07051, Error07056, Error07037
	errorResponseFromDNS = "%s responded with an error"            //Error07074, Error07078, Error07081, Error07060, Error07032, Error07045, Error07049, Error07053, Error07057, Error07038
	unavailableDNSError  = "Couldn't call %s. Try again later"     //Error07030, Error07036, Error07047, Error07050, Error07054, Error07058, Error07071, Error07076, Error07079, Error07087

	//specific CIS
	obtainTokenError      = "Couldn't obtain IAM token for provided ApiKey in order to access IBM Cloud Internet Services" // Error07070, Error07082, Error07084, Error07086, Error07029
	obtainCRNTokenError   = "Couldn't obtain IAM S2S token in order to access IBM Cloud Internet Services"                 // Error07070, Error07082, Error07084, Error07086, Error07029
	invalidCISInstanceCrn = "IBM Cloud Internet Services instance crn is not valid"                                        //Error07026, Error07027
)

//info messages
const (
	configCreated = "%s configuration with name '%s' has been created"
	configUpdated = "%s configuration with name '%s' has been updated"
	configDeleted = "%s configuration with name '%s' has been deleted"
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

//common error
const internalServerError = "Internal server Error"
