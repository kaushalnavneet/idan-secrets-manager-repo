package publiccerts

//Errors in communication with CIS
const (
	domainIsNotFoundInCIS = "Domain %s is not found in the IBM Cloud Internet Services instance"
	authorizationErrorCIS = "Authorization error when trying %s the IBM Cloud Internet Services instance"
	errorResponseFromCIS  = "IBM Cloud Internet Services responded with an error"
	internalServerError   = "Internal server Error"
	unavailableCISError   = "Could not call IBM Cloud Internet Services API. Try again later"
)

//Validation errors
const (
	commonNameTooLong            = "A primary domain name cannot be longer than 64 bytes"
	domainCantBeConvertedToASCII = "Invalid domain %s"
	redundantDomain              = "At least one of the domains is redundant with a wildcard domain in the same certificate. Remove one or the other from the certificate order."
	invalidDomain                = "Domain %s is not valid"
	duplicateDomain              = "Domain %s is duplicated"
)

//Fields description
const (
	FieldPolicyTypeDesc = "The type of policy that is associated with the specified secret."
	FieldPoliciesDesc   = "The new policies for the secret."
)

//config operations
const (
	GetRootConfigOpSummary = "Get all the configuration values"
	GetRootConfigOpDesc    = "Get all the configuration values"
	GetRootConfigHelpSyn   = "Read the root configuration."
	GetRootConfigHelpDesc  = "Read the root configuration."
)

//api operations descriptions
const (
	VersionMetaReadOpDesc = `The versions metadata read operation receives the secretId parameter as part of the path.
It returns all of the secret's version metadata.`

	VersionReadOpDesc = `The versions read operation receives the secretId parameter as part of the path.
It returns all of the secret's version.`

	VersionOperationsHelpSyn  = `Read secrets version in the Imported certificate Secrets store.`
	VersionOperationsHelpDesc = `This path takes a secretId and attempts to perform the version read operation on the secret with this secretId.` +
		"\n" + VersionReadOpDesc

	VersionMetaOperationsHelpSyn  = `Read metadata for secrets version in the Imported certificate Secrets store.`
	VersionMetaOperationsHelpDesc = `This path takes a secretId and attempts to perform the version metadata read operation on the secret with this secretId.` +
		"\n" + VersionMetaReadOpDesc
	issueConfigSyn  = "Issue certificate."
	issueConfigDesc = "Issue certificate."
	RotateHelpSyn   = "Renew certificate"
	RotateHelpDesc  = "Renew certificate"
	ListHelpSyn     = "List certificate"
	ListHelpDesc    = "List certificate"
	ListOpDesc      = `The List operation returns the secrets that are in the Imported certificate Secrets store.
It receives the following optional parameters: labels, limit and offset.
The labels parameter can be used to apply a tag-filter on the result of the operation, returning only the secrets that
have these required labels.
The limit and offset parameters are used for pagination.`

	secretsRootHelpSyn  = `Create and List secrets in the Public c Certificates Secrets store.`
	secretsRootHelpDesc = `This path supports creating a new public certificate secret, and listing the secrets of the User Credentials Secrets store.`
)

//policies operations
const (
	policyReadOpSummary = "Reads the policy of a secret."
	policyReadOpDesc    = `The policy read operation receives the secretId parameter as part of the path.
It returns the secret's policy, in case it was defined for this secret'.`
	policyUpdateOpSummary = "Updates the policy of a secret."
	policyUpdateOpDesc    = `The update operation receives the secretId parameter as part of the path.
It updates the secret's policy with the parameters that were provided, and returns the updated policy.`
	policyOperationsHelpSyn  = `Read and update a secret's policy for secrets in the User Credentials Secrets store.`
	policyOperationsHelpDesc = `This path takes a secretId and attempts to perform the policy read/update operation for the secret with this secretId.` +
		"\n" + policyReadOpDesc +
		"\n" + policyUpdateOpDesc
)

//policies validation errors
const (
	policiesMoreThanOne       = "Received more than one policy"
	policiesNotValidStructure = "Rotation policy has not valid structure"
	policiesNotValidField     = "Field %s in rotation policy is not valid. "
)
