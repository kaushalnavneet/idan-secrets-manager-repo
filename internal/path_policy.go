package publiccerts

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	at "github.ibm.com/security-services/secrets-manager-vault-plugins-common/activity_tracker"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry/policies"
	"net/http"
)

func (ob *OrdersBackend) pathSecretPolicies() []*framework.Path {
	atReadSecretPolicies := &at.ActivityTrackerVault{DataEvent: false, TargetResourceType: secretentry.SecretResourceName,
		TargetTypeURI: "secrets-manager/secret-policies", Description: "Get secret policies",
		Action: common.GetSecretPoliciesAction, Method: http.MethodGet, SecretType: secretentry.SecretTypePublicCert}
	atUpdateSecretPolicies := &at.ActivityTrackerVault{DataEvent: false, TargetResourceType: secretentry.SecretResourceName,
		TargetTypeURI: "secrets-manager/secret-policies", Description: "Set secret policies",
		Action: common.SetSecretPoliciesAction, Method: http.MethodPut, SecretType: secretentry.SecretTypePublicCert}
	fields := map[string]*framework.FieldSchema{
		secretentry.FieldId:      common.Fields[secretentry.FieldId],
		secretentry.FieldGroupId: common.Fields[secretentry.FieldGroupId],
		policies.FieldPolicy: {
			Type:          framework.TypeString,
			Description:   "The type of policy that is associated with the specified secret.",
			Required:      false,
			Query:         true,
			AllowedValues: ob.GetSecretBackendHandler().GetPolicyHandler().AllowedPolicyTypes(),
		},
		policies.FieldPolicies: {
			Type:        framework.TypeSlice,
			Description: "The new policies for the secret.",
			Required:    true,
		},
	}
	operations := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.GetPolicies, atReadSecretPolicies),
			Summary:     "Reads the policy of a secret.",
			Description: policyReadOpDesc,
		},
		logical.UpdateOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.UpdatePolicies, atUpdateSecretPolicies),
			Summary:     "Updates the policy of a secret.",
			Description: policyUpdateOpDesc,
		},
	}
	return []*framework.Path{
		{
			Pattern:         "secrets/" + framework.GenericNameRegex(secretentry.FieldId) + "/policies",
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    policyOperationsHelpSyn,
			HelpDescription: policyOperationsHelpDesc,
		},
		{
			Pattern:         "secrets/groups/" + framework.GenericNameRegex(secretentry.FieldGroupId) + "/" + framework.GenericNameRegex(secretentry.FieldId) + "/policies",
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    policyOperationsHelpSyn,
			HelpDescription: policyOperationsHelpDesc,
		},
	}
}

const policyReadOpDesc = `The policy read operation receives the secretId parameter as part of the path.
It returns the secret's policy, in case it was defined for this secret'.`
const policyUpdateOpDesc = `The update operation receives the secretId parameter as part of the path.
It updates the secret's policy with the parameters that were provided, and returns the updated policy.`

const policyOperationsHelpSyn = `Read and update a secret's policy for secrets in the User Credentials Secrets store.`
const policyOperationsHelpDesc = `This path takes a secretId and attempts to perform the policy read/update operation for the secret with this secretId.` +
	"\n" + policyReadOpDesc +
	"\n" + policyUpdateOpDesc
