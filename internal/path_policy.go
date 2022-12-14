package publiccerts

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-common-utils/secret_metadata_entry/policies"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	at "github.ibm.com/security-services/secrets-manager-vault-plugins-common/activity_tracker"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"net/http"
)

func (ob *OrdersBackend) pathSecretPolicies() []*framework.Path {
	atReadSecretPolicies := &at.ActivityTrackerVault{DataEvent: false, TargetResourceType: secretentry.SecretResourceName,
		TargetTypeURI: "secrets-manager/secret-policies", Description: atGetSecretPolicy,
		Action: common.GetSecretPoliciesAction, Method: http.MethodGet, SecretType: secretentry.SecretTypePublicCert}
	atUpdateSecretPolicies := &at.ActivityTrackerVault{DataEvent: false, TargetResourceType: secretentry.SecretResourceName,
		TargetTypeURI: "secrets-manager/secret-policies", Description: atSetSecretPolicy,
		Action: common.SetSecretPoliciesAction, Method: http.MethodPut, SecretType: secretentry.SecretTypePublicCert}
	fields := map[string]*framework.FieldSchema{
		secretentry.FieldId:      common.Fields[secretentry.FieldId],
		secretentry.FieldGroupId: common.Fields[secretentry.FieldGroupId],
		policies.FieldPolicy: {
			Type:          framework.TypeString,
			Description:   fieldPolicyTypeDesc,
			Required:      false,
			Query:         true,
			AllowedValues: ob.GetSecretBackendHandler().GetPolicyHandler().AllowedPolicyTypes(),
		},
		policies.FieldPolicies: {
			Type:        framework.TypeSlice,
			Description: fieldPoliciesDesc,
			Required:    true,
		},
	}
	operations := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.GetPolicies, atReadSecretPolicies, true),
			Summary:     policyReadOpSummary,
			Description: policyReadOpDesc,
		},
		logical.UpdateOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.UpdatePolicies, atUpdateSecretPolicies, false),
			Summary:     policyUpdateOpSummary,
			Description: policyUpdateOpDesc,
		},
	}
	return []*framework.Path{
		{
			Pattern:         PathSecrets + framework.GenericNameRegex(secretentry.FieldId) + "/policies",
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    pathPoliciesHelpSynopsis,
			HelpDescription: pathPoliciesHelpDescription,
		},
		{
			Pattern:         PathSecretGroups + framework.GenericNameRegex(secretentry.FieldGroupId) + "/" + framework.GenericNameRegex(secretentry.FieldId) + "/policies",
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    pathPoliciesHelpSynopsis,
			HelpDescription: pathPoliciesHelpDescription,
		},
	}
}
