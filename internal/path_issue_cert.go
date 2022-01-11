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

func (ob *OrdersBackend) pathIssueCert() []*framework.Path {
	atSecretCreate := &at.ActivityTrackerVault{DataEvent: true, TargetTypeURI: at.SecretTargetTypeURI,
		Description: atOrderCertificate, Action: common.CreateSecretAction, SecretType: secretentry.SecretTypePublicCert,
		TargetResourceType: secretentry.SecretResourceName}
	atSecretList := &at.ActivityTrackerVault{DataEvent: true, TargetTypeURI: at.SecretTargetTypeURI,
		Description: atListCertificates, Action: common.ListSecretsAction, SecretType: secretentry.SecretTypePublicCert,
		TargetResourceType: secretentry.SecretResourceName}

	fields := map[string]*framework.FieldSchema{
		secretentry.FieldName:        common.Fields[secretentry.FieldName],
		secretentry.FieldDescription: common.Fields[secretentry.FieldDescription],
		secretentry.FieldLabels:      common.Fields[secretentry.FieldLabels],
		secretentry.FieldGroupId:     common.Fields[secretentry.FieldGroupId],
		FieldCAConfig: {
			Type:        framework.TypeString,
			Description: fieldCAConfigDescription,
			Required:    true,
		},
		FieldDNSConfig: {
			Type:        framework.TypeString,
			Description: fieldDNSProviderConfigDescription,
			Required:    true,
		},
		secretentry.FieldCommonName: {
			Type:        framework.TypeString,
			Description: fieldCommonNameDescription,
			Required:    true,
		},
		secretentry.FieldAltNames: {
			Type:        framework.TypeCommaStringSlice,
			Description: fieldAltNamesDescription,
			Required:    false,
			Default:     []string{},
		},
		FieldBundleCert: {
			Type:        framework.TypeBool,
			Description: fieldBundleCertDescription,
			Default:     true,
		},
		secretentry.FieldKeyAlgorithm: {
			Type:        framework.TypeString,
			Description: fieldKeyAlgorithmDescription,
			Required:    false,
			Default:     "RSA2048",
		},
		FieldRotation: {
			Type:        framework.TypeMap,
			Description: fieldRotationDescription,
			Required:    false,
			Default:     map[string]interface{}{policies.FieldAutoRotate: false, policies.FieldRotateKeys: false},
		},
		secretentry.FieldOffset: common.Fields[secretentry.FieldOffset],
		secretentry.FieldLimit:  common.Fields[secretentry.FieldLimit],
		common.SearchText:       common.Fields[common.SearchText],
		common.SortBy:           common.Fields[common.SortBy],
		secretentry.FieldGroups: common.Fields[secretentry.FieldGroups],
	}

	operations := map[logical.Operation]framework.OperationHandler{
		logical.CreateOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.Create, atSecretCreate),
			Summary:     issueCertOperationSummary,
			Description: issueCertOperationDescription,
		},
		logical.ReadOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.List, atSecretList),
			Summary:     listCertsOperationSummary,
			Description: lListCertsOperationDescription,
		},
	}

	return []*framework.Path{
		{
			Pattern:         "secrets/?$",
			Fields:          fields,
			ExistenceCheck:  existenceCheck,
			Operations:      operations,
			HelpSynopsis:    pathIssueListHelpSynopsis,
			HelpDescription: pathIssueListHelpDescription,
		},
		{
			Pattern:         PathSecretGroups + framework.GenericNameRegex(secretentry.FieldGroupId) + "/?$",
			Fields:          fields,
			Operations:      operations,
			ExistenceCheck:  existenceCheck,
			HelpSynopsis:    pathIssueListHelpSynopsis,
			HelpDescription: pathIssueListHelpDescription,
		},
	}
}

func (ob *OrdersBackend) pathRotateCertificate() []*framework.Path {
	atRotateCertificate := &at.ActivityTrackerVault{DataEvent: true, TargetResourceType: secretentry.SecretResourceName,
		TargetTypeURI: at.SecretTargetTypeURI, Description: atRotateCertificate,
		Action: common.RotateSecretAction, Method: http.MethodPost, SecretType: secretentry.SecretTypePublicCert}

	fields := map[string]*framework.FieldSchema{
		secretentry.FieldId:      common.Fields[secretentry.FieldId],
		secretentry.FieldGroupId: common.Fields[secretentry.FieldGroupId],
		policies.FieldRotateKeys: {
			Type:        framework.TypeBool,
			Description: fieldRotateKeyDescription,
			Required:    true,
			Default:     false,
		},
	}

	operations := map[logical.Operation]framework.OperationHandler{
		logical.UpdateOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.Rotate, atRotateCertificate),
			Summary:     rotateOperationSummary,
			Description: rotateOperationDescription,
		},
	}

	return []*framework.Path{
		{
			Pattern:         PathSecrets + framework.GenericNameRegex(secretentry.FieldId) + PathRotate,
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    pathRotateHelpSynopsis,
			HelpDescription: pathRotateHelpDescription,
		},
		{
			Pattern:         PathSecretGroups + framework.GenericNameRegex(secretentry.FieldGroupId) + "/" + framework.GenericNameRegex(secretentry.FieldId) + "/rotate",
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    pathRotateHelpSynopsis,
			HelpDescription: pathRotateHelpDescription,
		},
	}
}
