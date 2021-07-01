package publiccerts

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	at "github.ibm.com/security-services/secrets-manager-vault-plugins-common/activity_tracker"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"net/http"
)

func (ob *OrdersBackend) pathCertificate() []*framework.Path {
	atGetCertificate := &at.ActivityTrackerVault{DataEvent: true, TargetResourceType: secretentry.SecretResourceName,
		TargetTypeURI: at.SecretTargetTypeURI, Description: "Get a certificate",
		Action: common.ReadSecretAction, Method: http.MethodGet, SecretType: SecretTypePublicCert}
	atDeleteCertificate := &at.ActivityTrackerVault{DataEvent: true, TargetResourceType: secretentry.SecretResourceName,
		TargetTypeURI: at.SecretTargetTypeURI, Description: "Delete a certificate",
		Action: common.DeleteSecretAction, Method: http.MethodDelete, SecretType: SecretTypePublicCert}

	fields := map[string]*framework.FieldSchema{
		secretentry.FieldId:          common.Fields[secretentry.FieldId],
		secretentry.FieldGroupId:     common.Fields[secretentry.FieldGroupId],
		secretentry.FieldName:        common.Fields[secretentry.FieldName],
		secretentry.FieldDescription: common.Fields[secretentry.FieldDescription],
		secretentry.FieldLabels:      common.Fields[secretentry.FieldLabels],
	}

	operations := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.Get, atGetCertificate),
			Summary:     "Get a certificate.",
			Description: "Get a certificate.",
		},
		logical.DeleteOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.Delete, atDeleteCertificate),
			Summary:     "Delete a certificate.",
			Description: "Delete a certificate.",
		},
	}

	return []*framework.Path{
		{
			Pattern:         "secrets/" + framework.GenericNameRegex(secretentry.FieldId),
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    "help",
			HelpDescription: "help",
		},
	}

}

func (ob *OrdersBackend) pathGetVersion() []*framework.Path {
	atGetVersion := &at.ActivityTrackerVault{DataEvent: true, TargetResourceType: secretentry.SecretResourceName, TargetTypeURI: at.SecretTargetTypeURI,
		Description: "Get version", Action: common.ReadSecretAction, Method: http.MethodGet, SecretType: SecretTypePublicCert}
	fields := map[string]*framework.FieldSchema{
		secretentry.FieldId:        common.Fields[secretentry.FieldId],
		secretentry.FieldGroupId:   common.Fields[secretentry.FieldGroupId],
		secretentry.FieldVersionId: common.Fields[secretentry.FieldVersionId],
	}

	operations := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.GetVersion, atGetVersion),
			Summary:     "Reads a version of a secret",
			Description: VersionReadOpDesc,
		},
	}

	return []*framework.Path{
		{
			Pattern:         "secrets/" + framework.GenericNameRegex(secretentry.FieldId) + "/versions/" + framework.GenericNameRegex(secretentry.FieldVersionId),
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    VersionOperationsHelpSyn,
			HelpDescription: VersionOperationsHelpDesc,
		},
		{
			Pattern:         "secrets/groups/" + framework.GenericNameRegex(secretentry.FieldGroupId) + "/" + framework.GenericNameRegex(secretentry.FieldId) + "/versions/" + framework.GenericNameRegex(secretentry.FieldVersionId),
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    VersionOperationsHelpSyn,
			HelpDescription: VersionOperationsHelpDesc,
		},
	}
}

func (ob *OrdersBackend) pathCertificateMetadata() []*framework.Path {
	atGetCertificate := &at.ActivityTrackerVault{DataEvent: true, TargetResourceType: secretentry.SecretResourceName,
		TargetTypeURI: SecretMetadataTargetTypeURI, Description: "Get a certificate metadata",
		Action: common.ReadSecretMetadataAction, Method: http.MethodGet, SecretType: SecretTypePublicCert}
	atUpdateCertificate := &at.ActivityTrackerVault{DataEvent: true, TargetResourceType: secretentry.SecretResourceName,
		TargetTypeURI: SecretMetadataTargetTypeURI, Description: "Update a certificate metadata",
		Action: common.UpdateSecretMetadataAction, Method: http.MethodPut, SecretType: SecretTypePublicCert}
	fields := map[string]*framework.FieldSchema{
		secretentry.FieldId:          common.Fields[secretentry.FieldId],
		secretentry.FieldGroupId:     common.Fields[secretentry.FieldGroupId],
		secretentry.FieldName:        common.Fields[secretentry.FieldName],
		secretentry.FieldDescription: common.Fields[secretentry.FieldDescription],
		secretentry.FieldLabels:      common.Fields[secretentry.FieldLabels],
	}

	operations := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.GetMetadata, atGetCertificate),
			Summary:     "Get a certificate metadata.",
			Description: "Get a certificate metadata.",
		},
		logical.UpdateOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.UpdateMetadata, atUpdateCertificate),
			Summary:     "Update a certificate metadata.",
			Description: "Update a certificate metadata.",
		},
	}

	return []*framework.Path{
		{
			Pattern:         "secrets/" + framework.GenericNameRegex(secretentry.FieldId) + "/metadata",
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    "help",
			HelpDescription: "help",
		},
		{
			Pattern:         "secrets/groups/" + framework.GenericNameRegex(secretentry.FieldGroupId) + "/" + framework.GenericNameRegex(secretentry.FieldId) + "/metadata",
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    "help",
			HelpDescription: "help",
		},
	}

}

func (ob *OrdersBackend) pathGetVersionMetadata() []*framework.Path {
	atGetVersion := &at.ActivityTrackerVault{DataEvent: true, TargetResourceType: secretentry.SecretResourceName, TargetTypeURI: SecretMetadataTargetTypeURI,
		Description: "Get version metadata", Action: common.ReadSecretMetadataAction, Method: http.MethodGet,
		SecretType: SecretTypePublicCert}
	fields := map[string]*framework.FieldSchema{
		secretentry.FieldId:        common.Fields[secretentry.FieldId],
		secretentry.FieldGroupId:   common.Fields[secretentry.FieldGroupId],
		secretentry.FieldVersionId: common.Fields[secretentry.FieldVersionId],
	}

	operations := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.GetVersionMetadata, atGetVersion),
			Summary:     "Reads a version metadata of a secret",
			Description: VersionMetaReadOpDesc,
		},
	}

	return []*framework.Path{
		{
			Pattern:         "secrets/" + framework.GenericNameRegex(secretentry.FieldId) + "/versions/" + framework.GenericNameRegex(secretentry.FieldVersionId) + "/metadata",
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    VersionMetaOperationsHelpSyn,
			HelpDescription: VersionMetaOperationsHelpDesc,
		},
		{
			Pattern:         "secrets/groups/" + framework.GenericNameRegex(secretentry.FieldGroupId) + "/" + framework.GenericNameRegex(secretentry.FieldId) + "/versions/" + framework.GenericNameRegex(secretentry.FieldVersionId) + "/metadata",
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    VersionMetaOperationsHelpSyn,
			HelpDescription: VersionMetaOperationsHelpDesc,
		},
	}
}
