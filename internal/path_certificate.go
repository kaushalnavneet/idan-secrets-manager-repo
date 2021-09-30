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
		TargetTypeURI: at.SecretTargetTypeURI, Description: atGetSecretData,
		Action: common.ReadSecretAction, Method: http.MethodGet, SecretType: secretentry.SecretTypePublicCert}
	atDeleteCertificate := &at.ActivityTrackerVault{DataEvent: true, TargetResourceType: secretentry.SecretResourceName,
		TargetTypeURI: at.SecretTargetTypeURI, Description: atDeleteSecret,
		Action: common.DeleteSecretAction, Method: http.MethodDelete, SecretType: secretentry.SecretTypePublicCert}

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
			Summary:     getSecretOperationSummary,
			Description: getSecretOperationDescription,
		},
		logical.DeleteOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.Delete, atDeleteCertificate),
			Summary:     deleteSecretOperationSummary,
			Description: deleteSecretOperationDescription,
		},
	}

	return []*framework.Path{
		{
			Pattern:         PathSecrets + framework.GenericNameRegex(secretentry.FieldId),
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    pathSecretHelpSynopsis,
			HelpDescription: pathSecretHelpDescription,
		},
		{
			Pattern:         PathSecretGroups + framework.GenericNameRegex(secretentry.FieldGroupId) + "/" + framework.GenericNameRegex(secretentry.FieldId),
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    pathSecretHelpSynopsis,
			HelpDescription: pathSecretHelpDescription,
		},
	}

}

func (ob *OrdersBackend) pathGetVersion() []*framework.Path {
	atGetVersion := &at.ActivityTrackerVault{DataEvent: true, TargetResourceType: secretentry.SecretResourceName, TargetTypeURI: at.SecretTargetTypeURI,
		Description: "Get version", Action: common.ReadSecretAction, Method: http.MethodGet, SecretType: secretentry.SecretTypePublicCert}
	fields := map[string]*framework.FieldSchema{
		secretentry.FieldId:        common.Fields[secretentry.FieldId],
		secretentry.FieldGroupId:   common.Fields[secretentry.FieldGroupId],
		secretentry.FieldVersionId: common.Fields[secretentry.FieldVersionId],
	}

	operations := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.GetVersion, atGetVersion),
			Summary:     getVersionOperationSummary,
			Description: getVersionOperationDescription,
		},
	}

	return []*framework.Path{
		{
			Pattern:         PathSecrets + framework.GenericNameRegex(secretentry.FieldId) + PathVersions + framework.GenericNameRegex(secretentry.FieldVersionId),
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    pathVersionHelpSynopsis,
			HelpDescription: pathVersionHelpDescription,
		},
		{
			Pattern:         PathSecretGroups + framework.GenericNameRegex(secretentry.FieldGroupId) + "/" + framework.GenericNameRegex(secretentry.FieldId) + PathVersions + framework.GenericNameRegex(secretentry.FieldVersionId),
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    pathVersionHelpSynopsis,
			HelpDescription: pathVersionHelpDescription,
		},
	}
}

func (ob *OrdersBackend) pathCertificateMetadata() []*framework.Path {
	atGetCertificate := &at.ActivityTrackerVault{DataEvent: true, TargetResourceType: secretentry.SecretResourceName,
		TargetTypeURI: at.SecretMetadataTargetTypeURI, Description: atGetCertMetadata,
		Action: common.ReadSecretMetadataAction, Method: http.MethodGet, SecretType: secretentry.SecretTypePublicCert}
	atUpdateCertificate := &at.ActivityTrackerVault{DataEvent: true, TargetResourceType: secretentry.SecretResourceName,
		TargetTypeURI: at.SecretMetadataTargetTypeURI, Description: atUpdateCertMetadata,
		Action: common.UpdateSecretMetadataAction, Method: http.MethodPut, SecretType: secretentry.SecretTypePublicCert}

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
			Summary:     getMetadataOperationSummary,
			Description: getMetadataOperationDescription,
		},
		logical.UpdateOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.UpdateMetadata, atUpdateCertificate),
			Summary:     updateMetadataOperationSummary,
			Description: updateMetadataOperationDescription,
		},
	}

	return []*framework.Path{
		{
			Pattern:         PathSecrets + framework.GenericNameRegex(secretentry.FieldId) + PathMetadata,
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    pathMetadataHelpSynopsis,
			HelpDescription: pathMetadataHelpDescription,
		},
		{
			Pattern:         PathSecretGroups + framework.GenericNameRegex(secretentry.FieldGroupId) + "/" + framework.GenericNameRegex(secretentry.FieldId) + PathMetadata,
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    pathMetadataHelpSynopsis,
			HelpDescription: pathMetadataHelpDescription,
		},
	}

}

func (ob *OrdersBackend) pathListVersions() []*framework.Path {
	atListVersions := &at.ActivityTrackerVault{DataEvent: true, TargetResourceType: "secret", TargetTypeURI: "secrets-manager/secret",
		Description: "List versions", Action: "secrets-manager.secret.list", Method: http.MethodGet, SecretType: secretentry.SecretTypePublicCert}
	fields := map[string]*framework.FieldSchema{
		secretentry.FieldId:      common.Fields[secretentry.FieldId],
		secretentry.FieldGroupId: common.Fields[secretentry.FieldGroupId],
	}

	operations := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.ListVersions, atListVersions),
			Summary:     "Lists the versions of a secret",
			Description: listVersionsOperationDescription,
		},
	}

	return []*framework.Path{
		{
			Pattern:         PathSecrets + framework.GenericNameRegex(secretentry.FieldId) + "/versions/?$",
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    listVersionsHelpSynopsis,
			HelpDescription: listVersionsHelpDescription,
		},
		{
			Pattern:         PathSecretGroups + framework.GenericNameRegex(secretentry.FieldGroupId) + "/" + framework.GenericNameRegex(secretentry.FieldId) + "/versions/?$",
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    listVersionsHelpSynopsis,
			HelpDescription: listVersionsHelpDescription,
		},
	}
}

func (ob *OrdersBackend) pathGetVersionMetadata() []*framework.Path {
	atGetVersion := &at.ActivityTrackerVault{DataEvent: true, TargetResourceType: secretentry.SecretResourceName, TargetTypeURI: at.SecretMetadataTargetTypeURI,
		Description: atGetVersionMetadata, Action: common.ReadSecretMetadataAction, Method: http.MethodGet,
		SecretType: secretentry.SecretTypePublicCert}
	fields := map[string]*framework.FieldSchema{
		secretentry.FieldId:        common.Fields[secretentry.FieldId],
		secretentry.FieldGroupId:   common.Fields[secretentry.FieldGroupId],
		secretentry.FieldVersionId: common.Fields[secretentry.FieldVersionId],
	}

	operations := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.GetVersionMetadata, atGetVersion),
			Summary:     getVersionMetaOperationSummary,
			Description: getVersionMetaOperationDescription,
		},
	}

	return []*framework.Path{
		{
			Pattern:         PathSecrets + framework.GenericNameRegex(secretentry.FieldId) + PathVersions + framework.GenericNameRegex(secretentry.FieldVersionId) + PathMetadata,
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    pathVersionMetaHelpSynopsis,
			HelpDescription: pathVersionMetaHelpDescription,
		},
		{
			Pattern:         PathSecretGroups + framework.GenericNameRegex(secretentry.FieldGroupId) + "/" + framework.GenericNameRegex(secretentry.FieldId) + PathVersions + framework.GenericNameRegex(secretentry.FieldVersionId) + PathMetadata,
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    pathVersionMetaHelpSynopsis,
			HelpDescription: pathVersionMetaHelpDescription,
		},
	}
}
