package publiccerts

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
)

type OrdersBackend struct {
	secretBackend secret_backend.SecretBackend
	Auth          common.AuthValidator
}

func (ob *OrdersBackend) SetSecretBackend(secretBackend secret_backend.SecretBackend) {
	ob.secretBackend = secretBackend
	ob.Auth = &common.AuthValidatorImpl{}
}

func (ob *OrdersBackend) GetConcretePath() []*framework.Path {
	return framework.PathAppend(
		//pathRoles(&b),        // create + metaRead + delete
		//pathRolesList(&b),    // list
		//pathRoleMetadata(&b), // metaRead + metaUpdate
		//pathRolesDeleteCredentials(&b),
		//pathCredentials(&b), // generate credentials
		// set + get config
		ob.pathConfigCA(),
		[]*framework.Path{

			//pathConfigAuthIAM(&b),
			//pathResolveSecretGroup(),
			//pathNumberOfSecretsInGroup(),
			//common.PathUsageToken(),
			//// Make sure this stays at the end so that the valid paths are processed first.
			//common.PathInvalid(backendHelp),
		})
}
func (ob *OrdersBackend) GetSecretBackendHandler() secret_backend.SecretBackendHandler {
	return &OrdersHandler{}
}

func existenceCheck(ctx context.Context, request *logical.Request, data *framework.FieldData) (bool, error) {
	return false, nil
}

//
//func (ob *OrdersBackend) pathImportListCertificate() []*framework.Path {
//	atImportCertificate := &activity_tracker.ActivityTrackerVault{DataEvent: true, TargetResourceType: "secret", TargetTypeURI: "secrets-manager/import-certificate", Description: "Import a certificate", Action: "secrets-manager.certificate.import", Method: http.MethodPost, SecretType: secretentry.SecretTypeExternalKpi}
//	atListCertificates := &activity_tracker.ActivityTrackerVault{DataEvent: true, TargetResourceType: "secret", TargetTypeURI: "secrets-manager/list-certificates", Description: "List certificates", Action: "secrets-manager.certificate.list", Method: http.MethodGet, SecretType: secretentry.SecretTypeExternalKpi}
//
//	fields := map[string]*framework.FieldSchema{
//		secretentry.FieldName:         common.Fields[secretentry.FieldName],
//		secretentry.FieldDescription:  common.Fields[secretentry.FieldDescription],
//		secretentry.FieldLabels:       common.Fields[secretentry.FieldLabels],
//		secretentry.FieldGroupId:      common.Fields[secretentry.FieldGroupId],
//		secretentry.FieldCertificate:  common.Fields[secretentry.FieldCertificate],
//		secretentry.FieldIntermediate: common.Fields[secretentry.FieldIntermediate],
//		secretentry.FieldPrivateKey:   common.Fields[secretentry.FieldPrivateKey],
//		secretentry.FieldOffset:       common.Fields[secretentry.FieldOffset],
//		secretentry.FieldLimit:        common.Fields[secretentry.FieldLimit],
//		common.SearchText:             common.Fields[common.SearchText],
//		common.SortBy:                 common.Fields[common.SortBy],
//	}
//	operations := map[logical.Operation]framework.OperationHandler{
//		logical.CreateOperation: &framework.PathOperation{
//			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.Create, atImportCertificate),
//			Summary:     "Import a certificate.",
//			Description: "Import a certificate.",
//		},
//		logical.ReadOperation: &framework.PathOperation{
//			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.List, atListCertificates),
//			Summary:     "Lists the certificate in the external PKI Secret Store.",
//			Description: "Lists the certificate in the external PKI Secret Store.",
//		},
//	}
//	return []*framework.Path{
//		{
//			Pattern:         "secrets/?$",
//			ExistenceCheck:  existenceCheck,
//			Fields:          fields,
//			Operations:      operations,
//			HelpSynopsis:    "help",
//			HelpDescription: "help",
//		},
//		{
//			Pattern:         "secrets/groups/" + framework.GenericNameRegex(secretentry.FieldGroupId) + "/?$",
//			Fields:          fields,
//			Operations:      operations,
//			ExistenceCheck:  existenceCheck,
//			HelpSynopsis:    "help",
//			HelpDescription: "help",
//		},
//	}
//}
//func (ob *OrdersBackend) pathGetDeleteCertificate() []*framework.Path {
//	atGetCertificate := &activity_tracker.ActivityTrackerVault{DataEvent: true, TargetResourceType: "secret", TargetTypeURI: "secrets-manager/get-certificate", Description: "Get a certificate", Action: "secrets-manager.certificate.get", Method: http.MethodGet, SecretType: secretentry.SecretTypeExternalKpi}
//	atDeleteCertificate := &activity_tracker.ActivityTrackerVault{DataEvent: true, TargetResourceType: "secret", TargetTypeURI: "secrets-manager/delete-certificate", Description: "Delete a certificate", Action: "secrets-manager.certificate.delete", Method: http.MethodDelete, SecretType: secretentry.SecretTypeExternalKpi}
//
//	fields := map[string]*framework.FieldSchema{
//		secretentry.FieldId:      common.Fields[secretentry.FieldId],
//		secretentry.FieldGroupId: common.Fields[secretentry.FieldGroupId],
//	}
//
//	operations := map[logical.Operation]framework.OperationHandler{
//		logical.ReadOperation: &framework.PathOperation{
//			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.Get, atGetCertificate),
//			Summary:     "Get a certificate.",
//			Description: "Get a certificate.",
//		},
//		logical.DeleteOperation: &framework.PathOperation{
//			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.Delete, atDeleteCertificate),
//			Summary:     "Delete a certificate.",
//			Description: "Delete a certificate.",
//		},
//	}
//
//	return []*framework.Path{
//		{
//			Pattern:         "secrets/" + framework.GenericNameRegex(secretentry.FieldId),
//			ExistenceCheck:  existenceCheck,
//			Fields:          fields,
//			Operations:      operations,
//			HelpSynopsis:    "help",
//			HelpDescription: "help",
//		},
//		{
//			Pattern:         "secrets/groups/" + framework.GenericNameRegex(secretentry.FieldGroupId) + "/" + framework.GenericNameRegex(secretentry.FieldId),
//			Fields:          fields,
//			Operations:      operations,
//			ExistenceCheck:  existenceCheck,
//			HelpSynopsis:    "help",
//			HelpDescription: "help",
//		},
//	}
//}
//func (ob *OrdersBackend) pathGetUpdateCertificateMetadata() []*framework.Path {
//	atGetCertificate := &activity_tracker.ActivityTrackerVault{DataEvent: true, TargetResourceType: "secret", TargetTypeURI: "secrets-manager/secret-metadata", Description: "Get a certificate metadata", Action: "secrets-manager.certificate.get-metadata", Method: http.MethodGet, SecretType: secretentry.SecretTypeExternalKpi}
//	atUpdateCertificate := &activity_tracker.ActivityTrackerVault{DataEvent: true, TargetResourceType: "secret", TargetTypeURI: "secrets-manager/secret-metadata", Description: "Update a certificate metadata", Action: "secrets-manager.certificate.secret-metadata.update", Method: http.MethodPut, SecretType: secretentry.SecretTypeExternalKpi}
//	fields := map[string]*framework.FieldSchema{
//		secretentry.FieldId:          common.Fields[secretentry.FieldId],
//		secretentry.FieldGroupId:     common.Fields[secretentry.FieldGroupId],
//		secretentry.FieldName:        common.Fields[secretentry.FieldName],
//		secretentry.FieldDescription: common.Fields[secretentry.FieldDescription],
//		secretentry.FieldLabels:      common.Fields[secretentry.FieldLabels],
//	}
//
//	operations := map[logical.Operation]framework.OperationHandler{
//		logical.ReadOperation: &framework.PathOperation{
//			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.GetMetadata, atGetCertificate),
//			Summary:     "Get a certificate.",
//			Description: "Get a certificate.",
//		},
//		logical.UpdateOperation: &framework.PathOperation{
//			Callback:    ob.secretBackend.PathCallback(ob.secretBackend.UpdateMetadata, atUpdateCertificate),
//			Summary:     "Update a certificate metadata.",
//			Description: "Update a certificate metadata.",
//		},
//	}
//
//	return []*framework.Path{
//		{
//			Pattern:         "secrets/" + framework.GenericNameRegex(secretentry.FieldId) + "/metadata",
//			Fields:          fields,
//			Operations:      operations,
//			HelpSynopsis:    "help",
//			HelpDescription: "help",
//		},
//		{
//			Pattern:         "secrets/groups/" + framework.GenericNameRegex(secretentry.FieldGroupId) + "/" + framework.GenericNameRegex(secretentry.FieldId) + "/metadata",
//			Fields:          fields,
//			Operations:      operations,
//			HelpSynopsis:    "help",
//			HelpDescription: "help",
//		},
//	}
//}
//
//func (ob *OrdersBackend) PathReimportCertificate() {

//}
