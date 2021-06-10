package publiccerts

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	at "github.ibm.com/security-services/secrets-manager-vault-plugins-common/activity_tracker"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"net/http"
)

func (ob *OrdersBackend) pathCertificateMetadata() []*framework.Path {
	atGetCertificate := &at.ActivityTrackerVault{DataEvent: true, TargetResourceType: "secret",
		TargetTypeURI: "secrets-manager/secret-metadata", Description: "Get a certificate metadata",
		Action: "secrets-manager.certificate.get-metadata", Method: http.MethodGet, SecretType: SecretTypePublicCert}
	atUpdateCertificate := &at.ActivityTrackerVault{DataEvent: true, TargetResourceType: "secret",
		TargetTypeURI: "secrets-manager/secret-metadata", Description: "Update a certificate metadata",
		Action: "secrets-manager.certificate.secret-metadata.update", Method: http.MethodPut, SecretType: SecretTypePublicCert}
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
