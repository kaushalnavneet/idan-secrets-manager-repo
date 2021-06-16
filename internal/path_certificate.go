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
	atGetCertificate := &at.ActivityTrackerVault{DataEvent: true, TargetResourceType: "secret",
		TargetTypeURI: "secrets-manager/secret", Description: "Get a certificate",
		Action: "secrets-manager.certificate.get", Method: http.MethodGet, SecretType: SecretTypePublicCert}
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
