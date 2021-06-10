package publiccerts

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	at "github.ibm.com/security-services/secrets-manager-vault-plugins-common/activity_tracker"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
)

func (ob *OrdersBackend) pathIssueCert() []*framework.Path {
	atSecretConfigCreate := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: "secrets-manager/secret",
		Description: "Issue a new certificate", Action: common.CreateSecretAction, SecretType: SecretTypePublicCert, TargetResourceType: "secret"}

	fields := map[string]*framework.FieldSchema{
		secretentry.FieldName:        common.Fields[secretentry.FieldName],
		secretentry.FieldDescription: common.Fields[secretentry.FieldDescription],
		secretentry.FieldLabels:      common.Fields[secretentry.FieldLabels],
		secretentry.FieldGroupId:     common.Fields[secretentry.FieldGroupId],

		FieldCAConfig: {
			Type:        framework.TypeString,
			Description: "Specifies the certificate authority configuration name.",
			Required:    true,
		},
		FieldDNSConfig: {
			Type:        framework.TypeString,
			Description: "Specifies the DNS provider configuration name.",
			Required:    true,
		},
		secretentry.FieldCommonName: {
			Type:        framework.TypeString,
			Description: "Specifies the certificate Common Name (main domain).",
			Required:    true,
		},
		secretentry.FieldAltNames: {
			Type:        framework.TypeCommaStringSlice,
			Description: "Specifies the certificate Alt Names (additional domains).",
			Required:    false,
			Default:     []string{},
		},
		FieldBundleCert: {
			Type:        framework.TypeBool,
			Description: "Set to `true` to bundle the issuer certificate with the public certificate (fullchain cert file)..",
			Default:     false,
		},
		secretentry.FieldAlgorithm: {
			Type:        framework.TypeString,
			Description: "Specifies the certificate algorithm.",
			Required:    false,
			Default:     "sha256WithRSAEncryption",
		},
		secretentry.FieldKeyAlgorithm: {
			Type:        framework.TypeString,
			Description: "Specifies the certificate key algorithm.",
			Required:    false,
			Default:     "rsaEncryption 2048 bit",
		},
		//TODO add rotation policy
	}
	operations := map[logical.Operation]framework.OperationHandler{
		logical.CreateOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.secretBackend.Create, atSecretConfigCreate),
			Summary:  "Issue a certificate",
		},
	}

	return []*framework.Path{
		{
			Pattern:         IssuePath,
			Fields:          fields,
			ExistenceCheck:  existenceCheck,
			Operations:      operations,
			HelpSynopsis:    issueConfigSyn,
			HelpDescription: issueConfigDesc,
		},
	}
}

//TODO update this text
const issueConfigSyn = "Issue certificate."
const issueConfigDesc = "Issue certificate."
