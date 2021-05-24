package publiccerts

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
)

type OrdersHandler struct {
}

func (oh *OrdersHandler) UpdateSecretEntrySecretData(secretEntry *secretentry.SecretEntry, data *framework.FieldData, userID string) (*logical.Response, error) {
	return nil, nil
}

//Perform Extra validation according to the request.
func (oh *OrdersHandler) ExtraValidation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

//Build a Secret parameter from the given secret data.
func (oh *OrdersHandler) BuildSecretParams(name string, description string, labels []string, instanceCRN string, userId string, groupId string, data *framework.FieldData) (*secretentry.SecretParameters, *logical.Response, error) {
	return nil, nil, nil
}

// MapSecretEntry Map secret entry to
func (oh *OrdersHandler) MapSecretEntry(entry *secretentry.SecretEntry, operation logical.Operation, includeSecretData bool) map[string]interface{} {
	return nil
}

// UpdateSecretEntryMetadata Update secret entry metadata
func (oh *OrdersHandler) UpdateSecretEntryMetadata(secretEntry *secretentry.SecretEntry, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

func (oh *OrdersHandler) MapSecretVersion(version *secretentry.SecretVersion, secretId string, crn string, operation logical.Operation, includeSecretData bool) map[string]interface{} {
	return nil
}

func (oh *OrdersHandler) mapCertificate(entry *secretentry.SecretEntry, includeSecretData bool) map[string]interface{} {
	return nil
}
