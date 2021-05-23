package publiccerts

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"net/http"
)

type OrdersHandler struct {
}

func (oh *OrdersHandler) UpdateSecretEntrySecretData(secretEntry *secretentry.SecretEntry, data *framework.FieldData, userID string) (*logical.Response, error) {
	panic("implement me")
}

//Perform Extra validation according to the request.
func (oh *OrdersHandler) ExtraValidation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

//Build a Secret parameter from the given secret data.
func (oh *OrdersHandler) BuildSecretParams(name string, description string, labels []string, instanceCRN string, userId string, groupId string, data *framework.FieldData) (*secretentry.SecretParameters, *logical.Response, error) {

	//cert := data.Get("certificate")
	//inter := data.Get("intermediate")
	//priv := data.Get("private_key")
	//
	//intermediate := ""
	//privateKey := ""

	//if inter != nil {
	//	intermediate = inter.(string)
	//}
	//
	//if priv != nil {
	//	privateKey = priv.(string)
	//}
	//
	//certData, err := oh.Parser.ParseCertificate(cert.(string), intermediate, privateKey)
	//if err != nil {
	//	return nil, nil, err
	//}

	secretParams := secretentry.SecretParameters{
		Name:        name,
		Description: description,
		Labels:      labels,
		Type:        secretentry.SecretTypeExternalKpi,
		//VersionData:    certData.RawData,
		//ExtraData:      certData.Metadata,
		//ExpirationDate: certData.Metadata.NotAfter,
		CreatedBy:   userId,
		InstanceCRN: instanceCRN,
		GroupID:     groupId,
	}

	return &secretParams, nil, nil
}

// MapSecretEntry Map secret entry to
func (oh *OrdersHandler) MapSecretEntry(entry *secretentry.SecretEntry, operation logical.Operation, includeSecretData bool, versionData *interface{}) map[string]interface{} {
	switch operation {
	case logical.CreateOperation:
	case logical.ReadOperation:
	case logical.UpdateOperation:
		return oh.mapCertificate(entry, includeSecretData)
	}
	return oh.mapCertificate(entry, includeSecretData)
}

// UpdateSecretEntryMetadata Update secret entry metadata
func (oh *OrdersHandler) UpdateSecretEntryMetadata(secretEntry *secretentry.SecretEntry, data *framework.FieldData) (*logical.Response, error) {

	// update name
	newNameRaw, ok := data.GetOk(secretentry.FieldName)
	if !ok {
		msg := fmt.Sprintf("Invalid %s parameter", secretentry.FieldName)
		common.ErrorLogForCustomer(msg, Error07008, "Retry with a valid name parameter")
		return nil, logical.CodedError(http.StatusBadRequest, msg)
	}

	newName := newNameRaw.(string)
	secretEntry.Name = newName
	//update labels
	labels := data.Get(secretentry.FieldLabels)
	secretEntry.Labels = labels.([]string)

	//update description
	description := data.Get(secretentry.FieldDescription)
	secretEntry.Description = description.(string)

	return nil, nil
}

func (oh *OrdersHandler) mapCertificate(entry *secretentry.SecretEntry, includeSecretData bool) map[string]interface{} {

	e := (*entry).ToMapWithVersions()
	return e
}
