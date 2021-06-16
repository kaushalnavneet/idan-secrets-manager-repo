package publiccerts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/certificate"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"net/http"
	"strings"
	"time"
)

type OrdersHandler struct {
	workerPool *WorkerPool
	//certRenewer *CertRenewer
	storage       logical.Storage
	currentOrders map[string]WorkItem
	parser        certificate.CertificateParser
}

func (oh *OrdersHandler) UpdateSecretEntrySecretData(secretEntry *secretentry.SecretEntry, data *framework.FieldData, userID string) (*logical.Response, error) {
	panic("implement me")
}

// ExtraValidation Perform Extra validation according to the request.
func (oh *OrdersHandler) ExtraValidation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

// BuildSecretParams Build a Secret parameter from the given secret data.
func (oh *OrdersHandler) BuildSecretParams(csp secret_backend.CommonSecretParams, ctx context.Context, req *logical.Request, d *framework.FieldData) (*secretentry.SecretParameters, *logical.Response, error) {
	err := oh.prepareOrderWorkItem(ctx, req, d)
	if err != nil {
		return nil, nil, err
	}

	certMetadata := &certificate.CertificateMetadata{
		CommonName: d.Get(secretentry.FieldCommonName).(string),
	}
	altNames := d.Get(secretentry.FieldAltNames).([]string)
	if len(altNames) != 0 {
		certMetadata.AltName = altNames
	}

	expiration := time.Now().Add(time.Hour * time.Duration(24))
	secretParams := secretentry.SecretParameters{
		Name:             csp.Name,
		Description:      csp.Description,
		Labels:           csp.Labels,
		Type:             SecretTypePublicCert,
		ExtraData:        certMetadata,
		VersionData:      nil, //we don't have cert.Data
		VersionExtraData: nil, //we don't have serialNumber, expirations
		ExpirationDate:   &expiration,
		CreatedBy:        csp.UserId,
		InstanceCRN:      csp.CRN,
		GroupID:          csp.GroupId, //state
	}

	return &secretParams, nil, nil
}

func (oh *OrdersHandler) MakeActionsBeforeStore(secretEntry *secretentry.SecretEntry, req *logical.Request, name string, ctx context.Context) (*logical.Response, error) {
	secretEntry.State = secretentry.StatePreActivation
	return nil, nil
}

func (oh *OrdersHandler) MakeActionsAfterStore(secretEntry *secretentry.SecretEntry, req *logical.Request, name string, ctx context.Context) (*logical.Response, error) {
	//get domains from the secret in order to build order key
	metadata, _ := certificate.DecodeMetadata(secretEntry.ExtraData)
	domains := getNames(metadata.CommonName, metadata.AltName)
	orderKey := getOrderID(domains)
	//get work item from cache
	workItem := oh.currentOrders[orderKey]
	//update it with secret id
	workItem.secretEntry = secretEntry
	//start an order
	_, _ = oh.workerPool.ScheduleCertificateRequest(workItem)
	return nil, nil
}

// MapSecretEntry Map secret entry to
func (oh *OrdersHandler) MapSecretEntry(entry *secretentry.SecretEntry, operation logical.Operation, includeSecretData bool) map[string]interface{} {
	if operation == logical.CreateOperation {
		return oh.getOrderDetails(entry)
	} else {

		return oh.getCertMetadata(entry, includeSecretData)
	}
}

// UpdateSecretEntryMetadata Update secret entry metadata
func (oh *OrdersHandler) UpdateSecretEntryMetadata(secretEntry *secretentry.SecretEntry, data *framework.FieldData) (*logical.Response, error) {
	// update name
	newNameRaw, ok := data.GetOk(secretentry.FieldName)
	if !ok {
		msg := fmt.Sprintf("Invalid %s parameter", secretentry.FieldName)
		common.ErrorLogForCustomer(msg, logdna.Error01035, "Retry with a valid name parameter")
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

func (oh *OrdersHandler) MapSecretVersion(version *secretentry.SecretVersion, secretId string, crn string, operation logical.Operation, includeSecretData bool) map[string]interface{} {
	return nil
}

func (oh *OrdersHandler) getCertMetadata(entry *secretentry.SecretEntry, includeSecretData bool) map[string]interface{} {
	var metadata *certificate.CertificateMetadata
	e := entry.ToMapWithVersionsMapper(oh.mapSecretVersionForVersionsList, logical.ReadOperation)
	metadata, _ = certificate.DecodeMetadata(entry.ExtraData)
	e[secretentry.FieldCommonName] = metadata.CommonName
	e[secretentry.FieldAlgorithm] = metadata.Algorithm
	e[secretentry.FieldKeyAlgorithm] = metadata.KeyAlgorithm
	e[secretentry.FieldPrivateKeyIncluded] = metadata.PrivateKeyIncluded
	e[secretentry.FieldIntermediateIncluded] = metadata.IntermediateIncluded
	e[secretentry.FieldExpirationDate] = metadata.NotAfter
	e[secretentry.FieldSerialNumber] = metadata.SerialNumber

	//Add only if alt names exists.
	if metadata.AltName != nil {
		e[secretentry.FieldAltNames] = metadata.AltName
	}

	e[secretentry.FieldIssuer] = metadata.Issuer
	e[secretentry.FieldValidity] = map[string]*time.Time{
		secretentry.FieldNotBefore: metadata.NotBefore,
		secretentry.FieldNotAfter:  metadata.NotAfter,
	}

	if !includeSecretData {
		delete(e, secretentry.FieldSecretData)
	}
	delete(e, secretentry.FieldVersions)
	return e
}

func (oh *OrdersHandler) mapSecretVersionForVersionsList(version *secretentry.SecretVersion, secretId string, crn string, operation logical.Operation, includeSecretData bool) map[string]interface{} {

	//extraData := version.ExtraData.(map[string]interface{})
	res := map[string]interface{}{
		//secretentry.FieldId:             version.ID,
		//secretentry.FieldCreatedBy:      version.CreatedBy,
		//secretentry.FieldCreatedAt:      version.CreationDate,
		//secretentry.FieldSerialNumber:   extraData[secretentry.FieldSerialNumber],
		//secretentry.FieldExpirationDate: extraData[secretentry.FieldNotAfter],
		//secretentry.FieldValidity: map[string]interface{}{
		//	secretentry.FieldNotAfter:  extraData[secretentry.FieldNotAfter],
		//	secretentry.FieldNotBefore: extraData[secretentry.FieldNotBefore],
		//},
	}
	//
	//if includeSecretData {
	//	res[secretentry.FieldSecretData] = version.VersionData
	//}
	return res
}

func getOrderID(names []string) string {
	nameHash := sha256.Sum256([]byte(strings.Join(names, "")))
	return hex.EncodeToString(nameHash[:])
}

//
//func (oh *OrdersHandler) GetCertEntryPath(names []string, requestID string) string {
//	return certEntryPathPrefix + "/" + getOrderID(names) + "/" + requestID
//}
//
//func (oh *OrdersHandler) GetCertEntryPathByCertID(certID string, requestID string) string {
//	return certEntryPathPrefix + "/" + certID + "/" + requestID
//}

func (oh *OrdersHandler) prepareOrderWorkItem(ctx context.Context, req *logical.Request, d *framework.FieldData) error {
	commonName := d.Get(secretentry.FieldCommonName).(string)
	alternativeNames := d.Get(secretentry.FieldAltNames).([]string)
	isBundle := d.Get(FieldBundleCert).(bool)
	caConfigName := d.Get(FieldCAConfig).(string)
	dnsConfigName := d.Get(FieldDNSConfig).(string)
	keyAlgorithm := d.Get(secretentry.FieldKeyAlgorithm).(string)
	//algorithm := d.Get(secretentry.FieldAlgorithm).(string)
	caConfig, err := getCAConfigByName(ctx, req, caConfigName)
	if err != nil {
		return err
	}
	dnsConfig, err := getDNSConfigByName(ctx, req, dnsConfigName)
	if err != nil {
		return err
	}
	domains := getNames(commonName, alternativeNames)
	//err = validateNames(domains)
	//if err != nil {
	//	return nil, err
	//}
	ca, err := NewCAAccountConfig(caConfig.Name, caConfig.DirectoryURL, caConfig.CARootCert, caConfig.PrivateKey, caConfig.Email)
	ca.initCAAccount()
	//ca := &CAUserConfig{
	//	Name:         caConfig.Name,
	//	CARootCert:   caConfig.CARootCert,
	//	DirectoryURL: caConfig.DirectoryURL,
	//	Email:        caConfig.Email,
	//	Registration: &registration.Resource{
	//		URI: caConfig.RegistrationURL,
	//	},
	//	key: caConfig.PrivateKey,
	//}

	//Get keyType and keyBits
	keyType, err := getKeyType(keyAlgorithm)
	if err != nil {
		return err
	}

	workItem := WorkItem{
		storage:    req.Storage,
		userConfig: ca,
		keyType:    keyType,
		dnsConfig:  dnsConfig,
		domains:    domains,
		isBundle:   isBundle,
	}

	orderKey := getOrderID(domains)

	if _, ok := oh.currentOrders[orderKey]; ok {
		return errors.New("order for these domains is in process")
	}
	oh.currentOrders[orderKey] = workItem
	return nil
}

func (oh *OrdersHandler) saveOrderResultToStorage(res Result) {
	//delete the order from cache of orders in process
	orderKey := getOrderID(res.workItem.domains)
	delete(oh.currentOrders, orderKey)
	//update secret entry
	secretEntry := res.workItem.secretEntry
	storage := res.workItem.storage
	if res.Error != nil {
		common.Logger().Error("Order Error ", "error", res.Error)
	} else {
		cert := string(res.certificate.Certificate)
		inter := string(res.certificate.IssuerCertificate)
		priv := string(res.certificate.PrivateKey)

		certData, err := oh.parser.ParseCertificate(cert, inter, priv)
		if err != nil {
			return
		}

		metadata, _ := certificate.DecodeMetadata(secretEntry.ExtraData)

		metadata.IntermediateIncluded = true
		metadata.PrivateKeyIncluded = true

		extraData := map[string]interface{}{
			secretentry.FieldNotBefore:    certData.Metadata.NotBefore,
			secretentry.FieldNotAfter:     certData.Metadata.NotAfter,
			secretentry.FieldSerialNumber: certData.Metadata.SerialNumber,
		}

		err = secretEntry.UpdateSecretDataV2(certData.RawData, secretEntry.CreatedBy, extraData)
		if err != nil {
			return
		}

		secretEntry.ExtraData = certData.Metadata
		secretEntry.ExpirationDate = certData.Metadata.NotAfter
		secretEntry.State = secretentry.StateActive
	}
	common.StoreSecretWithoutLocking(secretEntry, storage, context.Background())

}

func (oh *OrdersHandler) getOrderDetails(entry *secretentry.SecretEntry) map[string]interface{} {
	e := entry.ToMapMeta()
	metadata, _ := certificate.DecodeMetadata(entry.ExtraData)
	e[secretentry.FieldCommonName] = metadata.CommonName
	//Add only if alt names exists.
	if metadata.AltName != nil {
		e[secretentry.FieldAltNames] = metadata.AltName
	}

	return e
}
