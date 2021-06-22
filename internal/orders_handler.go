package publiccerts

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-iam/pkg/iam"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/certificate"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type OrdersHandler struct {
	workerPool *WorkerPool
	//certRenewer *CertRenewer
	storage       logical.Storage
	beforeOrders  map[string]WorkItem
	runningOrders map[string]WorkItem
	parser        certificate.CertificateParser
	iam           *iam.Config
}

type OrderError struct {
	Code    string `json:"error_code"`
	Message string `json:"error_message"`
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

	issuanceInfo := make(map[string]interface{})
	issuanceInfo[FieldOrderedOn] = time.Now()
	issuanceInfo[secretentry.FieldState] = secretentry.StatePreActivation
	issuanceInfo[secretentry.FieldStateDescription] = secretentry.GetNistStateDescription(secretentry.StatePreActivation)
	issuanceInfo[FieldAutoRenewed] = false
	issuanceInfo[FieldCAConfig] = d.Get(FieldCAConfig).(string)
	issuanceInfo[FieldDNSConfig] = d.Get(FieldDNSConfig).(string)

	certMetadata := &certificate.CertificateMetadata{
		CommonName:   d.Get(secretentry.FieldCommonName).(string),
		IssuanceInfo: issuanceInfo,
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
	workItem := oh.beforeOrders[orderKey]
	//update it with secret id
	workItem.secretEntry = secretEntry
	oh.runningOrders[orderKey] = workItem
	//empty beforeOrders, current workItem is moved to runningOrders
	//some previous order requests could fail on validations so their beforeOrders should be removed too
	oh.beforeOrders = make(map[string]WorkItem)
	//start an order
	_, _ = oh.workerPool.ScheduleCertificateRequest(workItem)
	return nil, nil
}

// MapSecretEntry Map secret entry to
func (oh *OrdersHandler) MapSecretEntry(entry *secretentry.SecretEntry, operation logical.Operation, includeSecretData bool) map[string]interface{} {
	if operation == logical.CreateOperation {
		return oh.getOrderResponse(entry)
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
	e[FieldIssuanceInfo] = metadata.IssuanceInfo

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

//builds work item (with validation) and save it in memory
func (oh *OrdersHandler) prepareOrderWorkItem(ctx context.Context, req *logical.Request, d *framework.FieldData) error {
	commonName := d.Get(secretentry.FieldCommonName).(string)
	alternativeNames := d.Get(secretentry.FieldAltNames).([]string)
	isBundle := d.Get(FieldBundleCert).(bool)
	caConfigName := d.Get(FieldCAConfig).(string)
	dnsConfigName := d.Get(FieldDNSConfig).(string)
	keyAlgorithm := d.Get(secretentry.FieldKeyAlgorithm).(string)
	//TODO check why we don't set algorithm
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
	err = validateNames(domains)
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(caConfig.PrivateKey))
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	ca := &CAUserConfig{
		Name:         caConfig.Name,
		CARootCert:   caConfig.CARootCert,
		DirectoryURL: caConfig.DirectoryURL,
		Email:        caConfig.Email,
		Registration: &registration.Resource{
			URI: caConfig.RegistrationURL,
		},
		key: privateKey,
	}

	//Get keyType and keyBits
	keyType, err := getKeyType(keyAlgorithm)
	if err != nil {
		return err
	}
	//TODO maybe add iam to dnsConfig	dnsConfig.Config["iam"] but it should be string
	iamConfig, err := oh.configureIamIfNeeded(ctx, req.Storage)
	workItem := WorkItem{
		storage:    req.Storage,
		iamConfig:  iamConfig,
		userConfig: ca,
		keyType:    keyType,
		dnsConfig:  dnsConfig,
		domains:    domains,
		isBundle:   isBundle,
	}

	orderKey := getOrderID(domains)
	if _, ok := oh.runningOrders[orderKey]; ok {
		return errors.New("order for these domains is in process")
	}
	oh.beforeOrders[orderKey] = workItem
	return nil
}

func (oh *OrdersHandler) saveOrderResultToStorage(res Result) {
	//delete the order from cache of orders in process
	orderKey := getOrderID(res.workItem.domains)
	delete(oh.runningOrders, orderKey)
	//update secret entry
	secretEntry := res.workItem.secretEntry
	storage := res.workItem.storage

	metadata, _ := certificate.DecodeMetadata(secretEntry.ExtraData)
	//metadata.IssuanceInfo = make(map[string]interface{})
	var data interface{}
	var extraData map[string]interface{}
	if res.Error != nil {
		common.Logger().Error("Order failed with error: " + res.Error.Error())
		errorObj := getOrderError(res)
		metadata.IssuanceInfo[FieldOrderedOn] = time.Now()
		metadata.IssuanceInfo[secretentry.FieldState] = secretentry.StateDeactivated
		metadata.IssuanceInfo[secretentry.FieldStateDescription] = secretentry.GetNistStateDescription(secretentry.StateDeactivated)
		metadata.IssuanceInfo[FieldErrorCode] = errorObj.Code
		metadata.IssuanceInfo[FieldErrorMessage] = errorObj.Message
		metadata.IssuanceInfo[FieldAutoRenewed] = false

		extraData = map[string]interface{}{
			FieldIssuanceInfo: metadata.IssuanceInfo,
		}
		err := secretEntry.UpdateSecretDataV2(data, secretEntry.CreatedBy, extraData)
		if err != nil {
			return
		}
		secretEntry.ExtraData = metadata
		secretEntry.State = secretentry.StateDeactivated
	} else {
		cert := string(res.certificate.Certificate)
		inter := string(res.certificate.IssuerCertificate)
		priv := string(res.certificate.PrivateKey)
		if !res.workItem.isBundle {
			//certificate in result contains itself + intermediate, find the end of the first cert
			certEnd := strings.Index(cert, endCertificate)
			//get only the first cert
			cert = cert[:certEnd+len(endCertificate)] + "\n"
		}
		certData, err := oh.parser.ParseCertificate(cert, inter, priv)
		if err != nil {
			return
		}
		metadata.IssuanceInfo[FieldOrderedOn] = time.Now()
		metadata.IssuanceInfo[secretentry.FieldState] = secretentry.StateActive
		metadata.IssuanceInfo[secretentry.FieldStateDescription] = secretentry.GetNistStateDescription(secretentry.StateActive)
		metadata.IssuanceInfo[FieldAutoRenewed] = false

		certData.Metadata.IssuanceInfo = metadata.IssuanceInfo
		data = certData.RawData

		extraData = map[string]interface{}{
			secretentry.FieldNotBefore:    certData.Metadata.NotBefore,
			secretentry.FieldNotAfter:     certData.Metadata.NotAfter,
			secretentry.FieldSerialNumber: certData.Metadata.SerialNumber,
			FieldIssuanceInfo:             certData.Metadata.IssuanceInfo,
		}
		err = secretEntry.UpdateSecretDataV2(data, secretEntry.CreatedBy, extraData)
		if err != nil {
			return
		}

		secretEntry.ExtraData = certData.Metadata
		secretEntry.ExpirationDate = certData.Metadata.NotAfter
		secretEntry.State = secretentry.StateActive
	}
	common.StoreSecretWithoutLocking(secretEntry, storage, context.Background())

}

func getOrderError(res Result) *OrderError {
	pat := regexp.MustCompile(fmt.Sprintf(errorPattern, "(.*?)", "(.*?)"))
	errorJson := pat.FindString(res.Error.Error())
	errorObj := &OrderError{}
	if errorJson != "" {
		json.Unmarshal([]byte(errorJson), errorObj)
	} else {
		errorObj.Code = "ACME_Error"
		errorObj.Message = res.Error.Error()
	}
	return errorObj
}

func (oh *OrdersHandler) getOrderResponse(entry *secretentry.SecretEntry) map[string]interface{} {
	e := entry.ToMapMeta()
	metadata, _ := certificate.DecodeMetadata(entry.ExtraData)
	e[secretentry.FieldCommonName] = metadata.CommonName
	//Add only if alt names exists.
	if metadata.AltName != nil {
		e[secretentry.FieldAltNames] = metadata.AltName
	}
	return e
}

func (oh *OrdersHandler) configureIamIfNeeded(ctx context.Context, s logical.Storage) (*iam.Config, error) {
	if oh.iam == nil {
		authConfig, err := common.ObtainAuthConfigFromStorage(ctx, s)
		if err != nil {
			return nil, err
		}
		conf := &iam.Config{
			IamEndpoint:  authConfig.IAMEndpoint,
			ApiKey:       authConfig.Service.APIKey,
			ClientID:     authConfig.Service.ClientID,
			ClientSecret: authConfig.Service.ClientSecret,
			DisableCache: false,
		}
		oh.iam = conf
		err = iam.Configure(conf)
		if err != nil {
			return nil, err
		}
	}
	return oh.iam, nil
}
