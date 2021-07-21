package publiccerts

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-iam/pkg/iam"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/certificate"
	commonErrors "github.ibm.com/security-services/secrets-manager-vault-plugins-common/errors"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry/policies"
	"net/http"
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

func (oh *OrdersHandler) GetPolicyHandler() secret_backend.PolicyHandler {
	return oh
}

type OrderError struct {
	Code    string `json:"error_code"`
	Message string `json:"error_message"`
}

func (oh *OrdersHandler) UpdateSecretEntrySecretData(ctx context.Context, req *logical.Request, data *framework.FieldData, entry *secretentry.SecretEntry, userID string) (*logical.Response, error) {
	if entry.State != secretentry.StateActive {
		return nil, errors.New("secret should be in Active state")
	}
	//TODO take rotate_key from policy and override with parameter if any
	rotateKey := data.Get(policies.FieldRotateKeys).(bool)
	metadata, _ := certificate.DecodeMetadata(entry.ExtraData)
	var privateKey []byte
	if !rotateKey {
		rawdata, _ := certificate.DecodeRawData(entry.LastVersionData())
		privateKey = []byte(rawdata.PrivateKey)
	}

	err := oh.prepareOrderWorkItem(ctx, req, metadata, privateKey)
	metadata.IssuanceInfo[FieldOrderedOn] = time.Now().UTC().Format(time.RFC3339)
	metadata.IssuanceInfo[FieldAutoRotated] = false
	if err != nil {
		metadata.IssuanceInfo[secretentry.FieldState] = secretentry.StateDeactivated
		metadata.IssuanceInfo[secretentry.FieldStateDescription] = secretentry.GetNistStateDescription(secretentry.StateDeactivated)
		metadata.IssuanceInfo[FieldErrorCode] = "RenewError"
		metadata.IssuanceInfo[FieldErrorMessage] = err.Error()
		entry.ExtraData = metadata
		return nil, err
	} else {
		metadata.IssuanceInfo[secretentry.FieldState] = secretentry.StatePreActivation
		metadata.IssuanceInfo[secretentry.FieldStateDescription] = secretentry.GetNistStateDescription(secretentry.StatePreActivation)
		delete(metadata.IssuanceInfo, FieldErrorCode)
		delete(metadata.IssuanceInfo, FieldErrorMessage)
		entry.ExtraData = metadata
		return nil, nil
	}
}

// ExtraValidation Perform Extra validation according to the request.
func (oh *OrdersHandler) ExtraValidation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

// BuildSecretParams Build a Secret parameter from the given secret data(used in CREATE)
func (oh *OrdersHandler) BuildSecretParams(ctx context.Context, req *logical.Request, data *framework.FieldData, csp secret_backend.CommonSecretParams) (*secretentry.SecretParameters, *logical.Response, error) {
	//build order data for a new order from input params
	issuanceInfo := make(map[string]interface{})
	issuanceInfo[FieldOrderedOn] = time.Now().UTC().Format(time.RFC3339)
	issuanceInfo[FieldAutoRotated] = false
	issuanceInfo[secretentry.FieldState] = secretentry.StatePreActivation
	issuanceInfo[secretentry.FieldStateDescription] = secretentry.GetNistStateDescription(secretentry.StatePreActivation)
	issuanceInfo[FieldCAConfig] = data.Get(FieldCAConfig).(string)
	issuanceInfo[FieldDNSConfig] = data.Get(FieldDNSConfig).(string)
	issuanceInfo[FieldBundleCert] = data.Get(FieldBundleCert).(bool)
	certMetadata := &certificate.CertificateMetadata{
		KeyAlgorithm: data.Get(secretentry.FieldKeyAlgorithm).(string),
		CommonName:   data.Get(secretentry.FieldCommonName).(string),
		AltName:      data.Get(secretentry.FieldAltNames).([]string),
		IssuanceInfo: issuanceInfo,
	}
	err := oh.prepareOrderWorkItem(ctx, req, certMetadata, nil)
	if err != nil {
		return nil, nil, err
	}

	rawPolicy := data.Get(FieldRotation)
	rotation, err := getRotationPolicy(rawPolicy)
	if err != nil {
		return nil, nil, err
	}
	secretParams := secretentry.SecretParameters{
		Name:        csp.Name,
		Description: csp.Description,
		Labels:      csp.Labels,
		Type:        secretentry.SecretTypePublicCert,
		ExtraData:   certMetadata,
		VersionData: certMetadata,
		VersionExtraData: map[string]interface{}{
			secretentry.FieldCommonName: certMetadata.CommonName,
			secretentry.FieldAltNames:   certMetadata.AltName,
		},
		CreatedBy:   csp.UserId,
		InstanceCRN: csp.CRN,
		GroupID:     csp.GroupId, //state
	}
	err = secretParams.Policies.UpdateRotationPolicy(rotation, csp.UserId, csp.CRN)

	return &secretParams, nil, nil
}

func (oh *OrdersHandler) MakeActionsBeforeStore(ctx context.Context, req *logical.Request, data *framework.FieldData, secretEntry *secretentry.SecretEntry) (*logical.Response, error) {
	secretEntry.State = secretentry.StatePreActivation
	return nil, nil
}

func (oh *OrdersHandler) MakeActionsAfterStore(ctx context.Context, req *logical.Request, data *framework.FieldData, secretEntry *secretentry.SecretEntry) (*logical.Response, error) {
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
	//for order and renew
	if operation == logical.CreateOperation || operation == logical.UpdateOperation {
		return oh.getOrderResponse(entry)
	} else { //for all other cases
		return oh.getCertMetadata(entry, includeSecretData, includeSecretData)
	}
}

// UpdateSecretEntryMetadata Update secret entry metadata
func (oh *OrdersHandler) UpdateSecretEntryMetadata(ctx context.Context, req *logical.Request, data *framework.FieldData, secretEntry *secretentry.SecretEntry) (*logical.Response, error) {
	// update name
	newNameRaw, ok := data.GetOk(secretentry.FieldName)
	if !ok {
		msg := fmt.Sprintf("Invalid %s parameter", secretentry.FieldName)
		common.ErrorLogForCustomer(msg, logdna.Error01035, "Retry with a valid name parameter", true)
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

func (oh *OrdersHandler) GetInputPolicies(data *framework.FieldData) (*policies.Policies, error) {
	requestPolicies, err := getPoliciesFromFieldData(data)
	if err != nil {
		msg := "Invalid policies: " + err.Error()
		common.ErrorLogForCustomer(msg, logdna.Error07095, "Verify that the policies parameter is valid", true)
		return nil, commonErrors.GenerateCodedError(logdna.Error07095, http.StatusBadRequest, msg)
	}
	return requestPolicies, nil

}

func (oh *OrdersHandler) BuildPoliciesResponse(entry *secretentry.SecretEntry, policyType string) map[string]interface{} {
	rotation := entry.Policies.Rotation.FieldsToMap([]string{policies.FieldAutoRotate, policies.FieldRotateKeys})
	policyMap := make([]map[string]interface{}, 1)
	policyMap[0] = rotation
	policies := map[string]interface{}{"policies": policyMap}
	return policies
}

func getPoliciesFromFieldData(data *framework.FieldData) (*policies.Policies, error) {
	newPolicies := &policies.Policies{}
	rawPolicies := data.Get("policies").([]interface{})
	if len(rawPolicies) > 1 {
		return nil, fmt.Errorf("received more than one policy")
	}
	policyMap, ok := rawPolicies[0].(map[string]interface{})
	if !ok {
		return nil, commonErrors.GenerateCodedError(logdna.Error07094, http.StatusBadRequest, "rotation policy is not valid ")
	}
	rawRotation, ok := policyMap["rotation"]
	if !ok {
		return nil, commonErrors.GenerateCodedError(logdna.Error07095, http.StatusBadRequest, "rotation policy is not valid ")
	}
	newPolicy, err := getRotationPolicy(rawRotation)
	if err != nil {
		return nil, err
	}
	newPolicies.Rotation = newPolicy
	return newPolicies, nil
}

func (oh *OrdersHandler) UpdatePoliciesData(ctx context.Context, req *logical.Request, data *framework.FieldData, secretEntry *secretentry.SecretEntry, cpp secret_backend.CommonPolicyParams) (*logical.Response, error) {
	err := secretEntry.Policies.UpdateRotationPolicy(cpp.Policies.Rotation, cpp.UserId, cpp.CRN)
	if err != nil {
		common.Logger().Error("could not update rotation policy", "error", err)
		common.ErrorLogForCustomer("Internal server error", logdna.Error07093, logdna.InternalErrorMessage, false)
		return common.ResponseInternalError()
	}
	return nil, nil
}

func (oh *OrdersHandler) MapSecretVersion(version *secretentry.SecretVersion, secretId string, crn string, operation logical.Operation, includeSecretData bool) map[string]interface{} {
	extraData := version.ExtraData.(map[string]interface{})
	res := map[string]interface{}{
		secretentry.FieldId:               secretId,
		secretentry.FieldCrn:              crn,
		secretentry.FieldVersionId:        version.ID,
		secretentry.FieldCreatedBy:        version.CreatedBy,
		secretentry.FieldCreatedAt:        version.CreationDate,
		secretentry.FieldSerialNumber:     extraData[secretentry.FieldSerialNumber],
		secretentry.FieldExpirationDate:   extraData[secretentry.FieldNotAfter],
		secretentry.FieldPayloadAvailable: version.VersionData != nil,
		secretentry.FieldValidity: map[string]interface{}{
			secretentry.FieldNotAfter:  extraData[secretentry.FieldNotAfter],
			secretentry.FieldNotBefore: extraData[secretentry.FieldNotBefore],
		},
	}
	if includeSecretData {
		res[secretentry.FieldSecretData] = version.VersionData
	}
	return res
}

func (oh *OrdersHandler) AllowedPolicyTypes() []interface{} {
	return []interface{}{policies.PolicyTypeRotation}
}

func (oh *OrdersHandler) getCertMetadata(entry *secretentry.SecretEntry, includeSecretData bool, includeVersion bool) map[string]interface{} {
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

	if !includeVersion {
		delete(e, secretentry.FieldVersions)
	}

	return e
}

func (oh *OrdersHandler) mapSecretVersionForVersionsList(version *secretentry.SecretVersion, secretId string, crn string, operation logical.Operation, includeSecretData bool) map[string]interface{} {

	extraData := version.ExtraData.(map[string]interface{})
	res := map[string]interface{}{
		secretentry.FieldId:               version.ID,
		secretentry.FieldCreatedBy:        version.CreatedBy,
		secretentry.FieldCreatedAt:        version.CreationDate,
		secretentry.FieldSerialNumber:     extraData[secretentry.FieldSerialNumber],
		secretentry.FieldExpirationDate:   extraData[secretentry.FieldNotAfter],
		secretentry.FieldPayloadAvailable: version.VersionData != nil,
		secretentry.FieldValidity: map[string]interface{}{
			secretentry.FieldNotAfter:  extraData[secretentry.FieldNotAfter],
			secretentry.FieldNotBefore: extraData[secretentry.FieldNotBefore],
		},
	}
	if includeSecretData {
		res[secretentry.FieldSecretData] = version.VersionData
	}
	return res
}

//builds work item (with validation) and save it in memory
func (oh *OrdersHandler) prepareOrderWorkItem(ctx context.Context, req *logical.Request, data *certificate.CertificateMetadata, privateKey []byte) error {
	caConfigName := data.IssuanceInfo[FieldCAConfig].(string)
	dnsConfigName := data.IssuanceInfo[FieldDNSConfig].(string)
	isBundle := data.IssuanceInfo[FieldBundleCert].(bool)
	//get ca config from the storage
	caConfig, err := getCAConfigByName(ctx, req, caConfigName)
	if err != nil {
		return err
	}
	//get dns config from the storage
	dnsConfig, err := getDNSConfigByName(ctx, req, dnsConfigName)
	if err != nil {
		return err
	}
	//validate domains
	domains := getNames(data.CommonName, data.AltName)
	err = validateNames(domains)
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(caConfig.PrivateKey))
	caPrivKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
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
		key: caPrivKey,
	}

	//Get keyType and keyBits
	keyType, err := getKeyType(data.KeyAlgorithm)
	if err != nil {
		return err
	}
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
	if privateKey != nil && len(privateKey) > 0 {
		certPrivKey, err := certcrypto.ParsePEMPrivateKey(privateKey)
		if err != nil {
			//can't happen
		}
		//need to reuse the same key
		csrAsDER, _ := certcrypto.GenerateCSR(certPrivKey, data.CommonName, data.AltName, false)
		csr, _ := x509.ParseCertificateRequest(csrAsDER)
		workItem.csr = csr
		workItem.privateKey = privateKey
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
	//if entry state is PreActivation,it's the first order, remove empty version
	if secretEntry.State == secretentry.StatePreActivation {
		secretEntry.Versions = make([]secretentry.SecretVersion, 0)
	}
	metadata, _ := certificate.DecodeMetadata(secretEntry.ExtraData)
	var data interface{}
	var extraData map[string]interface{}
	if res.Error != nil {
		common.Logger().Error("Order failed with error: " + res.Error.Error())
		errorObj := getOrderError(res)
		metadata.IssuanceInfo[secretentry.FieldState] = secretentry.StateDeactivated
		metadata.IssuanceInfo[secretentry.FieldStateDescription] = secretentry.GetNistStateDescription(secretentry.StateDeactivated)
		metadata.IssuanceInfo[FieldErrorCode] = errorObj.Code
		metadata.IssuanceInfo[FieldErrorMessage] = errorObj.Message

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

		metadata.IssuanceInfo[secretentry.FieldState] = secretentry.StateActive
		metadata.IssuanceInfo[secretentry.FieldStateDescription] = secretentry.GetNistStateDescription(secretentry.StateActive)
		delete(metadata.IssuanceInfo, FieldErrorCode)
		delete(metadata.IssuanceInfo, FieldErrorMessage)

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

func (oh *OrdersHandler) getOrderResponse(entry *secretentry.SecretEntry) map[string]interface{} {
	e := entry.ToMapMeta()
	metadata, _ := certificate.DecodeMetadata(entry.ExtraData)
	e[secretentry.FieldCommonName] = metadata.CommonName
	//Add only if alt names exists.
	if metadata.AltName != nil {
		e[secretentry.FieldAltNames] = metadata.AltName
	}
	e[secretentry.FieldKeyAlgorithm] = metadata.KeyAlgorithm
	e[FieldIssuanceInfo] = metadata.IssuanceInfo
	e[secretentry.FieldVersions] = make([]map[string]interface{}, 0)
	rotation := map[string]interface{}{
		policies.FieldAutoRotate: entry.Policies.Rotation.AutoRotate(),
		policies.FieldRotateKeys: entry.Policies.Rotation.RotateKeys()}
	e[FieldRotation] = rotation
	return e
}

func (oh *OrdersHandler) configureIamIfNeeded(ctx context.Context, storage logical.Storage) (*iam.Config, error) {
	if oh.iam == nil {
		authConfig, err := common.ObtainAuthConfigFromStorage(ctx, storage)
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
			common.Logger().Error("Failed to configure iam", "error", err)
			return nil, err
		}
	}
	return oh.iam, nil
}

func getRotationPolicy(rawPolicy interface{}) (*policies.RotationPolicy, error) {
	policy, ok := rawPolicy.(map[string]interface{})
	if !ok {
		return nil, commonErrors.GenerateCodedError(logdna.Error07090, http.StatusBadRequest, "rotation policy has not valid structure")
	}
	autoRotate, ok := policy[policies.FieldAutoRotate].(bool)
	if !ok {
		return nil, commonErrors.GenerateCodedError(logdna.Error07094, http.StatusBadRequest, fmt.Sprintf("field %s in rotation policy is not valid. ", policies.FieldAutoRotate))
	}
	rotateKeys, ok := policy[policies.FieldRotateKeys].(bool)
	if !ok {
		return nil, commonErrors.GenerateCodedError(logdna.Error07096, http.StatusBadRequest, fmt.Sprintf("field %s in rotation policy is not valid ", policies.FieldRotateKeys))
	}
	rotationPolicy := policies.RotationPolicy{
		Rotation: &policies.RotationData{
			AutoRotate: autoRotate,
			RotateKeys: rotateKeys,
			Interval:   59,
			Unit:       policies.DayUnit,
		},
		Type: policies.MIMETypeForPolicyResource,
	}

	return &rotationPolicy, nil
}
