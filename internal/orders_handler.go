package publiccerts

import (
	"context"
	"crypto/x509"
	"fmt"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/robfig/cron/v3"
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
	workerPool    *WorkerPool
	beforeOrders  map[string]WorkItem
	runningOrders map[string]WorkItem
	parser        certificate.CertificateParser
	pluginConfig  *common.ICAuthConfig
	cron          *cron.Cron
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
		common.ErrorLogForCustomer(secretShouldBeInActiveState, logdna.Error07062, logdna.BadRequestErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07062, http.StatusBadRequest, secretShouldBeInActiveState)
	}
	rotateKey := data.Get(policies.FieldRotateKeys).(bool)
	metadata, _ := certificate.DecodeMetadata(entry.ExtraData)
	var privateKey []byte
	if !rotateKey {
		rawdata, _ := certificate.DecodeRawData(entry.LastVersionData())
		privateKey = []byte(rawdata.PrivateKey)
	}

	err := oh.prepareOrderWorkItem(ctx, req, metadata, privateKey)
	if err != nil {
		return nil, err
	}
	//update issuance info only if it passed all validation
	metadata.IssuanceInfo[FieldOrderedOn] = time.Now().UTC().Format(time.RFC3339)
	metadata.IssuanceInfo[FieldAutoRotated] = false
	metadata.IssuanceInfo[secretentry.FieldState] = secretentry.StatePreActivation
	metadata.IssuanceInfo[secretentry.FieldStateDescription] = secretentry.GetNistStateDescription(secretentry.StatePreActivation)
	delete(metadata.IssuanceInfo, FieldErrorCode)
	delete(metadata.IssuanceInfo, FieldErrorMessage)
	entry.ExtraData = metadata
	return nil, nil
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
		VersionData: "",
		VersionExtraData: map[string]interface{}{
			secretentry.FieldCommonName: certMetadata.CommonName,
			secretentry.FieldAltNames:   certMetadata.AltName,
		},
		CreatedBy:   csp.UserId,
		InstanceCRN: csp.CRN,
		GroupID:     csp.GroupId, //state
	}
	err = secretParams.Policies.UpdateRotationPolicy(rotation, csp.UserId, csp.CRN)
	if err != nil {
		return nil, nil, err
	}
	return &secretParams, nil, nil
}

func (oh *OrdersHandler) MakeActionsBeforeStore(ctx context.Context, req *logical.Request, data *framework.FieldData, secretEntry *secretentry.SecretEntry) (*logical.Response, error) {
	if req.Operation == logical.CreateOperation {
		secretEntry.State = secretentry.StatePreActivation
	}
	return nil, nil
}

func (oh *OrdersHandler) MakeActionsAfterStore(ctx context.Context, req *logical.Request, data *framework.FieldData, secretEntry *secretentry.SecretEntry, storeError error) (*logical.Response, error) {
	if storeError != nil {
		return nil, storeError
	}
	//order and rotation
	if strings.Contains(req.Path, "rotate") && req.Operation == logical.UpdateOperation || req.Operation == logical.CreateOperation {
		oh.startOrder(secretEntry)
		//config iam endpoint
	} else if strings.Contains(req.Path, secret_backend.SecretEngineConfigPath) && req.Operation == logical.UpdateOperation {
		common.Logger().Debug("Get auth config and keep it in plugin configuration ")
		auth, err := common.ObtainAuthConfigFromStorage(ctx, req.Storage)
		if err == nil {
			oh.pluginConfig = auth
		}
		//configure certificates auto-rotation cron job if needed
		ConfigAutoRotationJob(auth, oh.cron)
	}
	return nil, nil
}

// MapSecretEntry Map secret entry to
func (oh *OrdersHandler) MapSecretEntry(entry *secretentry.SecretEntry, operation logical.Operation, includeSecretData bool) map[string]interface{} {
	//for order and rotate
	if operation == logical.CreateOperation || operation == logical.UpdateOperation {
		return oh.buildOrderResponse(entry)
	} else { //for all other cases
		return oh.getCertMetadata(entry, includeSecretData, includeSecretData)
	}
}

// UpdateSecretEntryMetadata Update secret entry metadata
func (oh *OrdersHandler) UpdateSecretEntryMetadata(ctx context.Context, req *logical.Request, data *framework.FieldData, secretEntry *secretentry.SecretEntry) (*logical.Response, error) {
	// update name
	newNameRaw, ok := data.GetOk(FieldName)
	if !ok {
		msg := fmt.Sprintf("Invalid %s parameter", FieldName)
		common.ErrorLogForCustomer(msg, logdna.Error01035, logdna.BadRequestErrorMessage, true)
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
		return nil, err
	}
	return requestPolicies, nil
}

func (oh *OrdersHandler) BuildPoliciesResponse(entry *secretentry.SecretEntry, policyType string) map[string]interface{} {
	rotation := entry.Policies.Rotation.FieldsToMap([]string{policies.FieldAutoRotate, policies.FieldRotateKeys})
	policyMap := make([]map[string]interface{}, 1)
	policyMap[0] = rotation
	//only if certificate is active and auto_rotate==true
	//and less than RotateIfExpirationIsInDays days left from UpdatedAt date till certExpiration date
	if entry.State == secretentry.StateActive &&
		entry.Policies.Rotation.AutoRotate() {
		certExpiration := *entry.ExpirationDate
		if entry.Policies.Rotation.Metadata.UpdatedAt.Add(RotateIfExpirationIsInDays * 24 * time.Hour).After(certExpiration) {
			rotation["warning"] = commonErrors.Warning{
				Code:    logdna.Warn07001,
				Message: policyWasUpdatedTooLate,
			}
		}
	}
	policiesMap := map[string]interface{}{policies.FieldPolicies: policyMap}
	return policiesMap
}

func (oh *OrdersHandler) UpdatePoliciesData(ctx context.Context, req *logical.Request, data *framework.FieldData, secretEntry *secretentry.SecretEntry, cpp secret_backend.CommonPolicyParams) (*logical.Response, error) {
	err := secretEntry.Policies.UpdateRotationPolicy(cpp.Policies.Rotation, cpp.UserId, cpp.CRN)
	if err != nil {
		common.Logger().Error("Could not update rotation policy", "error", err)
		common.ErrorLogForCustomer(internalServerError, logdna.Error07091, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07091, http.StatusInternalServerError, internalServerError)
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
	} else if e[secretentry.FieldSecretData] == nil || e[secretentry.FieldSecretData] == "" {
		e[secretentry.FieldSecretData] = make(map[string]string)
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
	err := oh.configureIamIfNeeded(ctx, req)
	if err != nil {
		return err
	}

	caConfigName := data.IssuanceInfo[FieldCAConfig].(string)
	dnsConfigName := data.IssuanceInfo[FieldDNSConfig].(string)
	isBundle := data.IssuanceInfo[FieldBundleCert].(bool)
	//get ca config from the storage
	caConfig, err := getConfigByName(caConfigName, providerTypeCA, ctx, req, http.StatusBadRequest)
	if err != nil {
		return err
	}
	//get dns config from the storage
	dnsConfig, err := getConfigByName(dnsConfigName, providerTypeDNS, ctx, req, http.StatusBadRequest)
	if err != nil {
		return err
	}
	//validate domains
	domains := getNames(data.CommonName, data.AltName)
	err = validateNames(domains)
	if err != nil {
		return err
	}

	caPrivKey, err := DecodePrivateKey(caConfig.Config[caConfigPrivateKey])
	if err != nil {
		message := fmt.Sprintf(invalidKey, err.Error())
		common.ErrorLogForCustomer(message, logdna.Error07039, logdna.BadRequestErrorMessage, true)
		return commonErrors.GenerateCodedError(logdna.Error07039, http.StatusBadRequest, message)
	}

	ca := &CAUserConfig{
		CARootCert:   caConfig.Config[caConfigCARootCert],
		DirectoryURL: caConfig.Config[caConfigDirectoryUrl],
		Email:        caConfig.Config[caConfigEmail],
		Registration: &registration.Resource{
			URI: caConfig.Config[caConfigRegistration],
		},
		key: caPrivKey,
	}

	//Get keyType and keyBits
	keyType, err := getKeyType(data.KeyAlgorithm)
	if err != nil {
		return err
	}

	workItem := WorkItem{
		storage:   req.Storage,
		caConfig:  ca,
		keyType:   keyType,
		dnsConfig: dnsConfig,
		domains:   domains,
		isBundle:  isBundle,
	}
	if privateKey != nil && len(privateKey) > 0 {
		certPrivKey, err := certcrypto.ParsePEMPrivateKey(privateKey)
		if err != nil {
			message := fmt.Sprintf(invalidKey, err.Error())
			common.ErrorLogForCustomer(message, logdna.Error07041, logdna.BadRequestErrorMessage, true)
			return commonErrors.GenerateCodedError(logdna.Error07041, http.StatusBadRequest, message)
		}
		//need to reuse the same key
		csrAsDER, _ := certcrypto.GenerateCSR(certPrivKey, data.CommonName, data.AltName, false)
		csr, _ := x509.ParseCertificateRequest(csrAsDER)
		workItem.csr = csr
		workItem.privateKey = privateKey
	}

	orderKey := getOrderID(domains)
	if _, ok := oh.runningOrders[orderKey]; ok {
		message := orderAlreadyInProcess
		common.ErrorLogForCustomer(message, logdna.Error07042, logdna.BadRequestErrorMessage, true)
		return commonErrors.GenerateCodedError(logdna.Error07042, http.StatusBadRequest, message)
	}
	//todo need to prevent "concurrent map writes"
	oh.beforeOrders[orderKey] = workItem
	return nil
}

//takes a work item from the map  and runs certificate order
func (oh *OrdersHandler) startOrder(secretEntry *secretentry.SecretEntry) {
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
	delete(oh.beforeOrders, orderKey)
	addWorkItemToOrdersInProgress(workItem)
	//start an order
	_, _ = oh.workerPool.ScheduleCertificateRequest(workItem)
}

//gets result of order and save it to secret entry
func (oh *OrdersHandler) saveOrderResultToStorage(res Result) {
	// at the end always remove order from orders in progress
	defer removeWorkItemFromOrdersInProgress(res.workItem)
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
		secretEntry.ExtraData = metadata
		//update secret state only in the first order, not in rotation
		if secretEntry.State == secretentry.StatePreActivation {
			secretEntry.State = secretentry.StateDeactivated
			err := secretEntry.UpdateSecretDataV2(data, secretEntry.CreatedBy, extraData)
			if err != nil {
				return
			}
		}
	} else {
		//update secret entry with the newly created certificate data
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
	err := common.StoreSecretWithoutLocking(secretEntry, storage, context.Background())
	if err != nil {
		common.Logger().Error("Couldn't save order result to storage: " + err.Error())
	}
}

//build response for create and rotate requests
func (oh *OrdersHandler) buildOrderResponse(entry *secretentry.SecretEntry) map[string]interface{} {
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
	delete(e, secretentry.FieldSecretData)
	return e
}

//is called from endpoints where we need iam
func (oh *OrdersHandler) configureIamIfNeeded(ctx context.Context, req *logical.Request) error {
	storage := req.Storage
	if oh.pluginConfig == nil {
		authConfig, err := common.ObtainAuthConfigFromStorage(ctx, storage)
		if err != nil {
			return err
		}
		if authConfig == nil {
			common.Logger().Error(logdna.Error07092 + " Engine config is missing in the storage")
			return commonErrors.GenerateCodedError(logdna.Error07092, http.StatusInternalServerError, internalServerError)
		}
		oh.pluginConfig = authConfig
	}
	return nil
}

//is called from path_rotate for every certificate in the storage
func (oh *OrdersHandler) rotateCertIfNeeded(entry *secretentry.SecretEntry, enginePolicies policies.Policies, req *logical.Request, ctx context.Context) error {
	if !isRotationNeeded(entry) {
		common.Logger().Debug(fmt.Sprintf("Secret '%s' with id %s should NOT be rotated", entry.Name, entry.ID))
		return nil
	}
	startOrder := true
	common.Logger().Debug(fmt.Sprintf("Secret '%s' with id %s SHOULD be rotated", entry.Name, entry.ID))
	rotateKey := entry.Policies.Rotation.RotateKeys()
	metadata, _ := certificate.DecodeMetadata(entry.ExtraData)
	var privateKey []byte
	if !rotateKey {
		common.Logger().Debug(fmt.Sprintf("Secret '%s' with id %s will be rotated with the same private key", entry.Name, entry.ID))
		rawdata, _ := certificate.DecodeRawData(entry.LastVersionData())
		privateKey = []byte(rawdata.PrivateKey)
	}

	metadata.IssuanceInfo[FieldOrderedOn] = time.Now().UTC().Format(time.RFC3339)
	metadata.IssuanceInfo[FieldAutoRotated] = true
	metadata.IssuanceInfo[secretentry.FieldState] = secretentry.StatePreActivation
	metadata.IssuanceInfo[secretentry.FieldStateDescription] = secretentry.GetNistStateDescription(secretentry.StatePreActivation)
	delete(metadata.IssuanceInfo, FieldErrorCode)
	delete(metadata.IssuanceInfo, FieldErrorMessage)
	entry.ExtraData = metadata
	//validate all the data and prepare it for order
	err := oh.prepareOrderWorkItem(ctx, req, metadata, privateKey)
	if err != nil {
		startOrder = false
		common.Logger().Error("Couldn't start auto rotation. Error: " + err.Error())
		updateIssuanceInfoWithError(metadata, err)
	}
	//save updated entry
	err = common.StoreSecretWithoutLocking(entry, req.Storage, context.Background())
	if err != nil {
		startOrder = false
		common.Logger().Error("Couldn't save auto rotation order data to storage: " + err.Error())
	}
	if startOrder {
		oh.startOrder(entry)
	}
	return nil
}

func (oh *OrdersHandler) cleanupAfterRotationCertIfNeeded(entry *secretentry.SecretEntry, enginePolicies policies.Policies, req *logical.Request, ctx context.Context) error {
	if !isRotationNeeded(entry) {
		common.Logger().Debug(fmt.Sprintf("Secret '%s' with id %s should NOT be rotated", entry.Name, entry.ID))
		return nil
	}
	common.Logger().Debug(fmt.Sprintf("Secret '%s' with id %s  SHOULD have been rotated but WAS NOT ", entry.Name, entry.ID))
	return nil
}

func addWorkItemToOrdersInProgress(workItem WorkItem) {
	// lock for writing
	lock := common.GetLockForName(PathOrdersInProgress)
	lock.Lock()
	defer lock.Unlock()

	ordersInProgress := getOrdersInProgress(workItem.storage)
	//check if current work item already in the list, if yes, no need to add it
	found := false
	for i, secret := range ordersInProgress.Orders {
		if secret.Id == workItem.secretEntry.ID {
			ordersInProgress.Orders[i].Attempts++
			common.Logger().Info(fmt.Sprintf("The secret with id %s is already in the list of orders in progress, encreasing attempts count to %d .", secret.Id, ordersInProgress.Orders[i].Attempts))
			found = true
			break
		}
	}
	if !found {
		//add it to the list
		ordersInProgress.Orders = append(ordersInProgress.Orders, OrderDetails{Id: workItem.secretEntry.ID, GroupId: workItem.secretEntry.GroupID, Attempts: 1})
	}
	ordersInProgress.save(workItem.storage)
	return
}

func removeWorkItemFromOrdersInProgress(workItem WorkItem) {
	removeOrderFromOrdersInProgress(workItem.storage, OrderDetails{Id: workItem.secretEntry.ID, GroupId: workItem.secretEntry.GroupID})
}

func removeOrderFromOrdersInProgress(storage logical.Storage, itemToRemove OrderDetails) {
	// lock for writing
	lock := common.GetLockForName(PathOrdersInProgress)
	lock.Lock()
	defer lock.Unlock()

	ordersInProgress := getOrdersInProgress(storage)
	//find the current work item and remove it
	for i, secret := range ordersInProgress.Orders {
		if secret.Id == itemToRemove.Id {
			ordersInProgress.Orders = append(ordersInProgress.Orders[:i], ordersInProgress.Orders[i+1:]...)
			common.Logger().Info(fmt.Sprintf("Removing the secret entry '%s' from 'orders in progress'", itemToRemove.GroupId+"/"+itemToRemove.Id))
			ordersInProgress.save(storage)
			break
		}
	}
}

func isRotationNeeded(entry *secretentry.SecretEntry) bool {
	if entry.State == secretentry.StateActive && entry.Policies.Rotation != nil && entry.Policies.Rotation.AutoRotate() {
		now := time.Now().UTC()
		midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		startExpirationPeriod := midnight.AddDate(0, 0, RotateIfExpirationIsInDays)
		endExpirationPeriod := midnight.AddDate(0, 0, RotateIfExpirationIsInDays+1)
		certExpiration := *entry.ExpirationDate
		return certExpiration.After(startExpirationPeriod) && certExpiration.Before(endExpirationPeriod)
	} else {
		return false
	}
}

func getPoliciesFromFieldData(data *framework.FieldData) (*policies.Policies, error) {
	newPolicies := &policies.Policies{}
	rawPolicies := data.Get(policies.FieldPolicies).([]interface{})
	if len(rawPolicies) > 1 {
		common.ErrorLogForCustomer(policiesMoreThanOne, logdna.Error07094, logdna.BadRequestErrorMessage, true)
		return nil, commonErrors.GenerateCodedError(logdna.Error07094, http.StatusBadRequest, policiesMoreThanOne)
	}
	policyMap, ok := rawPolicies[0].(map[string]interface{})
	if !ok {
		common.ErrorLogForCustomer(policiesNotValidStructure, logdna.Error07095, logdna.BadRequestErrorMessage, true)
		return nil, commonErrors.GenerateCodedError(logdna.Error07095, http.StatusBadRequest, policiesNotValidStructure)
	}
	rawRotation, ok := policyMap[policies.PolicyTypeRotation]
	if !ok {
		common.ErrorLogForCustomer(policiesNotValidStructure, logdna.Error07096, logdna.BadRequestErrorMessage, true)
		return nil, commonErrors.GenerateCodedError(logdna.Error07096, http.StatusBadRequest, policiesNotValidStructure)
	}
	newPolicy, err := getRotationPolicy(rawRotation)
	if err != nil {
		return nil, err
	}
	newPolicies.Rotation = newPolicy
	return newPolicies, nil
}

func getRotationPolicy(rawPolicy interface{}) (*policies.RotationPolicy, error) {
	policy, ok := rawPolicy.(map[string]interface{})
	if !ok {
		common.ErrorLogForCustomer(policiesNotValidStructure, logdna.Error07097, logdna.BadRequestErrorMessage, true)
		return nil, commonErrors.GenerateCodedError(logdna.Error07097, http.StatusBadRequest, policiesNotValidStructure)
	}
	autoRotate, ok := policy[policies.FieldAutoRotate].(bool)
	if !ok {
		msg := fmt.Sprintf(policiesNotValidField, policies.FieldAutoRotate)
		common.ErrorLogForCustomer(msg, logdna.Error07098, logdna.BadRequestErrorMessage, true)
		return nil, commonErrors.GenerateCodedError(logdna.Error07098, http.StatusBadRequest, msg)
	}
	rotateKeys, ok := policy[policies.FieldRotateKeys].(bool)
	if !ok {
		msg := fmt.Sprintf(policiesNotValidField, policies.FieldRotateKeys)
		common.ErrorLogForCustomer(msg, logdna.Error07099, logdna.BadRequestErrorMessage, true)
		return nil, commonErrors.GenerateCodedError(logdna.Error07099, http.StatusBadRequest, msg)
	}
	rotationPolicy := policies.RotationPolicy{
		Rotation: &policies.RotationData{
			AutoRotate: autoRotate,
			RotateKeys: rotateKeys,
			Interval:   0,
			Unit:       policies.DayUnit,
		},
		Type: policies.MIMETypeForPolicyResource,
	}
	//90 is for LetsEncrypt. need to set it according to CA
	if autoRotate {
		rotationPolicy.Rotation.Interval = 90 - RotateIfExpirationIsInDays
	}

	return &rotationPolicy, nil
}

func updateIssuanceInfoWithError(metadata *certificate.CertificateMetadata, err error) {
	if codedError, ok := err.(commonErrors.SMCodedError); ok {
		metadata.IssuanceInfo[FieldErrorCode] = codedError.ErrCode()
		metadata.IssuanceInfo[FieldErrorMessage] = codedError.Error()
	} else {
		metadata.IssuanceInfo[FieldErrorCode] = logdna.Error07110
		metadata.IssuanceInfo[FieldErrorMessage] = err.Error()

	}
	metadata.IssuanceInfo[secretentry.FieldState] = secretentry.StateDeactivated
	metadata.IssuanceInfo[secretentry.FieldStateDescription] = secretentry.GetNistStateDescription(secretentry.StateDeactivated)
}
