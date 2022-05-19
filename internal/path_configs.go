package publiccerts

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	at "github.ibm.com/security-services/secrets-manager-vault-plugins-common/activity_tracker"
	commonErrors "github.ibm.com/security-services/secrets-manager-vault-plugins-common/errors"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"net/http"
	"strings"
)

var secretsConfigLock locksutil.LockEntry

//************* Paths ***************//
func (ob *OrdersBackend) pathConfigCA() []*framework.Path {
	atSecretConfigUpdate := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: at.ConfigTargetTypeURI,
		Description: atSetConfigAction, Action: common.SetEngineConfigAction, SecretType: secretentry.SecretTypePublicCert, TargetResourceType: CA}
	atSecretConfigRead := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: at.ConfigTargetTypeURI,
		Description: atGetConfigAction, Action: common.GetEngineConfigAction, SecretType: secretentry.SecretTypePublicCert, TargetResourceType: CA}
	atSecretConfigDelete := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: at.ConfigTargetTypeURI,
		Description: atDeleteConfigAction, Action: common.DeleteEngineConfigAction, SecretType: secretentry.SecretTypePublicCert, TargetResourceType: CA}

	//create clones of type field in order not override AllowedValues
	fieldType := *configFields[FieldType]
	fieldType.AllowedValues = GetCATypesAllowedValues()

	fields := map[string]*framework.FieldSchema{
		FieldName:   configFields[FieldName],
		FieldType:   &fieldType,
		FieldConfig: configFields[FieldConfig],
	}

	operationsWithoutPathParam := map[logical.Operation]framework.OperationHandler{
		logical.UpdateOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.pathConfigCreate, atSecretConfigUpdate),
			Summary:     createCAConfigOperationSummary,
			Description: createCAConfigOperationDescription,
		},
		logical.ReadOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.pathConfigList, atSecretConfigRead),
			Summary:     listCAConfigOperationSummary,
			Description: listCAConfigOperationDescription,
		},
	}

	operationsWithPathParam := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.pathConfigRead, atSecretConfigRead),
			Summary:     getCAConfigOperationSummary,
			Description: getCAConfigOperationDescription,
		},
		logical.UpdateOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.pathConfigUpdate, atSecretConfigUpdate),
			Summary:     updateCAConfigOperationSummary,
			Description: updateCAConfigOperationDescription,
		},
		logical.DeleteOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.pathConfigDelete, atSecretConfigDelete),
			Summary:     deleteCAConfigOperationSummary,
			Description: deleteCAConfigOperationDescription,
		},
	}

	return []*framework.Path{
		{
			Pattern:         ConfigCAPath,
			Fields:          fields,
			Operations:      operationsWithoutPathParam,
			HelpSynopsis:    pathCAConfigHelpSynopsis,
			HelpDescription: pathCAConfigHelpDescription,
		},
		{
			Pattern:         ConfigCAPath + "/" + framework.GenericNameRegex(FieldName),
			Fields:          fields,
			Operations:      operationsWithPathParam,
			HelpSynopsis:    pathCAConfigWithNameHelpSynopsis,
			HelpDescription: pathCAConfigWithNameHelpDescription,
		},
	}
}

func (ob *OrdersBackend) pathConfigDNS() []*framework.Path {
	atSecretConfigUpdate := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: at.ConfigTargetTypeURI,
		Description: atSetConfigAction, Action: common.SetEngineConfigAction, SecretType: secretentry.SecretTypePublicCert, TargetResourceType: DNS}
	atSecretConfigRead := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: at.ConfigTargetTypeURI,
		Description: atGetConfigAction, Action: common.GetEngineConfigAction, SecretType: secretentry.SecretTypePublicCert, TargetResourceType: DNS}
	atSecretConfigDelete := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: at.ConfigTargetTypeURI,
		Description: atDeleteConfigAction, Action: common.DeleteEngineConfigAction, SecretType: secretentry.SecretTypePublicCert, TargetResourceType: DNS}

	//create clones of type field in order not override AllowedValues
	fieldType := *configFields[FieldType]
	fieldType.AllowedValues = GetDNSTypesAllowedValues()

	fields := map[string]*framework.FieldSchema{
		FieldName:   configFields[FieldName],
		FieldType:   &fieldType,
		FieldConfig: configFields[FieldConfig],
	}

	operationsWithoutPathParam := map[logical.Operation]framework.OperationHandler{
		logical.UpdateOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.pathConfigCreate, atSecretConfigUpdate),
			Summary:     createDNSConfigOperationSummary,
			Description: createDNSConfigOperationDescription,
		},
		logical.ReadOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.pathConfigList, atSecretConfigRead),
			Summary:     listDNSConfigOperationSummary,
			Description: listDNSConfigOperationDescription,
		},
	}

	operationsWithPathParam := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.pathConfigRead, atSecretConfigRead),
			Summary:     getDNSConfigOperationSummary,
			Description: getDNSConfigOperationDescription,
		},
		logical.UpdateOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.pathConfigUpdate, atSecretConfigUpdate),
			Summary:     updateDNSConfigOperationSummary,
			Description: updateDNSConfigOperationDescription,
		},
		logical.DeleteOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.pathConfigDelete, atSecretConfigDelete),
			Summary:     deleteDNSConfigOperationSummary,
			Description: deleteDNSConfigOperationDescription,
		},
	}

	return []*framework.Path{
		{
			Pattern:         ConfigDNSPath,
			Fields:          fields,
			Operations:      operationsWithoutPathParam,
			HelpSynopsis:    pathDNSConfigHelpSynopsis,
			HelpDescription: pathDNSConfigHelpDescription,
		},
		{
			Pattern:         ConfigDNSPath + "/" + framework.GenericNameRegex(FieldName),
			Fields:          fields,
			Operations:      operationsWithPathParam,
			HelpSynopsis:    pathDNSConfigWithNameHelpSynopsis,
			HelpDescription: pathDNSConfigWithNameHelpDescription,
		},
	}
}

func (ob *OrdersBackend) pathConfigRoot() []*framework.Path {
	atSecretConfigRead := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: at.ConfigTargetTypeURI,
		Description: atGetConfigAction, Action: common.GetEngineConfigAction,
		SecretType: secretentry.SecretTypePublicCert, TargetResourceType: Root}
	fields := map[string]*framework.FieldSchema{}
	operations := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback:    ob.secretBackend.PathCallback(ob.pathRootConfigRead, atSecretConfigRead),
			Summary:     getRootConfigOperationSummary,
			Description: getRootConfigOperationDescription,
		},
	}
	return []*framework.Path{
		{
			Pattern:         ConfigRootPath,
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    pathRootConfigHelpSynopsis,
			HelpDescription: pathRootConfigHelpDescription,
		},
	}
}

//************* Endpoints ***************//
func (ob *OrdersBackend) pathConfigCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if common.ReadOnlyEnabled(ob.secretBackend.GetMetadataClient()) {
		common.Logger().Error("vault is in read only mode")
		return commonErrors.GenerateReadOnlyCodedErrorResponse()
	}

	//get config name
	name, err := ob.validateConfigName(d)
	if err != nil {
		return nil, err
	}
	//prepare AT context
	atContext := ctx.Value(at.AtContextKey).(*at.AtContext)
	atContext.ResourceName = name

	res, err := ob.validateRequest(ctx, req, d)
	if err != nil {
		return res, err
	}

	providerType := getProviderType(req)
	// lock for writing
	secretsConfigLock.Lock()
	defer secretsConfigLock.Unlock()
	// Get the storage entry
	rootConfig, err := getRootConfig(ctx, req.Storage)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToGetConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07001, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07001, http.StatusInternalServerError, internalServerError)
	}
	//get array of providers by type (ca or dns)
	allConfigs := rootConfig.getConfigsByProviderType(providerType)
	if len(allConfigs) == MaxNumberConfigs {
		errorMessage := fmt.Sprintf(reachedTheMaximum, providerType, MaxNumberConfigs)
		common.ErrorLogForCustomer(errorMessage, logdna.Error07002, logdna.BadRequestErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07002, http.StatusBadRequest, errorMessage)
	}
	//check if config with this name already exists
	for _, config := range allConfigs {
		if config.Name == name {
			errorMessage := fmt.Sprintf(nameAlreadyExists, providerType, name)
			common.ErrorLogForCustomer(errorMessage, logdna.Error07003, logdna.BadRequestErrorMessage, true)
			return nil, commonErrors.GenerateCodedError(logdna.Error07003, http.StatusBadRequest, errorMessage)
		}
	}
	err = ob.ordersHandler.configureIamIfNeeded(ctx, req)
	if err != nil {
		return nil, err
	}
	//create config to store
	configToStore, err := ob.createConfigToStore(name, providerType, d)
	if err != nil {
		return nil, err
	}
	//update array of configs
	allConfigs = append(allConfigs, configToStore)
	rootConfig.setConfigsByProviderType(providerType, allConfigs)
	//save root config
	err = rootConfig.save(ctx, req.Storage)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToSaveConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07004, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07004, http.StatusInternalServerError, internalServerError)
	}
	common.Logger().Info(fmt.Sprintf(configCreated, providerType, name))
	respData := make(map[string]interface{})
	respData[FieldName] = configToStore.Name
	respData[FieldType] = configToStore.Type
	//we don't want to return whole config, it may contain data we added (not user's)
	respData[FieldConfig] = configToStore.getConfigForResponse(providerType)
	resp := &logical.Response{
		Data: respData,
	}
	return logical.RespondWithStatusCode(resp, req, http.StatusCreated)
}

func (ob *OrdersBackend) pathConfigUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if common.ReadOnlyEnabled(ob.secretBackend.GetMetadataClient()) {
		common.Logger().Error("vault is in read only mode")
		return commonErrors.GenerateReadOnlyCodedErrorResponse()
	}

	//get config name
	name, err := ob.validateConfigName(d)
	if err != nil {
		return nil, err
	}
	//prepare AT context
	atContext := ctx.Value(at.AtContextKey).(*at.AtContext)
	atContext.ResourceName = name

	res, err := ob.validateRequest(ctx, req, d)
	if err != nil {
		return res, err
	}

	providerType := getProviderType(req)
	// lock for writing
	secretsConfigLock.Lock()
	defer secretsConfigLock.Unlock()
	// Get the storage entry
	rootConfig, err := getRootConfig(ctx, req.Storage)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToGetConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07005, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07005, http.StatusInternalServerError, internalServerError)
	}
	//get array of providers by type (ca or dns)
	allConfigs := rootConfig.getConfigsByProviderType(providerType)
	//for dns provider validation we may need configured iam
	err = ob.ordersHandler.configureIamIfNeeded(ctx, req)
	if err != nil {
		return nil, err
	}
	//create config to store
	configToStore, err := ob.createConfigToStore(name, providerType, d)
	if err != nil {
		return nil, err
	}
	//check if config with this name already exists, if yes, replace it
	found := false
	for i, config := range allConfigs {
		if config.Name == name {
			found = true
			allConfigs[i] = configToStore
			break
		}
	}
	if !found {
		errorMessage := fmt.Sprintf(configNotFound, providerType, name)
		common.ErrorLogForCustomer(errorMessage, logdna.Error07006, logdna.NotFoundErrorMessage, true)
		return nil, commonErrors.GenerateCodedError(logdna.Error07006, http.StatusNotFound, errorMessage)
	}
	//update array of configs
	rootConfig.setConfigsByProviderType(providerType, allConfigs)
	//save root config
	err = rootConfig.save(ctx, req.Storage)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToSaveConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07007, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07007, http.StatusInternalServerError, internalServerError)
	}
	common.Logger().Info(fmt.Sprintf(configUpdated, providerType, name))
	respData := make(map[string]interface{})
	respData[FieldName] = configToStore.Name
	respData[FieldType] = configToStore.Type
	//we don't want to return whole config, it may contain data we added (not user's)
	respData[FieldConfig] = configToStore.getConfigForResponse(providerType)
	resp := &logical.Response{
		Data: respData,
	}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)

}

func (ob *OrdersBackend) pathConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if common.ReadOnlyEnabled(ob.secretBackend.GetMetadataClient()) {
		common.Logger().Error("vault is in read only mode")
		return commonErrors.GenerateReadOnlyCodedErrorResponse()
	}

	//get config name
	name, err := ob.validateConfigName(d)
	if err != nil {
		return nil, err
	}
	//prepare AT context
	atContext := ctx.Value(at.AtContextKey).(*at.AtContext)
	atContext.ResourceName = name

	res, err := ob.validateRequest(ctx, req, d)
	if err != nil {
		return res, err
	}

	providerType := getProviderType(req)
	// lock for writing
	secretsConfigLock.Lock()
	defer secretsConfigLock.Unlock()
	// Get the storage entry
	rootConfig, err := getRootConfig(ctx, req.Storage)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToGetConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07008, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07008, http.StatusInternalServerError, internalServerError)
	}
	//get array of providers by type (ca or dns)
	allConfigs := rootConfig.getConfigsByProviderType(providerType)
	//check if config with this name exists
	foundConfig := -1
	for i, config := range allConfigs {
		if config.Name == name {
			foundConfig = i
			break
		}
	}
	if foundConfig == -1 {
		errorMessage := fmt.Sprintf(configNotFound, providerType, name)
		common.ErrorLogForCustomer(errorMessage, logdna.Error07009, logdna.NotFoundErrorMessage, true)
		return nil, commonErrors.GenerateCodedError(logdna.Error07009, http.StatusNotFound, errorMessage)
	}
	//remove found config from the array
	allConfigs = append(allConfigs[:foundConfig], allConfigs[foundConfig+1:]...)
	//update array of configs in root config
	rootConfig.setConfigsByProviderType(providerType, allConfigs)
	//save root config
	err = rootConfig.save(ctx, req.Storage)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToSaveConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07010, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07010, http.StatusInternalServerError, internalServerError)
	}
	common.Logger().Info(fmt.Sprintf(configDeleted, providerType, name))
	resp := &logical.Response{}
	return logical.RespondWithStatusCode(resp, req, http.StatusNoContent)
}

func (ob *OrdersBackend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	//get config name
	name, err := ob.validateConfigName(d)
	if err != nil {
		return nil, err
	}
	//prepare AT context
	atContext := ctx.Value(at.AtContextKey).(*at.AtContext)
	atContext.ResourceName = name

	res, err := ob.validateRequest(ctx, req, d)
	if err != nil {
		return res, err
	}

	providerType := getProviderType(req)
	foundConfig, err := getConfigByName(name, providerType, ctx, req, http.StatusNotFound)
	if err != nil {
		return nil, err
	}

	respData := make(map[string]interface{})
	respData[FieldName] = foundConfig.Name
	respData[FieldType] = foundConfig.Type
	//we don't want to return whole config, it may contain data we added (not user's)
	respData[FieldConfig] = foundConfig.getConfigForResponse(providerType)
	resp := &logical.Response{
		Data: respData,
	}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)
}

func (ob *OrdersBackend) pathConfigList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	res, err := ob.validateRequest(ctx, req, d)
	if err != nil {
		return res, err
	}
	//// lock for reading
	secretsConfigLock.RLock()
	defer secretsConfigLock.RUnlock()
	// Get the storage entry
	rootConfig, err := getRootConfig(ctx, req.Storage)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToGetConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07013, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07013, http.StatusInternalServerError, internalServerError)
	}
	providerType := getProviderType(req)
	respData := make(map[string]interface{})
	var responseProperty string
	if providerType == providerTypeCA {
		responseProperty = CA
	} else {
		responseProperty = DNS
	}
	respData[responseProperty] = rootConfig.getConfigsAsMap(providerType)
	resp := &logical.Response{
		Data: respData,
	}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)
}

func (ob *OrdersBackend) pathRootConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := ob.secretBackend.GetValidator().ValidateRequestIsAuthorised(ctx, req, common.GetEngineConfigAction, "")
	if err != nil {
		return nil, err
	}
	// lock for reading
	secretsConfigLock.RLock()
	defer secretsConfigLock.RUnlock()
	// Get the storage entry
	rootConfig, err := getRootConfig(ctx, req.Storage)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToGetConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07014, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07014, http.StatusInternalServerError, internalServerError)
	}
	respData := make(map[string]interface{})
	respData[CA] = rootConfig.getConfigsAsMap(providerTypeCA)
	respData[DNS] = rootConfig.getConfigsAsMap(providerTypeDNS)
	resp := &logical.Response{
		Data: respData,
	}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)
}

//************* Utils ***************//
func (ob *OrdersBackend) validateConfigName(d *framework.FieldData) (string, error) {
	name, err := ob.validateStringField(d, FieldName, "min=2,max=256", "length should be 2 to 256 chars")
	if err != nil {
		errorMessage := err.Error()
		common.ErrorLogForCustomer(errorMessage, logdna.Error07015, logdna.BadRequestErrorMessage, true)
		return "", commonErrors.GenerateCodedError(logdna.Error07015, http.StatusBadRequest, errorMessage)
	}
	if strings.Contains(name, " ") {
		common.ErrorLogForCustomer(configNameWithSpace, logdna.Error07043, logdna.BadRequestErrorMessage, true)
		return "", commonErrors.GenerateCodedError(logdna.Error07043, http.StatusBadRequest, configNameWithSpace)
	}
	return name, nil
}

func (ob *OrdersBackend) createConfigToStore(name string, providerType string, d *framework.FieldData) (*ProviderConfig, error) {
	configType, err := ob.validateStringField(d, FieldType, "min=2,max=128", "length should be 2 to 128 chars")
	if err != nil {
		errorMessage := err.Error()
		common.ErrorLogForCustomer(errorMessage, logdna.Error07016, logdna.BadRequestErrorMessage, true)
		return nil, commonErrors.GenerateCodedError(logdna.Error07016, http.StatusBadRequest, errorMessage)
	}
	config, ok := d.Get(FieldConfig).(map[string]string)
	if !ok || config == nil {
		common.ErrorLogForCustomer(configWrongStructure, logdna.Error07017, logdna.BadRequestErrorMessage, true)
		return nil, commonErrors.GenerateCodedError(logdna.Error07017, http.StatusBadRequest, configWrongStructure)
	}
	configToStore := NewProviderConfig(name, configType, config)
	if providerType == providerTypeCA {
		err = prepareCAConfigToStore(configToStore)
	} else {
		err = ob.prepareDNSConfigToStore(configToStore)
	}
	if err != nil {
		return nil, err
	}
	return configToStore, nil
}

func (ob *OrdersBackend) validateRequest(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// validate that the user is authorised to perform this action
	err := ob.secretBackend.GetValidator().ValidateRequestIsAuthorised(ctx, req, common.SetEngineConfigAction, "")
	if err != nil {
		return nil, err
	}
	// Validate user input
	if res, err := ob.secretBackend.GetValidator().ValidateUnknownFields(req, d); err != nil {
		return res, err
	}
	// Validate allowed values
	if res, err := ob.secretBackend.GetValidator().ValidateAllowedFieldValues(d); err != nil {
		return res, err
	}
	return nil, nil
}

func getConfigByName(name string, providerType string, ctx context.Context, req *logical.Request, notFoundStatus int) (*ProviderConfig, error) {
	// lock for reading
	secretsConfigLock.RLock()
	defer secretsConfigLock.RUnlock()
	// Get the storage entry
	rootConfig, err := getRootConfig(ctx, req.Storage)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToGetConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07011, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07011, http.StatusInternalServerError, internalServerError)
	}
	//get array of providers by type (ca or dns)
	allConfigs := rootConfig.getConfigsByProviderType(providerType)

	//check if config with this name  exists
	var foundConfig *ProviderConfig
	for _, config := range allConfigs {
		if config.Name == name {
			foundConfig = config
			break
		}
	}
	if foundConfig == nil {
		errorMessage := fmt.Sprintf(configNotFound, providerType, name)
		common.ErrorLogForCustomer(errorMessage, logdna.Error07012, logdna.NotFoundErrorMessage, true)
		return nil, commonErrors.GenerateCodedError(logdna.Error07012, notFoundStatus, errorMessage)
	}

	return foundConfig, nil
}

func getProviderType(req *logical.Request) string {
	var providerType string
	if strings.Contains(req.Path, ConfigCAPath) {
		providerType = providerTypeCA
	} else if strings.Contains(req.Path, ConfigDNSPath) {
		providerType = providerTypeDNS
	} else {
		providerType = "Can't happen"
	}
	return providerType
}
