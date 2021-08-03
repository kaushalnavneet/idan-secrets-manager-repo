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
			Callback: ob.secretBackend.PathCallback(ob.pathConfigCreate, atSecretConfigUpdate),
			Summary:  "Create the configuration value",
		},
		logical.ReadOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathConfigList, atSecretConfigRead),
			Summary:  "Get all the configuration values",
		},
	}

	operationsWithPathParam := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathConfigRead, atSecretConfigRead),
			Summary:  "Read the configuration value",
		},
		logical.UpdateOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathConfigUpdate, atSecretConfigUpdate),
			Summary:  "Update the configuration value",
		},
		logical.DeleteOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathConfigDelete, atSecretConfigDelete),
			Summary:  "Delete the configuration value",
		},
	}

	return []*framework.Path{
		{
			Pattern:         ConfigCAPath,
			Fields:          fields,
			Operations:      operationsWithoutPathParam,
			HelpSynopsis:    caConfigSyn,
			HelpDescription: caConfigDesc,
		},
		{
			Pattern:         ConfigCAPath + "/" + framework.GenericNameRegex(FieldName),
			Fields:          fields,
			Operations:      operationsWithPathParam,
			HelpSynopsis:    caConfigSyn,
			HelpDescription: caConfigDesc,
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
			Callback: ob.secretBackend.PathCallback(ob.pathConfigCreate, atSecretConfigUpdate),
			Summary:  "Create the configuration value",
		},
		logical.ReadOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathConfigList, atSecretConfigRead),
			Summary:  "Get all the configuration values",
		},
	}

	operationsWithPathParam := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathConfigRead, atSecretConfigRead),
			Summary:  "Read the configuration value",
		},
		logical.UpdateOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathConfigUpdate, atSecretConfigUpdate),
			Summary:  "Update the configuration value",
		},
		logical.DeleteOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathConfigDelete, atSecretConfigDelete),
			Summary:  "Delete the configuration value",
		},
	}

	return []*framework.Path{
		{
			Pattern:         ConfigDNSPath,
			Fields:          fields,
			Operations:      operationsWithoutPathParam,
			HelpSynopsis:    dnsConfigSyn,
			HelpDescription: dnsConfigDesc,
		},
		{
			Pattern:         ConfigDNSPath + "/" + framework.GenericNameRegex(FieldName),
			Fields:          fields,
			Operations:      operationsWithPathParam,
			HelpSynopsis:    dnsConfigSyn,
			HelpDescription: dnsConfigDesc,
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
			Summary:     GetRootConfigOpSummary,
			Description: GetRootConfigOpDesc,
		},
	}
	return []*framework.Path{
		{
			Pattern:         ConfigRootPath,
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    GetRootConfigHelpSyn,
			HelpDescription: GetRootConfigHelpDesc,
		},
	}
}

//************* Endpoints ***************//
func (ob *OrdersBackend) pathConfigCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
	rootConfig, err := getRootConfig(ctx, req)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToGetConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07012, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07012, http.StatusInternalServerError, internalServerError)
	}
	//get array of providers by type (ca or dns)
	allConfigs := rootConfig.getConfigsByProviderType(providerType)
	if len(allConfigs) == MaxNumberConfigs {
		errorMessage := fmt.Sprintf(reachedTheMaximum, providerType, MaxNumberConfigs)
		common.ErrorLogForCustomer(errorMessage, logdna.Error07033, logdna.BadRequestErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07033, http.StatusBadRequest, errorMessage)
	}
	//check if config with this name already exists
	for _, config := range allConfigs {
		if config.Name == name {
			errorMessage := fmt.Sprintf(nameAlreadyExists, providerType, name)
			common.ErrorLogForCustomer(errorMessage, logdna.Error07013, logdna.BadRequestErrorMessage, true)
			return nil, logical.CodedError(http.StatusBadRequest, errorMessage)
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
	err = rootConfig.save(ctx, req)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToSaveConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07015, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07015, http.StatusInternalServerError, internalServerError)
	}
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
	rootConfig, err := getRootConfig(ctx, req)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToGetConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07016, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07016, http.StatusInternalServerError, internalServerError)
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
		common.ErrorLogForCustomer(errorMessage, logdna.Error07020, logdna.NotFoundErrorMessage, true)
		return nil, commonErrors.GenerateCodedError(logdna.Error07020, http.StatusNotFound, errorMessage)
	}
	//update array of configs
	rootConfig.setConfigsByProviderType(providerType, allConfigs)
	//save root config
	err = rootConfig.save(ctx, req)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToSaveConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07021, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07021, http.StatusInternalServerError, internalServerError)
	}
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
	rootConfig, err := getRootConfig(ctx, req)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToGetConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07017, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07017, http.StatusInternalServerError, internalServerError)
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
		common.ErrorLogForCustomer(errorMessage, logdna.Error07031, logdna.NotFoundErrorMessage, true)
		return nil, commonErrors.GenerateCodedError(logdna.Error07031, http.StatusNotFound, errorMessage)
	}
	//remove found config from the array
	allConfigs = append(allConfigs[:foundConfig], allConfigs[foundConfig+1:]...)
	//update array of configs in root config
	rootConfig.setConfigsByProviderType(providerType, allConfigs)
	//save root config
	err = rootConfig.save(ctx, req)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToSaveConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07032, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07032, http.StatusInternalServerError, internalServerError)
	}

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
	foundConfig, err := getConfigByName(name, providerType, ctx, req)
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
	rootConfig, err := getRootConfig(ctx, req)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToGetConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07027, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07027, http.StatusInternalServerError, internalServerError)
	}
	providerType := getProviderType(req)
	respData := make(map[string]interface{})
	respData[CA] = rootConfig.getConfigsAsMap(providerType)
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
	if res, err := ob.secretBackend.GetValidator().ValidateUnknownFields(req, d); err != nil {
		return res, err
	}
	// lock for reading
	secretsConfigLock.RLock()
	defer secretsConfigLock.RUnlock()
	// Get the storage entry
	rootConfig, err := getRootConfig(ctx, req)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToGetConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07004, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07004, http.StatusInternalServerError, internalServerError)
	}
	respData := make(map[string]interface{})
	respData[CA] = rootConfig.getConfigsAsMap(providerTypeCA)
	respData[DNS] = rootConfig.getConfigsAsMap(providerTypeDNS)
	resp := &logical.Response{
		Data: respData,
	}
	return resp, nil
}

//************* Utils ***************//
func (ob *OrdersBackend) validateConfigName(d *framework.FieldData) (string, error) {
	name, err := ob.validateStringField(d, FieldName, "min=2,max=256", "length should be 2 to 256 chars")
	if err != nil {
		errorMessage := fmt.Sprintf("Parameter validation error: %s", err.Error())
		common.ErrorLogForCustomer(errorMessage, logdna.Error07052, logdna.BadRequestErrorMessage, true)
		return "", commonErrors.GenerateCodedError(logdna.Error07052, http.StatusBadRequest, errorMessage)
	}
	return name, nil
}

func (ob *OrdersBackend) createConfigToStore(name string, providerType string, d *framework.FieldData) (*ProviderConfig, error) {
	configType, err := ob.validateStringField(d, FieldType, "min=2,max=128", "length should be 2 to 128 chars")
	if err != nil {
		return nil, err
	}
	config, ok := d.Get(FieldConfig).(map[string]string)
	if !ok || config == nil {
		return nil, fmt.Errorf("config field is not valid. It should be key-value map")
	}
	configToStore := NewProviderConfig(name, configType, config)

	if providerType == providerTypeCA {
		err = prepareCAConfigToStore(configToStore)
	} else {
		err = prepareDNSConfigToStore(configToStore, ob.ordersHandler.smInstanceCrn)
	}
	if err != nil {
		errorMessage := fmt.Sprintf(validationError, err.Error())
		common.ErrorLogForCustomer(errorMessage, logdna.Error07014, logdna.BadRequestErrorMessage, true)
		return nil, commonErrors.GenerateCodedError(logdna.Error07014, http.StatusBadRequest, errorMessage)
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

func getConfigByName(name string, providerType string, ctx context.Context, req *logical.Request) (*ProviderConfig, error) {
	// lock for reading
	secretsConfigLock.RLock()
	defer secretsConfigLock.RUnlock()
	// Get the storage entry
	rootConfig, err := getRootConfig(ctx, req)
	if err != nil {
		common.Logger().Error(fmt.Sprintf(failedToGetConfigError, err.Error()))
		common.ErrorLogForCustomer(internalServerError, logdna.Error07024, logdna.InternalErrorMessage, false)
		return nil, commonErrors.GenerateCodedError(logdna.Error07024, http.StatusInternalServerError, internalServerError)
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
		common.ErrorLogForCustomer(errorMessage, logdna.Error07025, logdna.NotFoundErrorMessage, true)
		return nil, logical.CodedError(http.StatusNotFound, errorMessage)
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
