package publiccerts

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	at "github.ibm.com/security-services/secrets-manager-vault-plugins-common/activity_tracker"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"net/http"
)

func (ob *OrdersBackend) pathConfigDNS() []*framework.Path {
	atSecretConfigUpdate := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: ConfigTargetTypeURI,
		Description: "Set secret engine configuration", Action: common.SetEngineConfigAction, SecretType: SecretTypePublicCert, TargetResourceType: DNS}
	atSecretConfigRead := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: ConfigTargetTypeURI,
		Description: "Get secret engine configuration", Action: common.GetEngineConfigAction, SecretType: SecretTypePublicCert, TargetResourceType: DNS}
	atSecretConfigDelete := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: ConfigTargetTypeURI,
		Description: "Delete secret engine configuration", Action: DeleteEngineConfigAction, SecretType: SecretTypePublicCert, TargetResourceType: DNS}

	fields := map[string]*framework.FieldSchema{
		secretentry.FieldName: {
			Type:        framework.TypeString,
			Description: "Specifies the dns provider name.",
			Required:    true,
		},
		FieldType: {
			Type:        framework.TypeString,
			Description: "Specifies the dns provider type.",
			Required:    true,
		},
		FieldConfig: {
			Type:        framework.TypeKVPairs,
			Description: "Specifies the set of dns provider properties.",
			Required:    true,
		},
	}
	operationsWithoutPathParam := map[logical.Operation]framework.OperationHandler{
		logical.UpdateOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathDnsConfigCreate, atSecretConfigUpdate),
			Summary:  "Create the configuration value",
		},
		logical.ReadOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathDnsConfigList, atSecretConfigRead),
			Summary:  "Get all the configuration values",
		},
	}

	operationsWithPathParam := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathDnsConfigRead, atSecretConfigRead),
			Summary:  "Read the configuration value",
		},
		logical.UpdateOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathDnsConfigUpdate, atSecretConfigUpdate),
			Summary:  "Update the configuration value",
		},
		logical.DeleteOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathDnsConfigDelete, atSecretConfigDelete),
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
			Pattern:         ConfigDNSPath + "/" + framework.GenericNameRegex(secretentry.FieldName),
			Fields:          fields,
			Operations:      operationsWithPathParam,
			HelpSynopsis:    dnsConfigSyn,
			HelpDescription: dnsConfigDesc,
		},
	}
}

// Create or update the IBM Cloud Auth backend configuration
func (ob *OrdersBackend) pathDnsConfigCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// validate that the user is authorised to perform this action
	err := ob.checkAuthorization(ctx, req, common.SetEngineConfigAction)
	if err != nil {
		return nil, err
	}
	//get config name
	name, err := ob.validateStringField(d, secretentry.FieldName, "min=2,max=512", "length should be 2 to 512 chars")
	if err != nil {
		errorMessage := fmt.Sprintf("Parameters validation error: %s", err.Error())
		common.ErrorLogForCustomer(errorMessage, logdna.Error07040, logdna.BadRequestErrorMessage, true)
		return nil, logical.CodedError(http.StatusBadRequest, errorMessage)
	}

	//prepare AT context
	atContext := ctx.Value(at.AtContextKey).(*at.AtContext)
	atContext.ResourceName = name

	// Validate user input
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), logdna.Error07041, "There are unexpected fields. Verify that the request parameters are valid", true)
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}
	// lock for writing
	secretsConfigLock.Lock()
	defer secretsConfigLock.Unlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to get configuration from the storage: %s", err.Error())
		common.Logger().Error(errorMessage)
		common.ErrorLogForCustomer("Internal server error", logdna.Error07042, logdna.InternalErrorMessage, false)
		return nil, errors.New(errorMessage)
	}

	//check if config with this name already exists
	for _, caConfig := range config.ProviderConfigs {
		if caConfig.Name == name {
			errorMessage := fmt.Sprintf("DNS provider configuration with name '%s' already exists", name)
			common.ErrorLogForCustomer(errorMessage, logdna.Error07043, logdna.BadRequestErrorMessage, true)
			return nil, logical.CodedError(http.StatusBadRequest, errorMessage)
		}
	}
	configToStore, err := createProviderConfigToStore(name, d)
	if err != nil {
		errorMessage := fmt.Sprintf("Parameters validation error: %s", err.Error())
		common.ErrorLogForCustomer(errorMessage, logdna.Error07044, logdna.BadRequestErrorMessage, true)
		return nil, logical.CodedError(http.StatusBadRequest, errorMessage)
	}
	config.ProviderConfigs = append(config.ProviderConfigs, configToStore)

	err = putRootConfig(ctx, req, config)
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to save configuration to the storage: %s", err.Error())
		common.Logger().Error(errorMessage)
		common.ErrorLogForCustomer("Internal server error", logdna.Error07045, logdna.InternalErrorMessage, false)
		return nil, errors.New(errorMessage)
	}

	respData := make(map[string]interface{})
	respData[secretentry.FieldName] = configToStore.Name
	respData[FieldType] = configToStore.Type
	respData[FieldConfig] = configToStore.Config
	resp := &logical.Response{
		Data: respData,
	}
	return logical.RespondWithStatusCode(resp, req, http.StatusCreated)
}

// Create or update the IBM Cloud Auth backend configuration
func (ob *OrdersBackend) pathDnsConfigUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// validate that the user is authorised to perform this action
	err := ob.checkAuthorization(ctx, req, common.SetEngineConfigAction)
	if err != nil {
		return nil, err
	}
	//get config name
	name, err := ob.validateStringField(d, secretentry.FieldName, "min=2,max=512", "length should be 2 to 512 chars")
	if err != nil {
		errorMessage := fmt.Sprintf("Parameters validation error: %s", err.Error())
		common.ErrorLogForCustomer(errorMessage, logdna.Error07046, logdna.BadRequestErrorMessage, true)
		return nil, logical.CodedError(http.StatusBadRequest, errorMessage)
	}

	//prepare AT context
	atContext := ctx.Value(at.AtContextKey).(*at.AtContext)
	atContext.ResourceName = name
	// Validate user input
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), logdna.Error07047, "There are unexpected fields. Verify that the request parameters are valid", true)
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	configToStore, err := createProviderConfigToStore(name, d)
	if err != nil {
		errorMessage := fmt.Sprintf("Parameters validation error: %s", err.Error())
		common.ErrorLogForCustomer(errorMessage, logdna.Error07048, logdna.BadRequestErrorMessage, true)
		return nil, logical.CodedError(http.StatusBadRequest, errorMessage)
	}

	// lock for writing
	secretsConfigLock.Lock()
	defer secretsConfigLock.Unlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to get configuration from the storage: %s", err.Error())
		common.Logger().Error(errorMessage)
		common.ErrorLogForCustomer("Internal server error", logdna.Error07049, logdna.InternalErrorMessage, false)
		return nil, errors.New(errorMessage)
	}
	//check if config with this name exists
	found := false
	for i, caConfig := range config.ProviderConfigs {
		if caConfig.Name == name {
			found = true
			config.ProviderConfigs[i] = configToStore
			break
		}
	}
	if !found {
		errorMessage := fmt.Sprintf("DNS provider configuration with name '%s' was not found", name)
		common.ErrorLogForCustomer(errorMessage, logdna.Error07050, logdna.NotFoundErrorMessage, true)
		return nil, logical.CodedError(http.StatusNotFound, errorMessage)
	}

	err = putRootConfig(ctx, req, config)
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to save configuration to the storage: %s", err.Error())
		common.Logger().Error(errorMessage)
		common.ErrorLogForCustomer("Internal server error", logdna.Error07051, logdna.InternalErrorMessage, false)
		return nil, errors.New(errorMessage)
	}

	respData := make(map[string]interface{})
	respData[secretentry.FieldName] = configToStore.Name
	respData[FieldType] = configToStore.Type
	respData[FieldConfig] = configToStore.Config
	resp := &logical.Response{
		Data: respData,
	}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)

}

// Read the IBM Cloud Auth backend configuration from storage
func (ob *OrdersBackend) pathDnsConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// validate that the user is authorised to perform this action
	err := ob.checkAuthorization(ctx, req, common.GetEngineConfigAction)
	if err != nil {
		return nil, err
	}
	//get config name
	name, err := ob.validateStringField(d, secretentry.FieldName, "min=2,max=512", "length should be 2 to 512 chars")
	if err != nil {
		errorMessage := fmt.Sprintf("Parameters validation error: %s", err.Error())
		common.ErrorLogForCustomer(errorMessage, logdna.Error07052, logdna.BadRequestErrorMessage, true)
		return nil, logical.CodedError(http.StatusBadRequest, errorMessage)
	}

	//prepare AT context
	atContext := ctx.Value(at.AtContextKey).(*at.AtContext)
	atContext.ResourceName = name
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), logdna.Error07053, "There are unexpected fields. Verify that the request parameters are valid", true)
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	foundConfig, err := getDNSConfigByName(ctx, req, name)
	if err != nil {
		return nil, err
	}

	respData := make(map[string]interface{})
	respData[secretentry.FieldName] = foundConfig.Name
	respData[FieldType] = foundConfig.Type
	respData[FieldConfig] = foundConfig.Config
	resp := &logical.Response{
		Data: respData,
	}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)
}

func (ob *OrdersBackend) pathDnsConfigList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// validate that the user is authorised to perform this action
	err := ob.checkAuthorization(ctx, req, common.GetEngineConfigAction)
	if err != nil {
		return nil, err
	}

	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), logdna.Error07057, "There are unexpected fields. Verify that the request parameters are valid", true)
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// lock for reading
	secretsConfigLock.RLock()
	defer secretsConfigLock.RUnlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to get configuration from the storage: %s", err.Error())
		common.Logger().Error(errorMessage)
		common.ErrorLogForCustomer("Internal server error", logdna.Error07058, logdna.InternalErrorMessage, false)
		return nil, errors.New(errorMessage)
	}

	respData := make(map[string]interface{})
	confArray := getDNSConfigsAsMap(config)
	respData[DNS] = confArray
	resp := &logical.Response{
		Data: respData,
	}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)
}

func (ob *OrdersBackend) pathDnsConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// validate that the user is authorised to perform this action
	err := ob.checkAuthorization(ctx, req, common.SetEngineConfigAction)
	if err != nil {
		return nil, err
	}
	//get config name
	name, err := ob.validateStringField(d, secretentry.FieldName, "min=2,max=512", "length should be 2 to 512 chars")
	if err != nil {
		errorMessage := fmt.Sprintf("Parameters validation error: %s", err.Error())
		common.ErrorLogForCustomer(errorMessage, logdna.Error07059, logdna.BadRequestErrorMessage, true)
		return nil, logical.CodedError(http.StatusBadRequest, errorMessage)
	}
	//prepare AT context
	atContext := ctx.Value(at.AtContextKey).(*at.AtContext)
	atContext.ResourceName = name

	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), logdna.Error07060, "There are unexpected fields. Verify that the request parameters are valid", true)
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}
	// lock for writing
	secretsConfigLock.Lock()
	defer secretsConfigLock.Unlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to get configuration from the storage: %s", err.Error())
		common.Logger().Error(errorMessage)
		common.ErrorLogForCustomer("Internal server error", logdna.Error07061, logdna.InternalErrorMessage, false)
		return nil, errors.New(errorMessage)
	}
	//check if config with this name already exists
	foundConfig := -1
	for i, caConfig := range config.ProviderConfigs {
		if caConfig.Name == name {
			foundConfig = i
			break
		}
	}
	if foundConfig == -1 {
		errorMessage := fmt.Sprintf("DNS provider configuration with name '%s' was not found", name)
		common.ErrorLogForCustomer(errorMessage, logdna.Error07062, logdna.NotFoundErrorMessage, true)
		return nil, logical.CodedError(http.StatusNotFound, errorMessage)
	}
	config.ProviderConfigs = append(config.ProviderConfigs[:foundConfig], config.ProviderConfigs[foundConfig+1:]...)

	err = putRootConfig(ctx, req, config)
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to save configuration to the storage: %s", err.Error())
		common.Logger().Error(errorMessage)
		common.ErrorLogForCustomer("Internal server error", logdna.Error07063, logdna.InternalErrorMessage, false)
		return nil, errors.New(errorMessage)
	}

	resp := &logical.Response{}
	return logical.RespondWithStatusCode(resp, req, http.StatusNoContent)
}

func createProviderConfigToStore(name string, d *framework.FieldData) (*DnsProviderConfig, error) {
	//TODO add config validation according to provider type
	providerType := d.Get(FieldType).(string)
	if providerType == "" {
		return nil, fmt.Errorf("type field is empty")
	}
	config := d.Get(FieldConfig).(map[string]string)
	if config == nil {
		return nil, fmt.Errorf("config field is empty")
	}
	p := NewDnsProviderConfig(name, providerType, config)
	return p, nil
}

func getDNSConfigByName(ctx context.Context, req *logical.Request, name string) (*DnsProviderConfig, error) {
	// lock for reading
	secretsConfigLock.RLock()
	defer secretsConfigLock.RUnlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to get configuration from the storage: %s", err.Error())
		common.Logger().Error(errorMessage)
		common.ErrorLogForCustomer("Internal server error", logdna.Error07054, logdna.InternalErrorMessage, false)
		return nil, errors.New(errorMessage)
	}
	//check if config with this name  exists
	var foundConfig *DnsProviderConfig
	for _, caConfig := range config.ProviderConfigs {
		if caConfig.Name == name {
			foundConfig = caConfig
			break
		}
	}
	if foundConfig == nil {
		errorMessage := fmt.Sprintf("DNS provider configuration with name '%s' was not found", name)
		common.ErrorLogForCustomer(errorMessage, logdna.Error07055, logdna.NotFoundErrorMessage, true)
		return nil, logical.CodedError(http.StatusNotFound, errorMessage)
	}
	return foundConfig, nil
}

//TODO update this text
const dnsConfigSyn = "Read and Update the dns provider configuration."
const dnsConfigDesc = "Read and Update the dns provider configuration."
