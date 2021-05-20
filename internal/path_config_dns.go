package publiccerts

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	at "github.ibm.com/security-services/secrets-manager-vault-plugins-common/activity_tracker"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"net/http"
)

func (ob *OrdersBackend) pathConfigDNS() []*framework.Path {
	//todo move const to secretentry
	atSecretConfigUpdate := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: "secrets-manager/secret-engine-config",
		Description: "Set secret engine configuration", Action: "secrets-manager.secret-engine-config.set", SecretType: SecretTypePublicCert}
	atSecretConfigRead := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: "secrets-manager/secret-engine-config",
		Description: "Get secret engine configuration", Action: common.GetEngineConfigAction, SecretType: SecretTypePublicCert}

	fields := map[string]*framework.FieldSchema{
		FieldName: {
			Type:        framework.TypeString,
			Description: "Specifies the dns provider name.",
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
			Callback: ob.secretBackend.PathCallback(ob.pathDnsConfigList, atSecretConfigUpdate),
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
			Callback: ob.secretBackend.PathCallback(ob.pathDnsConfigDelete, atSecretConfigUpdate),
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

// Create or update the IBM Cloud Auth backend configuration
func (ob *OrdersBackend) pathDnsConfigCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// validate that the user is authorised to perform this action
	//TODO check action to authorize
	if err := ob.Auth.ValidateRequestIsAuthorised(ctx, req, common.SetEngineConfigAction, ""); err != nil {
		if _, ok := err.(logical.HTTPCodedError); ok {
			common.ErrorLogForCustomer("Internal server error", logdna.Error03078, logdna.InternalErrorMessage)
			return nil, err
		}
		common.ErrorLogForCustomer(err.Error(), logdna.Error03079, logdna.PermissionErrorMessage)
		return nil, err
	}

	// Validate user input
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), logdna.Error03080, "There are unexpected fields. Verify that the request parameters are valid")
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}
	// lock for writing
	secretsConfigLock.Lock()
	defer secretsConfigLock.Unlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		common.Logger().Error("Failed to get root configuration from storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", logdna.Error03087, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to get configuration from the storage: %s", err.Error())
	}
	name := d.Get(FieldName).(string)
	if name == "" {
		return nil, fmt.Errorf("name field is empty")
	}
	//check if config with this name already exists
	for _, caConfig := range config.ProviderConfigs {
		if caConfig.Name == name {
			common.Logger().Error("DNS provider configuration with this name already exists.", "name", name, "error", err)
			//TODO What is errorcode??
			common.ErrorLogForCustomer("Bad Request", logdna.Error03087, logdna.BadRequestErrorMessage)
			return nil, fmt.Errorf("DNS provider configuration with name %s already exists", name)
		}
	}

	configToStore, err := createProviderConfigToStore(d)
	if err != nil {
		common.Logger().Error("Parameters validation error.", "error", err)
		//TODO What is errorcode??
		common.ErrorLogForCustomer("Bad Request", logdna.Error03087, logdna.BadRequestErrorMessage)
		return nil, fmt.Errorf("parameters validation error: %s", err.Error())

	}
	config.ProviderConfigs = append(config.ProviderConfigs, configToStore)

	err = putRootConfig(ctx, req, config)
	// Get the storage entry
	if err != nil {
		common.Logger().Error("Failed to save root configuration to storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", logdna.Error03087, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to persist configuration to storage: %s", err.Error())
	}

	resp := &logical.Response{}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)
}

// Create or update the IBM Cloud Auth backend configuration
func (ob *OrdersBackend) pathDnsConfigUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// validate that the user is authorised to perform this action
	if err := ob.Auth.ValidateRequestIsAuthorised(ctx, req, common.SetEngineConfigAction, ""); err != nil {
		if _, ok := err.(logical.HTTPCodedError); ok {
			common.ErrorLogForCustomer("Internal server error", logdna.Error03078, logdna.InternalErrorMessage)
			return nil, err
		}
		common.ErrorLogForCustomer(err.Error(), logdna.Error03079, logdna.PermissionErrorMessage)
		return nil, err
	}

	// Validate user input
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), logdna.Error03080, "There are unexpected fields. Verify that the request parameters are valid")
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	configToStore, err := createProviderConfigToStore(d)
	if err != nil {
		common.Logger().Error("Parameters validation error.", "error", err)
		//TODO What is errorcode??
		common.ErrorLogForCustomer("Bad Request", logdna.Error03087, logdna.BadRequestErrorMessage)
		return nil, fmt.Errorf("parameters validation error: %s", err.Error())
	}

	// lock for writing
	secretsConfigLock.Lock()
	defer secretsConfigLock.Unlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		common.Logger().Error("Failed to get root configuration from storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", logdna.Error03087, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to get configuration from the storage: %s", err.Error())
	}
	name := d.Get(FieldName).(string)
	//check if config with this name already exists
	found := false
	for i, caConfig := range config.ProviderConfigs {
		if caConfig.Name == name {
			found = true
			config.ProviderConfigs[i] = configToStore
			break
		}
	}
	if !found {
		common.Logger().Error("DNS provider configuration with this name was not found.", "name", name, "error", err)
		//TODO What is errorcode??
		common.ErrorLogForCustomer("Not Found", logdna.Error03087, logdna.NotFoundErrorMessage)
		return nil, fmt.Errorf("DNS provider configuration with name '%s' was not found", name)
	}

	err = putRootConfig(ctx, req, config)
	// Get the storage entry
	if err != nil {
		common.Logger().Error("Failed to save root configuration to storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", logdna.Error03087, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to persist configuration to storage: %s", err.Error())
	}

	resp := &logical.Response{}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)
}

// Read the IBM Cloud Auth backend configuration from storage
func (ob *OrdersBackend) pathDnsConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	//validate that the user is authorised to perform this action
	if err := ob.Auth.ValidateRequestIsAuthorised(ctx, req, common.GetEngineConfigAction, ""); err != nil {
		if _, ok := err.(logical.HTTPCodedError); ok {
			common.ErrorLogForCustomer("Internal server error", logdna.Error03088, logdna.InternalErrorMessage)
			return nil, err
		}
		common.ErrorLogForCustomer(err.Error(), logdna.Error03089, logdna.PermissionErrorMessage)
		return nil, err
	}
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), logdna.Error03090, "There are unexpected fields. Verify that the request parameters are valid")
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}
	name := d.Get(FieldName).(string)
	//// lock for reading
	secretsConfigLock.RLock()
	defer secretsConfigLock.RUnlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		common.Logger().Error("Failed to get root configuration from storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", logdna.Error03087, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to get configuration from the storage: %s", err.Error())
	}
	//check if config with this name  exists
	var foundConfig *DnsProviderConfig
	for _, caConfig := range config.ProviderConfigs {
		if caConfig.Name == name {
			foundConfig = caConfig
		}
	}
	if foundConfig == nil {
		common.Logger().Error("DNS provider configuration with this name was not found.", "name", name, "error", err)
		//TODO What is errorcode??
		common.ErrorLogForCustomer("Not Found", logdna.Error03087, logdna.NotFoundErrorMessage)
		return nil, fmt.Errorf("DNS provider configuration with name '%s' was not found", name)
	}
	respData := make(map[string]interface{})

	respData[FieldName] = common.GetNonEmptyStringFirstOrSecond(foundConfig.Name, d.GetDefaultOrZero(FieldName).(string))
	respData[FieldConfig] = foundConfig.Config

	resp := &logical.Response{
		Data: respData,
	}
	return resp, nil
}

func (ob *OrdersBackend) pathDnsConfigList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	//validate that the user is authorised to perform this action
	if err := ob.Auth.ValidateRequestIsAuthorised(ctx, req, common.GetEngineConfigAction, ""); err != nil {
		if _, ok := err.(logical.HTTPCodedError); ok {
			common.ErrorLogForCustomer("Internal server error", logdna.Error03088, logdna.InternalErrorMessage)
			return nil, err
		}
		common.ErrorLogForCustomer(err.Error(), logdna.Error03089, logdna.PermissionErrorMessage)
		return nil, err
	}
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), logdna.Error03090, "There are unexpected fields. Verify that the request parameters are valid")
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	//// lock for reading
	secretsConfigLock.RLock()
	defer secretsConfigLock.RUnlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		common.Logger().Error("Failed to get root configuration from storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", logdna.Error03087, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to get configuration from the storage: %s", err.Error())
	}

	respData := make(map[string]interface{})
	respData["dns_providers"] = config.ProviderConfigs
	resp := &logical.Response{
		Data: respData,
	}
	return resp, nil
}

func (ob *OrdersBackend) pathDnsConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	//validate that the user is authorised to perform this action
	//TODO what is action??
	if err := ob.Auth.ValidateRequestIsAuthorised(ctx, req, common.SetEngineConfigAction, ""); err != nil {
		if _, ok := err.(logical.HTTPCodedError); ok {
			common.ErrorLogForCustomer("Internal server error", logdna.Error03088, logdna.InternalErrorMessage)
			return nil, err
		}
		common.ErrorLogForCustomer(err.Error(), logdna.Error03089, logdna.PermissionErrorMessage)
		return nil, err
	}
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), logdna.Error03090, "There are unexpected fields. Verify that the request parameters are valid")
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}
	name := d.Get(FieldName).(string)
	// lock for writing
	secretsConfigLock.Lock()
	defer secretsConfigLock.Unlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		common.Logger().Error("Failed to get root configuration from storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", logdna.Error03087, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to get configuration from the storage: %s", err.Error())
	}
	//check if config with this name already exists
	foundConfig := -1
	for i, caConfig := range config.ProviderConfigs {
		if caConfig.Name == name {
			foundConfig = i
		}
	}
	if foundConfig == -1 {
		common.Logger().Error("DNS provider configuration with this name was not found.", "name", name, "error", err)
		//TODO What is errorcode??
		common.ErrorLogForCustomer("Not Found", logdna.Error03087, logdna.NotFoundErrorMessage)
		return nil, fmt.Errorf("DNS provider configuration with name '%s' was not found", name)
	}
	config.ProviderConfigs = append(config.ProviderConfigs[:foundConfig], config.ProviderConfigs[foundConfig+1:]...)

	err = putRootConfig(ctx, req, config)
	// Get the storage entry
	if err != nil {
		common.Logger().Error("Failed to save root configuration to storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", logdna.Error03087, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to persist configuration to storage: %s", err.Error())
	}

	resp := &logical.Response{}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)
}

func createProviderConfigToStore(d *framework.FieldData) (*DnsProviderConfig, error) {
	name := d.Get(FieldName).(string)
	config := d.Get(FieldConfig).(map[string]string)
	if config == nil {
		return nil, fmt.Errorf("config field is empty")
	}
	p := NewDnsProviderConfig(name, config)
	return p, nil
}

//TODO update this text
const dnsConfigSyn = "Read and Update the root configuration containing the IAM API key that is used to generate IAM credentials."
const dnsConfigDesc = `Read and update the IAM API key that will be used to generate IAM credentials.
To allow the secret engine to generate IAM credentials for you,
this IAM API key should have Editor role (IAM role) on both the IAM Identity Service and the IAM Access Groups Service.`
