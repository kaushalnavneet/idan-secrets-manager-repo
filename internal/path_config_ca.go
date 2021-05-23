package publiccerts

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	at "github.ibm.com/security-services/secrets-manager-vault-plugins-common/activity_tracker"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"net/http"
)

var secretsConfigLock locksutil.LockEntry

func (ob *OrdersBackend) pathConfigCA() []*framework.Path {
	//todo TargetTypeURI
	atSecretConfigUpdate := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: "secrets-manager/secret-engine-config",
		Description: "Set secret engine configuration", Action: common.SetEngineConfigAction, SecretType: SecretTypePublicCert}
	atSecretConfigRead := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: "secrets-manager/secret-engine-config",
		Description: "Get secret engine configuration", Action: common.GetEngineConfigAction, SecretType: SecretTypePublicCert}

	fields := map[string]*framework.FieldSchema{
		FieldName: {
			Type:        framework.TypeString,
			Description: "Specifies the ACME CA name.",
			Required:    true,
		},
		FieldDirectoryUrl: {
			Type:        framework.TypeString,
			Description: "Specifies the directory url of the ACME server.",
			Required:    true,
		},
		FieldCaCert: {
			Type:        framework.TypeString,
			Description: "Path to the root certificate of the ACME CA server.",
			Required:    false,
		},
		FieldEmail: {
			Type:        framework.TypeString,
			Description: "Email to be used for registering the user. If a user account is being retrieved, then the retrieved email will override this field",
			Required:    false,
		},
		FieldPrivateKey: {
			Type:        framework.TypeString,
			Description: "Private key in PKCS8 PEM encoded format to retrieve an existing account",
			Required:    true,
		},
		FieldRegistrationUrl: {
			Type:        framework.TypeString,
			Description: "Registration URL of an existing account",
			Required:    true,
		},
	}
	operationsWithoutPathParam := map[logical.Operation]framework.OperationHandler{
		logical.UpdateOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathCAConfigCreate, atSecretConfigUpdate),
			Summary:  "Create the configuration value",
		},
		logical.ReadOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathCAConfigList, atSecretConfigRead),
			Summary:  "Get all the configuration values",
		},
	}

	operationsWithPathParam := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathCAConfigRead, atSecretConfigRead),
			Summary:  "Read the configuration value",
		},
		logical.UpdateOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathCAConfigUpdate, atSecretConfigUpdate),
		},
		logical.DeleteOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathCAConfigDelete, atSecretConfigUpdate),
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

// Create or update the IBM Cloud Auth backend configuration
func (ob *OrdersBackend) pathCAConfigCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// validate that the user is authorised to perform this action
	//TODO check action to authorize
	if err := ob.Auth.ValidateRequestIsAuthorised(ctx, req, common.SetEngineConfigAction, ""); err != nil {
		if _, ok := err.(logical.HTTPCodedError); ok {
			common.ErrorLogForCustomer("Internal server error", Error07005, logdna.InternalErrorMessage)
			return nil, err
		}
		common.ErrorLogForCustomer(err.Error(), Error07006, logdna.PermissionErrorMessage)
		return nil, err
	}

	// Validate user input
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), Error07007, "There are unexpected fields. Verify that the request parameters are valid")
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}
	// lock for writing
	secretsConfigLock.Lock()
	defer secretsConfigLock.Unlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		common.Logger().Error("Failed to get root configuration from storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", Error07031, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to get configuration from the storage: %s", err.Error())
	}
	name := d.Get(FieldName).(string)
	//check if config with this name already exists
	for _, caConfig := range config.CaConfigs {
		if caConfig.Name == name {
			common.Logger().Error("CA configuration with this name already exists.", "name", name, "error", err)
			common.ErrorLogForCustomer("Bad Request", Error07032, logdna.BadRequestErrorMessage)
			return nil, fmt.Errorf("CA configuration with name %s already exists", name)
		}
	}

	configToStore, err := createCAConfigToStore(d)
	if err != nil {
		common.Logger().Error("Parameters validation error.", "error", err)
		common.ErrorLogForCustomer("Bad Request", Error07033, logdna.BadRequestErrorMessage)
		return nil, fmt.Errorf("parameters validation error: %s", err.Error())

	}
	config.CaConfigs = append(config.CaConfigs, configToStore)

	err = putRootConfig(ctx, req, config)
	// Get the storage entry
	if err != nil {
		common.Logger().Error("Failed to save root configuration to storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", Error07034, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to persist configuration to storage: %s", err.Error())
	}

	resp := &logical.Response{}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)
}

// Create or update the IBM Cloud Auth backend configuration
func (ob *OrdersBackend) pathCAConfigUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// validate that the user is authorised to perform this action
	if err := ob.Auth.ValidateRequestIsAuthorised(ctx, req, common.SetEngineConfigAction, ""); err != nil {
		if _, ok := err.(logical.HTTPCodedError); ok {
			common.ErrorLogForCustomer("Internal server error", Error07035, logdna.InternalErrorMessage)
			return nil, err
		}
		common.ErrorLogForCustomer(err.Error(), Error07036, logdna.PermissionErrorMessage)
		return nil, err
	}

	// Validate user input
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), Error07037, "There are unexpected fields. Verify that the request parameters are valid")
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	configToStore, err := createCAConfigToStore(d)
	if err != nil {
		common.Logger().Error("Parameters validation error.", "error", err)

		common.ErrorLogForCustomer("Bad Request", Error07038, logdna.BadRequestErrorMessage)
		return nil, fmt.Errorf("parameters validation error: %s", err.Error())
	}

	// lock for writing
	secretsConfigLock.Lock()
	defer secretsConfigLock.Unlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		common.Logger().Error("Failed to get root configuration from storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", Error07039, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to get configuration from the storage: %s", err.Error())
	}
	name := d.Get(FieldName).(string)
	//check if config with this name already exists
	found := false
	for i, caConfig := range config.CaConfigs {
		if caConfig.Name == name {
			found = true
			config.CaConfigs[i] = configToStore
			break
		}
	}
	if !found {
		common.Logger().Error("CA configuration with this name was not found.", "name", name, "error", err)

		common.ErrorLogForCustomer("Not Found", Error07040, logdna.NotFoundErrorMessage)
		return nil, fmt.Errorf("CA configuration with name '%s' was not found", name)
	}

	err = putRootConfig(ctx, req, config)
	// Get the storage entry
	if err != nil {
		common.Logger().Error("Failed to save root configuration to storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", Error07015, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to persist configuration to storage: %s", err.Error())
	}

	resp := &logical.Response{}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)
}

// Read the IBM Cloud Auth backend configuration from storage
func (ob *OrdersBackend) pathCAConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	//validate that the user is authorised to perform this action
	if err := ob.Auth.ValidateRequestIsAuthorised(ctx, req, common.GetEngineConfigAction, ""); err != nil {
		if _, ok := err.(logical.HTTPCodedError); ok {
			common.ErrorLogForCustomer("Internal server error", Error07016, logdna.InternalErrorMessage)
			return nil, err
		}
		common.ErrorLogForCustomer(err.Error(), Error07017, logdna.PermissionErrorMessage)
		return nil, err
	}
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), Error07018, "There are unexpected fields. Verify that the request parameters are valid")
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
		common.ErrorLogForCustomer("Internal server error", Error07019, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to get configuration from the storage: %s", err.Error())
	}
	//check if config with this name already exists
	var foundConfig *CAUserConfigToStore
	for _, caConfig := range config.CaConfigs {
		if caConfig.Name == name {
			foundConfig = caConfig
		}
	}
	if foundConfig == nil {
		common.Logger().Error("CA configuration with this name was not found.", "name", name, "error", err)

		common.ErrorLogForCustomer("Not Found", Error07020, logdna.NotFoundErrorMessage)
		return nil, fmt.Errorf("CA configuration with name '%s' was not found", name)
	}
	respData := make(map[string]interface{})

	respData[FieldName] = common.GetNonEmptyStringFirstOrSecond(foundConfig.Name, d.GetDefaultOrZero(FieldName).(string))
	respData[FieldDirectoryUrl] = common.GetNonEmptyStringFirstOrSecond(foundConfig.DirectoryURL, d.GetDefaultOrZero(FieldDirectoryUrl).(string))
	respData[FieldPrivateKey] = common.GetNonEmptyStringFirstOrSecond(foundConfig.PrivateKey, d.GetDefaultOrZero(FieldPrivateKey).(string))
	respData[FieldRegistrationUrl] = common.GetNonEmptyStringFirstOrSecond(foundConfig.RegistrationURL, d.GetDefaultOrZero(FieldRegistrationUrl).(string))
	respData[FieldEmail] = common.GetNonEmptyStringFirstOrSecond(foundConfig.Email, d.GetDefaultOrZero(FieldEmail).(string))

	resp := &logical.Response{
		Data: respData,
	}
	return resp, nil
}

func (ob *OrdersBackend) pathCAConfigList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	//validate that the user is authorised to perform this action
	if err := ob.Auth.ValidateRequestIsAuthorised(ctx, req, common.GetEngineConfigAction, ""); err != nil {
		if _, ok := err.(logical.HTTPCodedError); ok {
			common.ErrorLogForCustomer("Internal server error", Error07021, logdna.InternalErrorMessage)
			return nil, err
		}
		common.ErrorLogForCustomer(err.Error(), Error07022, logdna.PermissionErrorMessage)
		return nil, err
	}
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), Error07023, "There are unexpected fields. Verify that the request parameters are valid")
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	//// lock for reading
	secretsConfigLock.RLock()
	defer secretsConfigLock.RUnlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		common.Logger().Error("Failed to get root configuration from storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", Error07024, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to get configuration from the storage: %s", err.Error())
	}

	respData := make(map[string]interface{})
	respData["certificate_authorities"] = config.CaConfigs
	resp := &logical.Response{
		Data: respData,
	}
	return resp, nil
}

func (ob *OrdersBackend) pathCAConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	//validate that the user is authorised to perform this action
	if err := ob.Auth.ValidateRequestIsAuthorised(ctx, req, common.SetEngineConfigAction, ""); err != nil {
		if _, ok := err.(logical.HTTPCodedError); ok {
			common.ErrorLogForCustomer("Internal server error", Error07025, logdna.InternalErrorMessage)
			return nil, err
		}
		common.ErrorLogForCustomer(err.Error(), Error07026, logdna.PermissionErrorMessage)
		return nil, err
	}
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), Error07027, "There are unexpected fields. Verify that the request parameters are valid")
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
		common.ErrorLogForCustomer("Internal server error", Error07028, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to get configuration from the storage: %s", err.Error())
	}
	//check if config with this name already exists
	foundConfig := -1
	for i, caConfig := range config.CaConfigs {
		if caConfig.Name == name {
			foundConfig = i
		}
	}
	if foundConfig == -1 {
		common.Logger().Error("CA configuration with this name was not found.", "name", name, "error", err)

		common.ErrorLogForCustomer("Not Found", Error07029, logdna.NotFoundErrorMessage)
		return nil, fmt.Errorf("CA configuration with name '%s' was not found", name)
	}
	config.CaConfigs = append(config.CaConfigs[:foundConfig], config.CaConfigs[foundConfig+1:]...)

	err = putRootConfig(ctx, req, config)
	// Get the storage entry
	if err != nil {
		common.Logger().Error("Failed to save root configuration to storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", Error07030, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to persist configuration to storage: %s", err.Error())
	}

	resp := &logical.Response{}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)
}

func createCAConfigToStore(d *framework.FieldData) (*CAUserConfigToStore, error) {
	name := d.Get(FieldName).(string)
	directoryUrl := d.Get(FieldDirectoryUrl).(string)
	privateKeyPEM := d.Get(FieldPrivateKey).(string)
	caCert := d.Get(FieldCaCert).(string)

	if directoryUrl == "" {
		return nil, fmt.Errorf("directory_url field is empty")
	}

	if privateKeyPEM == "" {
		return nil, fmt.Errorf("private_key field is empty")
	}

	var ca *CAUserConfig
	ca, err := NewCAAccountConfig(name, directoryUrl, caCert, privateKeyPEM)

	if err != nil {
		return nil, err
	}
	err = ca.initCAAccount()
	if err != nil {
		return nil, err
	}
	configToStore, err := ca.getConfigToStore()
	if err != nil {
		return nil, err
	}
	return configToStore, nil
}

//TODO update this text
const caConfigSyn = "Read and Update the root configuration containing the IAM API key that is used to generate IAM credentials."
const caConfigDesc = `Read and update the IAM API key that will be used to generate IAM credentials.
To allow the secret engine to generate IAM credentials for you,
this IAM API key should have Editor role (IAM role) on both the IAM Identity Service and the IAM Access Groups Service.`
