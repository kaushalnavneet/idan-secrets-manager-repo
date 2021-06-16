package publiccerts

import (
	"context"
	"errors"
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
	atSecretConfigUpdate := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: "secrets-manager/secret-engine-config",
		Description: "Set secret engine configuration", Action: common.SetEngineConfigAction, SecretType: SecretTypePublicCert, TargetResourceType: CA}
	atSecretConfigRead := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: "secrets-manager/secret-engine-config",
		Description: "Get secret engine configuration", Action: common.GetEngineConfigAction, SecretType: SecretTypePublicCert, TargetResourceType: CA}
	atSecretConfigDelete := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: "secrets-manager/secret-engine-config",
		Description: "Delete secret engine configuration", Action: DeleteEngineConfigAction, SecretType: SecretTypePublicCert, TargetResourceType: CA}

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
			Summary:  "Update the configuration value",
		},
		logical.DeleteOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathCAConfigDelete, atSecretConfigDelete),
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

// Create or update the IBM Cloud Auth backend configuration
func (ob *OrdersBackend) pathCAConfigCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// validate that the user is authorised to perform this action
	err := ob.checkAuthorization(ctx, req, common.SetEngineConfigAction)
	if err != nil {
		return nil, err
	}
	//get config name
	name, err := ob.validateStringField(d, FieldName, "min=2,max=512", "length should be 2 to 512 chars")
	if err != nil {
		errorMessage := fmt.Sprintf("Parameters validation error: %s", err.Error())
		common.ErrorLogForCustomer(errorMessage, Error07010, logdna.BadRequestErrorMessage)
		return nil, logical.CodedError(http.StatusBadRequest, errorMessage)
	}

	//prepare AT context
	atContext := ctx.Value(at.AtContextKey).(*at.AtContext)
	atContext.ResourceName = name

	// Validate user input
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), Error07011, "There are unexpected fields. Verify that the request parameters are valid")
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
		common.ErrorLogForCustomer("Internal server error", Error07012, logdna.InternalErrorMessage)
		return nil, errors.New(errorMessage)
	}
	//check if config with this name already exists
	for _, caConfig := range config.CaConfigs {
		if caConfig.Name == name {
			errorMessage := fmt.Sprintf("CA configuration with name '%s' already exists", name)
			common.ErrorLogForCustomer(errorMessage, Error07013, logdna.BadRequestErrorMessage)
			return nil, logical.CodedError(http.StatusBadRequest, errorMessage)
		}
	}
	configToStore, err := ob.createCAConfigToStore(d, name)
	if err != nil {
		errorMessage := fmt.Sprintf("Parameters validation error: %s", err.Error())
		common.ErrorLogForCustomer(errorMessage, Error07014, logdna.BadRequestErrorMessage)
		return nil, logical.CodedError(http.StatusBadRequest, errorMessage)
	}
	config.CaConfigs = append(config.CaConfigs, configToStore)

	err = putRootConfig(ctx, req, config)
	// Get the storage entry
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to save configuration to the storage: %s", err.Error())
		common.Logger().Error(errorMessage)
		common.ErrorLogForCustomer("Internal server error", Error07015, logdna.InternalErrorMessage)
		return nil, errors.New(errorMessage)
	}

	resp := &logical.Response{}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)
}

// Create or update the IBM Cloud Auth backend configuration
func (ob *OrdersBackend) pathCAConfigUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// validate that the user is authorised to perform this action
	err := ob.checkAuthorization(ctx, req, common.SetEngineConfigAction)
	if err != nil {
		return nil, err
	}
	//get config name
	name, err := ob.validateStringField(d, FieldName, "min=2,max=512", "length should be 2 to 512 chars")
	if err != nil {
		errorMessage := fmt.Sprintf("Parameters validation error: %s", err.Error())
		common.ErrorLogForCustomer(errorMessage, Error07016, logdna.BadRequestErrorMessage)
		return nil, logical.CodedError(http.StatusBadRequest, errorMessage)
	}
	//prepare AT context
	atContext := ctx.Value(at.AtContextKey).(*at.AtContext)
	atContext.ResourceName = name
	// Validate user input
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), Error07017, "There are unexpected fields. Verify that the request parameters are valid")
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}
	configToStore, err := ob.createCAConfigToStore(d, name)
	if err != nil {
		errorMessage := fmt.Sprintf("Parameters validation error: %s", err.Error())
		common.ErrorLogForCustomer(errorMessage, Error07018, logdna.BadRequestErrorMessage)
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
		common.ErrorLogForCustomer("Internal server error", Error07019, logdna.InternalErrorMessage)
		return nil, errors.New(errorMessage)
	}
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
		errorMessage := fmt.Sprintf("CA configuration with name '%s' was not found", name)
		common.ErrorLogForCustomer(errorMessage, Error07020, logdna.NotFoundErrorMessage)
		return nil, logical.CodedError(http.StatusNotFound, errorMessage)
	}

	err = putRootConfig(ctx, req, config)
	// Get the storage entry
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to save configuration to the storage: %s", err.Error())
		common.Logger().Error(errorMessage)
		common.ErrorLogForCustomer("Internal server error", Error07021, logdna.InternalErrorMessage)
		return nil, errors.New(errorMessage)
	}

	resp := &logical.Response{}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)
}

// Read the IBM Cloud Auth backend configuration from storage
func (ob *OrdersBackend) pathCAConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// validate that the user is authorised to perform this action
	err := ob.checkAuthorization(ctx, req, common.GetEngineConfigAction)
	if err != nil {
		return nil, err
	}
	//get config name
	name, err := ob.validateStringField(d, FieldName, "min=2,max=512", "length should be 2 to 512 chars")
	if err != nil {
		errorMessage := fmt.Sprintf("Parameters validation error: %s", err.Error())
		common.ErrorLogForCustomer(errorMessage, Error07022, logdna.BadRequestErrorMessage)
		return nil, logical.CodedError(http.StatusBadRequest, errorMessage)
	}

	//prepare AT context
	atContext := ctx.Value(at.AtContextKey).(*at.AtContext)
	atContext.ResourceName = name

	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), Error07023, "There are unexpected fields. Verify that the request parameters are valid")
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}
	foundConfig, err := getCAConfigByName(ctx, req, name)
	if err != nil {
		return nil, err
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

func getCAConfigByName(ctx context.Context, req *logical.Request, name string) (*CAUserConfigToStore, error) {
	// lock for reading
	secretsConfigLock.RLock()
	defer secretsConfigLock.RUnlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to get configuration from the storage: %s", err.Error())
		common.Logger().Error(errorMessage)
		common.ErrorLogForCustomer("Internal server error", Error07024, logdna.InternalErrorMessage)
		return nil, errors.New(errorMessage)
	}
	//check if config with this name  exists
	var foundConfig *CAUserConfigToStore
	for _, caConfig := range config.CaConfigs {
		if caConfig.Name == name {
			foundConfig = caConfig
			break
		}
	}
	if foundConfig == nil {
		errorMessage := fmt.Sprintf("CA configuration with name '%s' was not found", name)
		common.ErrorLogForCustomer(errorMessage, Error07025, logdna.NotFoundErrorMessage)
		return nil, logical.CodedError(http.StatusNotFound, errorMessage)
	}

	return foundConfig, nil
}

func (ob *OrdersBackend) pathCAConfigList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	//validate that the user is authorised to perform this action
	err := ob.checkAuthorization(ctx, req, common.GetEngineConfigAction)
	if err != nil {
		return nil, err
	}
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), Error07026, "There are unexpected fields. Verify that the request parameters are valid")
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	//// lock for reading
	secretsConfigLock.RLock()
	defer secretsConfigLock.RUnlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to get configuration from the storage: %s", err.Error())
		common.Logger().Error(errorMessage)
		common.ErrorLogForCustomer("Internal server error", Error07027, logdna.InternalErrorMessage)
		return nil, errors.New(errorMessage)
	}

	respData := make(map[string]interface{})
	respData[CA] = config.CaConfigs
	//TODO remove private keys
	resp := &logical.Response{
		Data: respData,
	}
	return resp, nil
}

func (ob *OrdersBackend) pathCAConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// validate that the user is authorised to perform this action
	err := ob.checkAuthorization(ctx, req, common.SetEngineConfigAction)
	if err != nil {
		return nil, err
	}
	//get config name
	name, err := ob.validateStringField(d, FieldName, "min=2,max=512", "length should be 2 to 512 chars")
	if err != nil {
		errorMessage := fmt.Sprintf("Parameters validation error: %s", err.Error())
		common.ErrorLogForCustomer(errorMessage, Error07028, logdna.BadRequestErrorMessage)
		return nil, logical.CodedError(http.StatusBadRequest, errorMessage)
	}
	//prepare AT context
	atContext := ctx.Value(at.AtContextKey).(*at.AtContext)
	atContext.ResourceName = name
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), Error07029, "There are unexpected fields. Verify that the request parameters are valid")
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
		common.ErrorLogForCustomer("Internal server error", Error07030, logdna.InternalErrorMessage)
		return nil, errors.New(errorMessage)
	}
	//check if config with this name already exists
	foundConfig := -1
	for i, caConfig := range config.CaConfigs {
		if caConfig.Name == name {
			foundConfig = i
			break
		}
	}
	if foundConfig == -1 {
		errorMessage := fmt.Sprintf("CA configuration with name '%s' was not found", name)
		common.ErrorLogForCustomer(errorMessage, Error07031, logdna.NotFoundErrorMessage)
		return nil, logical.CodedError(http.StatusNotFound, errorMessage)
	}
	config.CaConfigs = append(config.CaConfigs[:foundConfig], config.CaConfigs[foundConfig+1:]...)

	err = putRootConfig(ctx, req, config)
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to save configuration to the storage: %s", err.Error())
		common.Logger().Error(errorMessage)
		common.ErrorLogForCustomer("Internal server error", Error07032, logdna.InternalErrorMessage)
		return nil, errors.New(errorMessage)
	}

	resp := &logical.Response{}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)
}

func (ob *OrdersBackend) createCAConfigToStore(d *framework.FieldData, name string) (*CAUserConfigToStore, error) {
	directoryUrl, err := ob.validateStringField(d, FieldDirectoryUrl, "url", "not valid url")
	if err != nil {
		return nil, err
	}
	privateKeyPEM := d.Get(FieldPrivateKey).(string)
	if privateKeyPEM == "" {
		return nil, errors.New("private key is missing")
	}
	email := d.Get(FieldEmail).(string)
	caCert := d.Get(FieldCaCert).(string)
	ca, err := NewCAAccountConfig(name, directoryUrl, caCert, privateKeyPEM, email)
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
const caConfigSyn = "Read and Update the CA configuration."
const caConfigDesc = "Read and Update the CA configuration."
