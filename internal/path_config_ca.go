package publiccerts

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-iam/pkg/crn"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	at "github.ibm.com/security-services/secrets-manager-vault-plugins-common/activity_tracker"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"strings"

	"net/http"
)

var secretsConfigLock locksutil.LockEntry

func (ob *OrdersBackend) pathConfigCA() []*framework.Path {
	//todo move const to secretentry
	atSecretConfigUpdate := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: "secrets-manager/secret-engine-config",
		Description: "Set secret engine configuration", Action: "secrets-manager.secret-engine-config.set", SecretType: SecretTypePublicCert}
	atSecretConfigRead := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: "secrets-manager/secret-engine-config",
		Description: "Get secret engine configuration", Action: "secrets-manager.secret-engine-config.get", SecretType: SecretTypePublicCert}

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
		FieldTermsOfServiceAgreed: {
			Type:        framework.TypeBool,
			Description: "Whether the user agrees to the terms of service",
			Required:    true,
			Default:     false,
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
			Callback: ob.secretBackend.PathCallback(ob.pathSecretsConfigCreate, atSecretConfigUpdate),
			Summary:  "Create the configuration value",
		},
		logical.ListOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathSecretsListConfigs, atSecretConfigUpdate),
			Summary:  "Get all the configuration values",
		},
	}

	operationsWithPathParam := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathSecretsConfigRead, atSecretConfigRead),
			Summary:  "Read the configuration value",
		},
		logical.UpdateOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathSecretsConfigUpdate, atSecretConfigUpdate),
		},
		logical.DeleteOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathSecretsConfigDelete, atSecretConfigUpdate),
		},
	}

	return []*framework.Path{
		{
			Pattern:         ConfigPath,
			Fields:          fields,
			Operations:      operationsWithoutPathParam,
			HelpSynopsis:    rootConfigSyn,
			HelpDescription: rootConfigDesc,
		},
		{
			Pattern:         ConfigPath + "/" + framework.GenericNameRegex(FieldName),
			Fields:          fields,
			Operations:      operationsWithPathParam,
			HelpSynopsis:    rootConfigSyn,
			HelpDescription: rootConfigDesc,
		},
	}
}

// Create or update the IBM Cloud Auth backend configuration
func (ob *OrdersBackend) pathSecretsConfigCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

	name := d.Get(FieldName).(string)
	directoryUrl := d.Get(FieldDirectoryUrl).(string)
	privateKeyPEM := d.Get(FieldPrivateKey).(string)
	caCert := d.Get(FieldCaCert).(string)
	email := d.Get(FieldEmail).(string)
	agreed := d.Get(FieldTermsOfServiceAgreed).(bool)

	if directoryUrl == "" {
		return nil, fmt.Errorf("directory_url field is empty")
	}

	if privateKeyPEM == "" && email == "" {
		return nil, fmt.Errorf("email field is empty")
	}
	//
	//if privateKeyPEM == ""  {
	//	return nil, fmt.Errorf("private key field is empty")
	//}

	if agreed == false {
		return nil, fmt.Errorf("terms of service not agreed")
	}
	// lock for writing
	secretsConfigLock.Lock()
	defer secretsConfigLock.Unlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		common.Logger().Error("Failed to get root configuration from storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", logdna.Error03087, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to get configuration from the storage: %w", err)
	}
	//check if config with this name already exists
	for _, caConfig := range config.CaConfigs {
		if caConfig.Name == name {
			common.Logger().Error("CA configuration with this name already exists.", "name", name, "error", err)
			//TODO What is errorcode??
			common.ErrorLogForCustomer("Internal server error", logdna.Error03087, logdna.InternalErrorMessage)
			return nil, fmt.Errorf("CA configuration with name %s already exists", name)
		}
	}

	var ca *CAUserConfig
	ca, err = NewCAAccountConfig(name, directoryUrl, caCert, email, agreed, privateKeyPEM)
	if err != nil {
		return nil, err
	}
	err = ca.createCAAccount(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	configToStore, err := ca.getConfigToStore()
	if err != nil {
		return nil, err
	}
	config.CaConfigs = append(config.CaConfigs, configToStore)

	putRootConfig(ctx, req, config)
	// Get the storage entry
	if err != nil {
		common.Logger().Error("Failed to save root configuration to storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", logdna.Error03087, logdna.InternalErrorMessage)
		return nil, errwrap.Wrapf("failed to persist configuration to storage: {{err}}", err)
	}

	resp := &logical.Response{}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)
}

// Create or update the IBM Cloud Auth backend configuration
func (ob *OrdersBackend) pathSecretsConfigUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

	name := d.Get(FieldName).(string)
	directoryUrl := d.Get(FieldDirectoryUrl).(string)
	privateKeyPEM := d.Get(FieldPrivateKey).(string)
	caCert := d.Get(FieldCaCert).(string)
	email := d.Get(FieldEmail).(string)
	agreed := d.Get(FieldTermsOfServiceAgreed).(bool)

	if directoryUrl == "" {
		return nil, fmt.Errorf("directory_url field is empty")
	}

	if privateKeyPEM == "" && email == "" {
		return nil, fmt.Errorf("email field is empty")
	}

	if agreed == false {
		return nil, fmt.Errorf("terms of service not agreed")
	}
	// lock for writing
	secretsConfigLock.Lock()
	defer secretsConfigLock.Unlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		common.Logger().Error("Failed to get root configuration from storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", logdna.Error03087, logdna.InternalErrorMessage)
		return nil, errwrap.Wrapf("failed to get configuration from the storage: {{err}}", err)
	}

	var ca *CAUserConfig
	ca, err = NewCAAccountConfig(name, directoryUrl, caCert, email, agreed, privateKeyPEM)

	if err != nil {
		return nil, err
	}

	//check if config with this name already exists
	found := false
	for i, caConfig := range config.CaConfigs {
		if caConfig.Name == name {
			found = true
			configToStore, _ := ca.getConfigToStore()
			config.CaConfigs[i] = configToStore
		}
	}
	if !found {
		common.Logger().Error("CA configuration with this name was not found.", "name", name, "error", err)
		//TODO What is errorcode??
		common.ErrorLogForCustomer("Internal server error", logdna.Error03087, logdna.InternalErrorMessage)
		return nil, errors.New("CA configuration with this name was not found")
	}

	putRootConfig(ctx, req, config)
	// Get the storage entry
	if err != nil {
		common.Logger().Error("Failed to save root configuration to storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", logdna.Error03087, logdna.InternalErrorMessage)
		return nil, errwrap.Wrapf("failed to persist configuration to storage: {{err}}", err)
	}

	resp := &logical.Response{}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)
}

// Read the IBM Cloud Auth backend configuration from storage
func (ob *OrdersBackend) pathSecretsConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
		return nil, errwrap.Wrapf("failed to get configuration from the storage: {{err}}", err)
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
		//TODO What is errorcode??
		common.ErrorLogForCustomer("Internal server error", logdna.Error03087, logdna.InternalErrorMessage)
		return nil, errors.New("CA configuration with this name was not found")
	}
	//block, _ := pem.Decode([]byte(foundConfig.PrivateKey))
	//privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	//if err != nil {
	//	return nil, err
	//}
	respData := make(map[string]interface{})

	respData[FieldName] = common.GetNonEmptyStringFirstOrSecond(foundConfig.Name, d.GetDefaultOrZero(FieldName).(string))
	respData[FieldDirectoryUrl] = common.GetNonEmptyStringFirstOrSecond(foundConfig.DirectoryURL, d.GetDefaultOrZero(FieldDirectoryUrl).(string))
	respData[FieldPrivateKey] = common.GetNonEmptyStringFirstOrSecond(foundConfig.PrivateKey, d.GetDefaultOrZero(FieldPrivateKey).(string))
	respData[FieldRegistrationUrl] = common.GetNonEmptyStringFirstOrSecond(foundConfig.RegistrationURL, d.GetDefaultOrZero(FieldRegistrationUrl).(string))

	resp := &logical.Response{
		Data: respData,
	}
	return resp, nil
}

//TODO update this text
const rootConfigSyn = "Read and Update the root configuration containing the IAM API key that is used to generate IAM credentials."
const rootConfigDesc = `Read and update the IAM API key that will be used to generate IAM credentials.
To allow the secret engine to generate IAM credentials for you,
this IAM API key should have Editor role (IAM role) on both the IAM Identity Service and the IAM Access Groups Service.`

func getAccountIdFromCRN(rawCRN string) (string, error) {
	instanceCRN, err := crn.ToCRN(rawCRN)
	if err != nil {
		common.Logger().Error("failed to configure IAM secrets (config/root): invalid instance CRN found in auth configuration", "error", err, "invalid_CRN", rawCRN)
		return "", logical.CodedError(http.StatusInternalServerError, "internal error")
	}
	if !strings.HasPrefix(instanceCRN.Scope, scopePrefixForAccountIdInCRN) {
		// The Scope segment will start with "a/" if it contains an accountId
		// see the documentation on CRN's scope segment: https://cloud.ibm.com/docs/account?topic=account-crn
		common.Logger().Error("instance CRN does not contain accountId (scope segment prefix is not \"a/\")", "invalid_CRN", rawCRN)
		return "", logical.CodedError(http.StatusInternalServerError, "internal error")
	}
	accountId := strings.TrimPrefix(instanceCRN.Scope, scopePrefixForAccountIdInCRN)
	return accountId, nil
}

func (ob *OrdersBackend) pathSecretsListConfigs(ctx context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	resp := &logical.Response{
		Data: make(map[string]interface{}),
	}
	return resp, nil
}

func (ob *OrdersBackend) pathSecretsConfigDelete(ctx context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	resp := &logical.Response{
		Data: make(map[string]interface{}),
	}
	return resp, nil
}
