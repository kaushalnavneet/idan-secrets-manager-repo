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

func (ob *OrdersBackend) pathConfigRoot() []*framework.Path {
	atSecretConfigRead := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: "secrets-manager/secret-engine-config",
		Description: "Get secret engine configuration", Action: common.GetEngineConfigAction, SecretType: SecretTypePublicCert}
	fields := map[string]*framework.FieldSchema{}
	operations := map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation: &framework.PathOperation{
			Callback: ob.secretBackend.PathCallback(ob.pathRootConfigRead, atSecretConfigRead),
			Summary:  "Get all the configuration values",
		},
	}
	return []*framework.Path{
		{
			Pattern:         ConfigRootPath,
			Fields:          fields,
			Operations:      operations,
			HelpSynopsis:    rootConfigSyn,
			HelpDescription: rootConfigDesc,
		},
	}
}

func (ob *OrdersBackend) pathRootConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	//validate that the user is authorised to perform this action
	if err := ob.Auth.ValidateRequestIsAuthorised(ctx, req, common.GetEngineConfigAction, ""); err != nil {
		if _, ok := err.(logical.HTTPCodedError); ok {
			common.ErrorLogForCustomer("Internal server error", Error07001, logdna.InternalErrorMessage)
			return nil, err
		}
		common.ErrorLogForCustomer(err.Error(), Error07002, logdna.PermissionErrorMessage)
		return nil, err
	}
	if err := common.ValidateUnknownFields(req, d); err != nil {
		common.ErrorLogForCustomer(err.Error(), Error07003, "There are unexpected fields. Verify that the request parameters are valid")
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// lock for reading
	secretsConfigLock.RLock()
	defer secretsConfigLock.RUnlock()
	// Get the storage entry
	config, err := getRootConfig(ctx, req)
	if err != nil {
		common.Logger().Error("Failed to get root configuration from storage.", "error", err)
		common.ErrorLogForCustomer("Internal server error", Error07004, logdna.InternalErrorMessage)
		return nil, fmt.Errorf("failed to get configuration from the storage: %s", err.Error())
	}

	respData := make(map[string]interface{})
	respData["certificate_authorities"] = config.CaConfigs
	respData["dns_providers"] = config.ProviderConfigs
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
