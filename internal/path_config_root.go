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
	"net/http"
)

func (ob *OrdersBackend) pathConfigRoot() []*framework.Path {
	atSecretConfigRead := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: "secrets-manager/secret-engine-config",
		Description: "Get secret engine configuration", Action: common.GetEngineConfigAction, SecretType: SecretTypePublicCert, TargetResourceType: Root}
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
	err := ob.checkAuthorization(ctx, req, common.GetEngineConfigAction)
	if err != nil {
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
		errorMessage := fmt.Sprintf("Failed to get configuration from the storage: %s", err.Error())
		common.Logger().Error(errorMessage)
		common.ErrorLogForCustomer("Internal server error", Error07004, logdna.InternalErrorMessage)
		return nil, errors.New(errorMessage)
	}

	respData := make(map[string]interface{})
	//TODO remove private keys
	respData[CA] = config.CaConfigs
	//TODO remove configs
	respData[DNS] = config.ProviderConfigs
	resp := &logical.Response{
		Data: respData,
	}
	return resp, nil
}

//TODO update this text
const rootConfigSyn = "Read and Update the root configuration."
const rootConfigDesc = "Read and Update the root configuration."
