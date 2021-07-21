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
)

func (ob *OrdersBackend) pathConfigRoot() []*framework.Path {
	atSecretConfigRead := &at.ActivityTrackerVault{DataEvent: false, TargetTypeURI: ConfigTargetTypeURI,
		Description: "Get secret engine configuration", Action: common.GetEngineConfigAction,
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

func (ob *OrdersBackend) pathRootConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := ob.checkAuthorization(ctx, req, common.GetEngineConfigAction)
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
	config, err := getRootConfig(ctx, req)
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to get configuration from the storage: %s", err.Error())
		common.Logger().Error(errorMessage)
		common.ErrorLogForCustomer(internalServerError, logdna.Error07004, logdna.InternalErrorMessage, false)
		return nil, errors.New(errorMessage)
	}

	respData := make(map[string]interface{})
	respData[CA] = getCAConfigsAsMap(config)
	respData[DNS] = getDNSConfigsAsMap(config)
	resp := &logical.Response{
		Data: respData,
	}
	return resp, nil
}
