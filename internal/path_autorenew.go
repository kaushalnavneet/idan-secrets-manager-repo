package publiccerts

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
)

func (ob *OrdersBackend) pathAutoRenew() *framework.Path {
	return &framework.Path{
		Pattern: AutoRenewPath,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: ob.autoRenewCertificates,
			},
		},
	}
}

func (ob *OrdersBackend) autoRenewCertificates(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	common.Logger().Info("!!!!autoRenewCertificates!!!!")
	//common.PerformOperationOnAllSecrets(ctx, req, ob.GetSecretBackendHandler().(*OrdersHandler).renewCertIfNeeded)
	return nil, nil
}
