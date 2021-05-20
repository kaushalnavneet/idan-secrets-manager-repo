package publiccerts

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
)

type OrdersBackend struct {
	secretBackend secret_backend.SecretBackend
	Auth          common.AuthValidator
}

func (ob *OrdersBackend) SetSecretBackend(secretBackend secret_backend.SecretBackend) {
	ob.secretBackend = secretBackend
	ob.Auth = &common.AuthValidatorImpl{}
}

func (ob *OrdersBackend) GetConcretePath() []*framework.Path {
	return framework.PathAppend(
		// set + get config
		ob.pathConfigCA(),
		ob.pathConfigDNS(),
		ob.pathConfigRoot(),
		[]*framework.Path{
			//// Make sure this stays at the end so that the valid paths are processed first.
			//common.PathInvalid(backendHelp),
		})
}
func (ob *OrdersBackend) GetSecretBackendHandler() secret_backend.SecretBackendHandler {
	return &OrdersHandler{}
}

func existenceCheck(ctx context.Context, request *logical.Request, data *framework.FieldData) (bool, error) {
	return false, nil
}
