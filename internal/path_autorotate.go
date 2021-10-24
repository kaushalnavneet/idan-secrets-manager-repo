package publiccerts

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
)

func (ob *OrdersBackend) pathAutoRotate() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: AutoRotatePath,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: ob.autoRotateCertificates}},
		},
		{
			Pattern: AutoRotateCleanupPath,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: ob.autoRotateCleanup}},
		},
	}
}

func (ob *OrdersBackend) autoRotateCertificates(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	common.Logger().Info("AUTO ROTATE CERTIFICATES started")
	common.PerformOperationOnAllSecrets(ctx, req, ob.secretBackend.GetMetadataClient(), ob.secretBackend.GetPluginSecretType(), ob.GetSecretBackendHandler().(*OrdersHandler).rotateCertIfNeeded)
	return nil, nil
}

func (ob *OrdersBackend) autoRotateCleanup(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	common.Logger().Info(" Final running of AUTO ROTATE CERTIFICATES for this day")
	common.PerformOperationOnAllSecrets(ctx, req, ob.secretBackend.GetMetadataClient(), ob.secretBackend.GetPluginSecretType(), ob.GetSecretBackendHandler().(*OrdersHandler).cleanupAfterRotationCertIfNeeded)
	return nil, nil
}
