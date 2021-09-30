package publiccerts

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/activity_tracker"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry/policies"
	"gotest.tools/v3/assert"
	"reflect"
	"testing"
)

var b *secret_backend.SecretBackendImpl
var storage logical.Storage

func TestOrdersBackend_GetConcretePath(t *testing.T) {

	b := OrdersBackend{secretBackend: &secret_backend.SecretBackendImpl{}}
	res := b.GetConcretePath()

	//We have 12 paths
	assert.Equal(t, len(res), 24)
	assert.Equal(t, res[0].Pattern, "config/certificate_authorities")
	assert.Equal(t, res[1].Pattern, "config/certificate_authorities/(?P<name>\\w(([\\w-.]+)?\\w)?)")
	assert.Equal(t, res[2].Pattern, "config/dns_providers")
	assert.Equal(t, res[3].Pattern, "config/dns_providers/(?P<name>\\w(([\\w-.]+)?\\w)?)")
	assert.Equal(t, res[4].Pattern, "config/root")
	assert.Equal(t, res[5].Pattern, "secrets/(?P<id>\\w(([\\w-.]+)?\\w)?)/policies")
	assert.Equal(t, res[6].Pattern, "secrets/groups/(?P<secret_group_id>\\w(([\\w-.]+)?\\w)?)/(?P<id>\\w(([\\w-.]+)?\\w)?)/policies")
	assert.Equal(t, res[7].Pattern, "secrets/?$")
	assert.Equal(t, res[8].Pattern, "secrets/groups/(?P<secret_group_id>\\w(([\\w-.]+)?\\w)?)/?$")
	assert.Equal(t, res[9].Pattern, "secrets/(?P<id>\\w(([\\w-.]+)?\\w)?)/rotate")
	assert.Equal(t, res[10].Pattern, "secrets/groups/(?P<secret_group_id>\\w(([\\w-.]+)?\\w)?)/(?P<id>\\w(([\\w-.]+)?\\w)?)/rotate")
	assert.Equal(t, res[11].Pattern, "secrets/(?P<id>\\w(([\\w-.]+)?\\w)?)/metadata")
	assert.Equal(t, res[12].Pattern, "secrets/groups/(?P<secret_group_id>\\w(([\\w-.]+)?\\w)?)/(?P<id>\\w(([\\w-.]+)?\\w)?)/metadata")
	assert.Equal(t, res[13].Pattern, "secrets/(?P<id>\\w(([\\w-.]+)?\\w)?)")
	assert.Equal(t, res[14].Pattern, "secrets/groups/(?P<secret_group_id>\\w(([\\w-.]+)?\\w)?)/(?P<id>\\w(([\\w-.]+)?\\w)?)")
	assert.Equal(t, res[15].Pattern, "secrets/(?P<id>\\w(([\\w-.]+)?\\w)?)/versions/(?P<version_id>\\w(([\\w-.]+)?\\w)?)")
	assert.Equal(t, res[16].Pattern, "secrets/groups/(?P<secret_group_id>\\w(([\\w-.]+)?\\w)?)/(?P<id>\\w(([\\w-.]+)?\\w)?)/versions/(?P<version_id>\\w(([\\w-.]+)?\\w)?)")
	assert.Equal(t, res[17].Pattern, "secrets/(?P<id>\\w(([\\w-.]+)?\\w)?)/versions/(?P<version_id>\\w(([\\w-.]+)?\\w)?)/metadata")
	assert.Equal(t, res[18].Pattern, "secrets/groups/(?P<secret_group_id>\\w(([\\w-.]+)?\\w)?)/(?P<id>\\w(([\\w-.]+)?\\w)?)/versions/(?P<version_id>\\w(([\\w-.]+)?\\w)?)/metadata")
	assert.Equal(t, res[19].Pattern, AutoRotatePath)
	assert.Equal(t, res[20].Pattern, AutoRotateCleanupPath)
	assert.Equal(t, res[21].Pattern, ResumeOrderPath)
	assert.Equal(t, res[21].Pattern, "secrets/(?P<id>\\w(([\\w-.]+)?\\w)?)/versions/?$")
	assert.Equal(t, res[22].Pattern, "secrets/groups/(?P<secret_group_id>\\w(([\\w-.]+)?\\w)?)/(?P<id>\\w(([\\w-.]+)?\\w)?)/versions/?$")
}

func TestOrdersBackend_SetSecretBackend(t *testing.T) {
	b := OrdersBackend{}
	mb := MockSecretBackend{name: "public_cert mock"}
	b.SetSecretBackend(&mb)
	assert.Equal(t, b.secretBackend.(*MockSecretBackend).name, "public_cert mock")
}

func TestOrdersBackend_GetSecretBackendHandler(t *testing.T) {
	b := OrdersBackend{secretBackend: &secret_backend.SecretBackendImpl{}}
	handler := b.GetSecretBackendHandler()
	assert.Equal(t, reflect.TypeOf(handler).String(), reflect.TypeOf(&OrdersHandler{}).String())
}

type MockSecretBackend struct {
	name string
}

func (sb *MockSecretBackend) MarkSecretAsDestroyedIfExpired(secret *secretentry.SecretEntry, enginePolicies policies.Policies, req *logical.Request, ctx context.Context) error {
	return nil
}

func (sb *MockSecretBackend) Create(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	panic("implement me")
}

func (sb *MockSecretBackend) Get(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	panic("implement me")
}

func (sb *MockSecretBackend) List(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	panic("implement me")
}

func (sb *MockSecretBackend) ListVersions(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	panic("implement me")
}

func (sb *MockSecretBackend) Delete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	panic("implement me")
}

func (sb *MockSecretBackend) GetMetadata(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	panic("implement me")
}

func (sb *MockSecretBackend) GetPolicies(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	panic("implement me")
}

func (sb *MockSecretBackend) UpdateMetadata(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	panic("implement me")
}

func (sb *MockSecretBackend) UpdatePolicies(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	panic("implement me")
}

func (sb *MockSecretBackend) Rotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	panic("implement me")
}

func (sb *MockSecretBackend) GetVersion(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	panic("implement me")
}

func (sb *MockSecretBackend) GetVersionMetadata(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	panic("implement me")
}

func (sb *MockSecretBackend) DeleteSecretIfExpired(secret *secretentry.SecretEntry, enginePolicies policies.Policies, req *logical.Request, ctx context.Context) error {
	panic("implement me")
}

func (sb *MockSecretBackend) GetValidator() secret_backend.Validator {
	return nil
}
func (sb *MockSecretBackend) PathCallback(operation framework.OperationFunc, atVaultParams *activity_tracker.ActivityTrackerVault) framework.OperationFunc {
	return nil
}
