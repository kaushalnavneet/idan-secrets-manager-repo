package publiccerts

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-common-utils/secret_metadata_entry/policies"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/activity_tracker"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"gotest.tools/v3/assert"
	"os"
	"reflect"
	"testing"
)

var b *secret_backend.SecretBackendImpl
var storage logical.Storage

func init() {
	// reach old path without metadata manager
	instanceCRN = "crn:v1:staging:public:secrets-manager:us-south:a/791f5fb10986423e97aa8512f18b7e65:baf0054c-235f-45ab-b6e8-45edbf044444::"
	os.Setenv("CRN", instanceCRN)
	metadataManagerWhitelist = "crn:v1:staging:public:secrets-manager:us-south:a/791f5fb10986423e97aa8512f18b7e65:baf0054c-235f-45ab-b6e8-45edbf044116::"
	os.Setenv("METADATA_MANAGER_WHITELIST", metadataManagerWhitelist)
}

func TestOrdersBackend_GetConcretePath(t *testing.T) {
	b := OrdersBackend{secretBackend: &secret_backend.SecretBackendImpl{}}
	res := b.GetConcretePath()

	//We have 25 paths
	assert.Equal(t, len(res), 25)
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
	assert.Equal(t, res[20].Pattern, ResumeOrderPath)
	assert.Equal(t, res[21].Pattern, "secrets/(?P<id>\\w(([\\w-.]+)?\\w)?)/versions/?$")
	assert.Equal(t, res[22].Pattern, "secrets/groups/(?P<secret_group_id>\\w(([\\w-.]+)?\\w)?)/(?P<id>\\w(([\\w-.]+)?\\w)?)/versions/?$")
	assert.Equal(t, res[23].Pattern, "secrets/(?P<id>\\w(([\\w-.]+)?\\w)?)/validate_dns_challenge")
	assert.Equal(t, res[24].Pattern, "secrets/groups/(?P<secret_group_id>\\w(([\\w-.]+)?\\w)?)/(?P<id>\\w(([\\w-.]+)?\\w)?)/validate_dns_challenge")
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

func (sb *MockSecretBackend) GetVersionsLockedMap(secretId string) (map[string]bool, error) {
	return map[string]bool{secret_backend.Current: false, secret_backend.Previous: false}, nil
}

func (sb *MockSecretBackend) GetMetadataMapper() common.MetadataMapper {
	return secret_backend.GetDefaultMetadataMapper("public_cert")
}

func (sb *MockSecretBackend) GetLocks(ctx context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}
func (sb *MockSecretBackend) DeleteLocks(ctx context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}
func (sb *MockSecretBackend) AddLocks(ctx context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
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

func (sb *MockSecretBackend) UpdateVersionMetadata(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

func (sb *MockSecretBackend) DeleteSecretIfExpired(secret *secretentry.SecretEntry, enginePolicies policies.Policies, req *logical.Request, ctx context.Context) error {
	panic("implement me")
}

func (sb *MockSecretBackend) GetValidator() secret_backend.Validator {
	return nil
}
func (sb *MockSecretBackend) PathCallback(operation framework.OperationFunc, atVaultParams *activity_tracker.ActivityTrackerVault, isAllowedInReadOnly bool) framework.OperationFunc {
	return nil
}
func (sb *MockSecretBackend) GetMetadataClient() common.MetadataClient {
	return nil
}
func (sb *MockSecretBackend) GetPluginSecretType() string {
	return "public_cert"
}
