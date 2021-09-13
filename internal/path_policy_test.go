package publiccerts

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/errors"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry/policies"
	"gotest.tools/v3/assert"
	"net/http"
	"reflect"
	"testing"
)

func Test_ReadPolicy_Happy(t *testing.T) {
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{})
	common.StoreSecretWithoutLocking(expiresIn30Days_autoRotateTrue, storage, context.Background())
	common.StoreSecretWithoutLocking(expiresIn20Days_autoRotateTrue, storage, context.Background())

	t.Run("Read policy", func(t *testing.T) {
		data := map[string]interface{}{
			policies.FieldPolicy: policies.PolicyTypeRotation,
		}
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      PathSecrets + expiresIn30Days_autoRotateTrue_id + "/policies",
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		expectedPolicy := map[string]interface{}{
			policies.FieldAutoRotate: true,
			policies.FieldRotateKeys: false,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
		respPolicy := resp.Data[policies.FieldPolicies].([]map[string]interface{})[0]
		rotation := respPolicy[policies.PolicyTypeRotation].(map[string]interface{})
		assert.Equal(t, rotation[policies.FieldAutoRotate], expectedPolicy[policies.FieldAutoRotate])
		assert.Equal(t, rotation[policies.FieldRotateKeys], expectedPolicy[policies.FieldRotateKeys])
	})

	t.Run("Update policy + warning", func(t *testing.T) {
		data := map[string]interface{}{
			policies.FieldPolicy: policies.PolicyTypeRotation,
			policies.FieldPolicies: []map[string]interface{}{{
				policies.PolicyTypeRotation: map[string]interface{}{
					policies.FieldAutoRotate: true,
					policies.FieldRotateKeys: true,
				}}}}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      PathSecrets + expiresIn20Days_autoRotateTrue_id + "/policies",
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		expectedPolicy := map[string]interface{}{
			policies.FieldAutoRotate: true,
			policies.FieldRotateKeys: true,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
		respPolicy := resp.Data[policies.FieldPolicies].([]map[string]interface{})[0]
		rotation := respPolicy[policies.PolicyTypeRotation].(map[string]interface{})
		warning := respPolicy["warning"].(errors.Warning)
		assert.Equal(t, rotation[policies.FieldAutoRotate], expectedPolicy[policies.FieldAutoRotate])
		assert.Equal(t, rotation[policies.FieldRotateKeys], expectedPolicy[policies.FieldRotateKeys])
		assert.Equal(t, warning.Code, logdna.Warn07001)
		assert.Equal(t, warning.Message, policyWasUpdatedTooLate)

	})

	t.Run("Update policy - missing auto_rotate", func(t *testing.T) {
		data := map[string]interface{}{
			policies.FieldPolicy: policies.PolicyTypeRotation,
			policies.FieldPolicies: []map[string]interface{}{{
				policies.PolicyTypeRotation: map[string]interface{}{
					"wrong_field": true,
				}}}}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      PathSecrets + expiresIn20Days_autoRotateTrue_id + "/policies",
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(policiesNotValidField, policies.FieldAutoRotate)
		assert.Equal(t, len(resp.Headers[errors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[errors.ErrorCodeHeader][0], logdna.Error07098)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(http.StatusBadRequest, expectedMessage)))

	})

	t.Run("Update policy - missing rotate_key", func(t *testing.T) {
		data := map[string]interface{}{
			policies.FieldPolicy: policies.PolicyTypeRotation,
			policies.FieldPolicies: []map[string]interface{}{{
				policies.PolicyTypeRotation: map[string]interface{}{
					policies.FieldAutoRotate: true,
					"wrong_field":            true,
				}}}}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      PathSecrets + expiresIn20Days_autoRotateTrue_id + "/policies",
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(policiesNotValidField, policies.FieldRotateKeys)
		assert.Equal(t, len(resp.Headers[errors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[errors.ErrorCodeHeader][0], logdna.Error07099)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(http.StatusBadRequest, expectedMessage)))

	})
}
