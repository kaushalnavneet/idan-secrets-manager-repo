package publiccerts

import (
	"context"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"gotest.tools/v3/assert"
	"testing"
	"time"
)

func Test_Resume(t *testing.T) {
	oh := initOrdersHandler()
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{ordersHandler: oh})
	initBackend()

	t.Run("Order doesn't exist anymore", func(t *testing.T) {
		setOrdersInProgress(secretId, 1)
		//get secret
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ResumeOrderPath,
			Storage:   storage,
			Data:      make(map[string]interface{}),
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
		checkOrdersInProgress(t, []SecretId{})
		assert.Equal(t, len(oh.runningOrders), 0)
	})

	t.Run("Order exist but already Active", func(t *testing.T) {
		common.StoreSecretWithoutLocking(expiresIn30Days_autoRotateTrue, storage, context.Background())
		setOrdersInProgress(expiresIn30Days_autoRotateTrue_id, 1)
		//get secret
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ResumeOrderPath,
			Storage:   storage,
			Data:      make(map[string]interface{}),
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
		checkOrdersInProgress(t, []SecretId{})
		assert.Equal(t, len(oh.runningOrders), 0)
	})

	t.Run("Order started more than 3 hours ago", func(t *testing.T) {
		issuanceInfoToTest := map[string]interface{}{
			secretentry.FieldState:            secretentry.StatePreActivation,
			secretentry.FieldStateDescription: secretentry.GetNistStateDescription(secretentry.StatePreActivation),
			FieldBundleCert:                   true, FieldCAConfig: caConfig, FieldDNSConfig: dnsConfig, FieldAutoRotated: true,
			FieldOrderedOn: time.Now().UTC().Add(-4 * time.Hour),
		}
		certMetadataToTest := certMetadata
		certMetadataToTest.IssuanceInfo = issuanceInfoToTest
		entryToTest := expiresIn30Days_autoRotateTrue
		entryToTest.ExtraData = certMetadataToTest
		entryToTest.ID = uuid.New().String()
		common.StoreSecretWithoutLocking(entryToTest, storage, context.Background())
		setOrdersInProgress(entryToTest.ID, 1)
		//get secret
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ResumeOrderPath,
			Storage:   storage,
			Data:      make(map[string]interface{}),
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
		checkOrdersInProgress(t, []SecretId{})
		assert.Equal(t, len(oh.runningOrders), 0)
	})

	t.Run("Resume order - config doesn't exist", func(t *testing.T) {
		//reset running orders
		oh.runningOrders = make(map[string]WorkItem)
		issuanceInfoToTest := map[string]interface{}{
			secretentry.FieldState:            secretentry.StatePreActivation,
			secretentry.FieldStateDescription: secretentry.GetNistStateDescription(secretentry.StatePreActivation),
			FieldBundleCert:                   true, FieldCAConfig: "wrong", FieldDNSConfig: dnsConfig, FieldAutoRotated: true,
			FieldOrderedOn: time.Now().UTC().Add(-1 * time.Hour),
		}
		certMetadataToTest := certMetadata //copy all fields and override reference type fields
		certMetadataToTest.IssuanceInfo = issuanceInfoToTest
		entryToTest := expiresIn30Days_autoRotateTrue //copy all fields and override reference type fields
		entryToTest.ExtraData = certMetadataToTest
		entryToTest.ID = uuid.New().String()
		common.StoreSecretWithoutLocking(entryToTest, storage, context.Background())
		setOrdersInProgress(entryToTest.ID, 1)
		//get secret
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ResumeOrderPath,
			Storage:   storage,
			Data:      make(map[string]interface{}),
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
		assert.Equal(t, len(oh.runningOrders), 0)
		checkOrdersInProgress(t, []SecretId{})
		//should become Deactivated
		expectedIssuanceInfoForFailedRotation := map[string]interface{}{
			secretentry.FieldState:            secretentry.StateDeactivated,
			secretentry.FieldStateDescription: secretentry.GetNistStateDescription(secretentry.StateDeactivated),
			FieldErrorCode:                    "secrets-manager.Error07012",
			FieldErrorMessage:                 "Certificate authority configuration with name 'wrong' was not found",
			FieldBundleCert:                   true, FieldCAConfig: "wrong", FieldDNSConfig: dnsConfig, FieldAutoRotated: true}
		getSecretAndCheckItsContent(t, entryToTest.ID, entryToTest, expectedIssuanceInfoForFailedRotation)
	})

	t.Run("Resume order - happy flow", func(t *testing.T) {
		//reset running orders
		oh.runningOrders = make(map[string]WorkItem)
		issuanceInfoToTest := map[string]interface{}{
			secretentry.FieldState:            secretentry.StatePreActivation,
			secretentry.FieldStateDescription: secretentry.GetNistStateDescription(secretentry.StatePreActivation),
			FieldBundleCert:                   true, FieldCAConfig: caConfig, FieldDNSConfig: dnsConfig, FieldAutoRotated: true,
			FieldOrderedOn: time.Now().UTC().Add(-1 * time.Hour),
		}
		certMetadataToTest := certMetadata //copy all fields and override reference type fields
		certMetadataToTest.IssuanceInfo = issuanceInfoToTest
		entryToTest := expiresIn30Days_autoRotateTrue //copy all fields and override reference type fields
		entryToTest.ExtraData = certMetadataToTest
		entryToTest.ID = uuid.New().String()
		common.StoreSecretWithoutLocking(entryToTest, storage, context.Background())
		setOrdersInProgress(entryToTest.ID, 1)
		//get secret
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ResumeOrderPath,
			Storage:   storage,
			Data:      make(map[string]interface{}),
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
		assert.Equal(t, len(oh.runningOrders), 1)
		checkOrdersInProgress(t, []SecretId{{GroupId: defaultGroup, Id: entryToTest.ID}})
	})
}
