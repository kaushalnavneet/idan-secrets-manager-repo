package publiccerts

import (
	"context"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
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
		checkOrdersInProgress(t, []OrderDetails{})
		assert.Equal(t, len(oh.runningOrders), 0)
	})

	t.Run("Order exist but already Active", func(t *testing.T) {
		common.StoreSecretWithoutLocking(expiresIn30Days_autoRotateTrue, storage, context.Background(), nil, false)
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
		checkOrdersInProgress(t, []OrderDetails{})
		assert.Equal(t, len(oh.runningOrders), 0)
	})

	t.Run("Order started more than 3 hours ago", func(t *testing.T) {
		issuanceInfoToTest := map[string]interface{}{
			secretentry.FieldState:            secretentry.StatePreActivation,
			secretentry.FieldStateDescription: secretentry.GetNistStateDescription(secretentry.StatePreActivation),
			FieldBundleCert:                   true, FieldCAConfig: caConfig, FieldDNSConfig: dnsConfig, FieldAutoRotated: true,
			FieldOrderedOn: time.Now().UTC().Add(-14 * time.Hour),
		}
		certMetadataToTest := certMetadata
		certMetadataToTest.IssuanceInfo = issuanceInfoToTest
		entryToTest := expiresIn30Days_autoRotateTrue
		entryToTest.ExtraData = certMetadataToTest
		entryToTest.ID = uuid.New().String()
		common.StoreSecretWithoutLocking(entryToTest, storage, context.Background(), nil, false)
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
		checkOrdersInProgress(t, []OrderDetails{})
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
		common.StoreSecretWithoutLocking(entryToTest, storage, context.Background(), nil, false)
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
		checkOrdersInProgress(t, []OrderDetails{})
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
		common.StoreSecretWithoutLocking(entryToTest, storage, context.Background(), nil, false)
		setOrdersInProgressWithAttempts(entryToTest.ID, 1)
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
		checkOrdersInProgress(t, []OrderDetails{{GroupId: defaultGroup, Id: entryToTest.ID, Attempts: 2}})
	})

	t.Run("Resume order - third attempt = failure", func(t *testing.T) {
		//reset running orders
		oh.runningOrders = make(map[string]WorkItem)
		issuanceInfoToTest := map[string]interface{}{
			secretentry.FieldState:            secretentry.StatePreActivation,
			secretentry.FieldStateDescription: secretentry.GetNistStateDescription(secretentry.StatePreActivation),
			FieldBundleCert:                   false, FieldCAConfig: caConfig, FieldDNSConfig: dnsConfig, FieldAutoRotated: false,
			FieldOrderedOn: time.Now().UTC().Add(-1 * time.Hour),
		}
		certMetadataToTest := certMetadata //copy all fields and override reference type fields
		certMetadataToTest.IssuanceInfo = issuanceInfoToTest
		entryToTest := expiresIn30Days_autoRotateTrue //copy all fields and override reference type fields
		entryToTest.ExtraData = certMetadataToTest
		entryToTest.ID = uuid.New().String()
		common.StoreSecretWithoutLocking(entryToTest, storage, context.Background(), nil, false)
		setOrdersInProgressWithAttempts(entryToTest.ID, MaxAttemptsToOrder)
		//resume orders
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
		checkOrdersInProgress(t, []OrderDetails{})

		//check secret
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      PathSecrets + entryToTest.ID,
			Storage:   storage,
			Data:      make(map[string]interface{}),
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err = b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		//common fields
		assert.Equal(t, false, resp.IsError())
		//issuance info
		assert.Equal(t, resp.Data[secretentry.FieldId], entryToTest.ID)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRotated], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldBundleCert], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldCAConfig], caConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldDNSConfig], dnsConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(secretentry.StateDeactivated))
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldErrorCode], logdna.Error07046)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldErrorMessage], orderCouldNotBeProcessed)
	})
}

func setOrdersInProgressWithAttempts(id string, attempt int) {
	ordersInProgress := getOrdersInProgress(storage)
	ordersInProgress.Orders = []OrderDetails{{GroupId: defaultGroup, Id: id, Attempts: attempt}}
	ordersInProgress.save(storage)
}
