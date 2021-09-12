package publiccerts

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/certificate"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"gotest.tools/v3/assert"
	"testing"
)

var oh *OrdersHandler

func Test_AutoRotate(t *testing.T) {
	oh = &OrdersHandler{
		runningOrders: make(map[string]WorkItem),
		beforeOrders:  make(map[string]WorkItem),
		parser:        &certificate.CertificateParserImpl{},
	}
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{})
	initBackend()

	t.Run("Rotate certificates", func(t *testing.T) {
		createCertificates()
		//get secret
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      AutoRotatePath,
			Storage:   storage,
			Data:      make(map[string]interface{}),
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
	})
}

func createCertificates() {
	orderResult := createOrderResult(false, true, true)
	oh.saveOrderResultToStorage(orderResult)
}
