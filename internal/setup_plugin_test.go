package publiccerts

import (
	"context"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"gotest.tools/v3/assert"
	"testing"
	"time"
)

func Test_setup_plugin(t *testing.T) {
	oh := initOrdersHandler()
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{ordersHandler: oh})
	testSystem := logical.TestSystemView()
	config := &logical.BackendConfig{
		StorageView: storage,
		Logger:      hclog.NewNullLogger(),
		System:      testSystem,
	}
	t.Run("Setup plugin", func(t *testing.T) {
		c := b.Cron
		err := SetupPublicCertPlugin(context.Background(), config, b)
		assert.NilError(t, err)
		assert.Equal(t, len(c.Entries()) > 0, true)
		assert.Equal(t, c.Entries()[0].Valid(), true)
		//next rotation should be in less than 3 hours
		found := false
		for _, entry := range b.Cron.Entries() {
			if entry.ID == rotateEntryId {
				found = true
				assert.Equal(t, true, b.Cron.Entries()[0].Next.Before(time.Now().Add(3*time.Hour)))
			}
		}
		assert.Equal(t, found, true)
	})
}
