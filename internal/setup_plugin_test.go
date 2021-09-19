package publiccerts

import (
	"context"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"gotest.tools/v3/assert"
	"testing"
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
	t.Run("First order - order succeeded", func(t *testing.T) {
		c := b.Cron
		err := SetupPublicCertPlugin(context.Background(), config, b)
		assert.NilError(t, err)
		assert.Equal(t, len(c.Entries()), 2)
		assert.Equal(t, c.Entries()[0].Valid(), true)
		//parser:=cron.NewParser(cron.ParseOption)
		//schedule, err := c.parser.Parse("5 */3 * * *")
		//assert.Equal(t,b.Cron.Entries()[0].Schedule, )
	})
}
