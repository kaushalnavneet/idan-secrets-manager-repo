package publiccerts

import (
	"github.com/hashicorp/go-hclog"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"gotest.tools/v3/assert"
	"testing"
)

func Test_Manual(t *testing.T) {
	common.SetLogger(hclog.L())
	t.Run("Present ", func(t *testing.T) {
		providerManual := NewManualDNSProvider()
		err := providerManual.Present(domainName, tokenNotInUse, keyAuth)
		assert.NilError(t, err)
	})
	t.Run("Cleanup", func(t *testing.T) {
		providerManual := NewManualDNSProvider()
		err := providerManual.CleanUp(domainName, tokenNotInUse, keyAuth)
		assert.NilError(t, err)
	})

	t.Run("Timeout", func(t *testing.T) {
		providerManual := NewManualDNSProvider()
		propagationTimeout, pollingInterval := providerManual.Timeout()
		assert.Equal(t, PropagationTimeoutManual, propagationTimeout)
		assert.Equal(t, PollingIntervalManual, pollingInterval)
	})
}
