package publiccerts

import (
	"fmt"
	"github.com/google/uuid"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/certificate"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"gotest.tools/v3/assert"
	"strconv"
	"testing"
	"time"
)

func WaitFunction(cancelChan chan struct{}, workItem WorkItem, timeout time.Duration) {
	time.Sleep(2 * time.Second)
}

func TestWorkerPoolFull(t *testing.T) {
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{})
	initBackend()
	oh := &OrdersHandler{
		runningOrders: make(map[string]WorkItem),
		beforeOrders:  make(map[string]WorkItem),
		parser:        &certificate.CertificateParserImpl{},
	}
	pool := NewWorkerPool(oh, 1, 2, 10*time.Second, WaitFunction)
	workItem := WorkItem{
		requestID:   uuid.UUID{},
		caConfig:    &CAUserConfig{},
		dnsConfig:   &ProviderConfig{},
		keyType:     keyType,
		privateKey:  nil,
		csr:         nil,
		domains:     []string{certCommonName},
		isBundle:    true,
		secretEntry: &secretentry.SecretEntry{},
	}
	errEncountered := false
	for i := 0; i < 5; i++ {
		workItem.domains = append(workItem.domains, strconv.Itoa(i))
		_, err := pool.ScheduleCertificateRequest(workItem)
		if err != nil {
			errEncountered = true
			assert.Equal(t, fmt.Errorf("too many pending requests! Try again later"), err)
		}
	}
	// assert that at least one error was encountered
	assert.Equal(t, true, errEncountered)

	pool.CancelAll()
}
