package publiccerts

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ExecFunctionType func(cancelChan chan struct{}, workItem WorkItem, timeout time.Duration)
type WorkerPool struct {
	workChan          chan WorkItem
	cancelChan        chan struct{}
	wg                sync.WaitGroup
	httpClientWrapper HttpClientWrapper
	cache             *Cache
	handler           *OrdersHandler
	execFunction      ExecFunctionType
}

type HttpClientWrapper struct {
	client *http.Client
	mut    sync.RWMutex
}

type WorkItem struct {
	storage    logical.Storage
	requestID  uuid.UUID
	userConfig *CAUserConfig
	dnsConfig  *DnsProviderConfig

	keyType    certcrypto.KeyType
	privateKey []byte
	csr        *x509.CertificateRequest
	domains    []string //first entry is the CN and the rest are SAN
	isBundle   bool

	secretEntry *secretentry.SecretEntry
	req         *logical.Request
	ctx         context.Context
}

type Result struct {
	workItem    WorkItem
	Error       error
	certificate *certificate.Resource
}

func NewWorkerPool(handler *OrdersHandler, numWorkers, maxWorkItems int, timeout time.Duration, execFunction ...ExecFunctionType) *WorkerPool {
	workerPool := WorkerPool{
		workChan:          make(chan WorkItem, maxWorkItems),
		cancelChan:        make(chan struct{}),
		httpClientWrapper: HttpClientWrapper{client: nil},
		cache:             NewCache(),
		handler:           handler,
	}
	if len(execFunction) == 0 {
		workerPool.execFunction = workerPool.startCertificateRequest
	} else {
		workerPool.execFunction = execFunction[0]
	}

	for i := 0; i < numWorkers; i++ {
		workerPool.wg.Add(1)
		go func(pool *WorkerPool) {
			for {
				select {
				case workItem := <-pool.workChan:
					pool.execFunction(pool.cancelChan, workItem, timeout)
					pool.deleteCertificateRequest(workItem.domains)
				case <-pool.cancelChan:
					common.Logger().Debug("[Waiting to receive work] Received Cancellation signal")
					pool.wg.Done()
					return
				}
			}
		}(&workerPool)
	}

	return &workerPool
}

func (w *WorkerPool) getOrCreateHttpClient(userConfig *CAUserConfig) (*http.Client, error) {

	w.httpClientWrapper.mut.RLock()
	if w.httpClientWrapper.client == nil {
		w.httpClientWrapper.mut.RUnlock()
		w.httpClientWrapper.mut.Lock()
		defer w.httpClientWrapper.mut.Unlock()
		client, err := GetHTTPSClient(userConfig.CARootCert)
		if err != nil {
			return nil, err
		}
		w.httpClientWrapper.client = client

	} else {
		w.httpClientWrapper.mut.RUnlock()
	}
	return w.httpClientWrapper.client, nil

}

func (w *WorkerPool) startCertificateRequest(cancelChan chan struct{}, workItem WorkItem, timeout time.Duration) {
	select {

	case result := <-w.getCertificate(workItem):
		result.workItem = workItem
		//update storage with the order result
		w.handler.saveOrderResultToStorage(result)

	case <-time.After(timeout):
		common.Logger().Debug("timeout")
		result := Result{
			workItem:    workItem,
			Error:       errors.New("timeout"),
			certificate: nil,
		}
		w.handler.saveOrderResultToStorage(result)
		//w.createAndStoreErrorCert(workItem, "timeout")

	// [Navaneeth] Note: Current assessment is that ongoing certificate request cannot be cancelled
	// because Lego does not support a transport that can be cancelled
	case <-cancelChan:
		common.Logger().Info("[Waiting for work to finish] Received Cancellation signal")
		return
	}
}

func (w *WorkerPool) getCertificate(workItem WorkItem) chan Result {
	// [Navaneeth] Note: channel size needs to be 1 to avoid goroutine leak when work is cancelled
	resultChan := make(chan Result, 1)
	common.Logger().Info("Certificate request received")

	go func() {
		result, err := w.issueCertificate(workItem)
		if err != nil {
			common.Logger().Error(err.Error())
			var errorResult Result
			errorResult.Error = err
			resultChan <- errorResult
			return
		}

		if result != nil {
			resultChan <- *result
		} else {
			var errorResult Result
			errorResult.Error = fmt.Errorf("nil result")
			resultChan <- errorResult
		}

	}()

	return resultChan

}

func (w *WorkerPool) issueCertificate(workItem WorkItem) (*Result, error) {
	var result Result

	// [Navaneeth] Note: - we want to avoid creating multiple connections, so create one only if a cached
	// connection does not exist
	httpClient, err := w.getOrCreateHttpClient(workItem.userConfig)
	if err != nil {
		common.Logger().Error("Http client create/get error: " + err.Error())
		return nil, err
	}

	client, err := NewACMEClientWithCustomHttpClient(workItem.userConfig, workItem.keyType, httpClient)
	//client, err := NewACMEClient(workItem.userConfig, workItem.keyType)

	if err != nil {
		return nil, err
	}

	err = client.SetChallengeProviders(workItem.dnsConfig)
	if err != nil {
		return nil, err
	}

	if workItem.csr != nil {
		certificateResource, err := client.ObtainCertificateForCSR(workItem.csr, workItem.isBundle)
		if err != nil {
			return nil, err
		}
		certificateResource.PrivateKey = workItem.privateKey
		result.certificate = certificateResource
	} else {
		certificateResource, err := client.ObtainCertificate(workItem.domains, workItem.isBundle)
		if err != nil {
			return nil, err
		}
		result.certificate = certificateResource
	}
	return &result, nil
}

func (w *WorkerPool) ScheduleCertificateRequest(workItem WorkItem) (string, error) {

	//if len(workItem.domains) == 0 {
	//	return "", fmt.Errorf("no domain provided for certificate request")
	//}
	//
	//_, err := w.createAndStorePendingCertIfNotExists(&workItem)
	//if err != nil {
	//	return "", err
	//}

	select {

	case w.workChan <- workItem:
		return workItem.requestID.String(), nil

	default:
		w.deleteCertificateRequest(workItem.domains)
		//err := w.handler.certStore.DeleteFromVault(context.TODO(), workItem.storage, w.handler.GetCertEntryPath(workItem.domains, workItem.requestID.String()))
		//if err != nil {
		//	return "", err
		//}
		return "", fmt.Errorf("too many pending requests! Try again later")

	}
}

func (w *WorkerPool) addCertificateRequestToPending(key []string, value string) {
	w.cache.Store(strings.Join(key, ","), value)
}

// returns the key, value pair and the status as to whether the key value pair was inserted
// Success (true) means that there was no entry with the key existing in the map. In this case the input key, value pair is returned
// Failure (false) means that there already exists an entry with this key. In this case the existing key, value pair is returned
func (w *WorkerPool) addCertificateRequestToPendingIfNotExists(key []string, value string) (KeyValue, bool) {
	return w.cache.StoreIfNotExists(strings.Join(key, ","), value)
}

func (w *WorkerPool) isCertificateRequestPending(key []string) (string, bool) {
	response, ok := w.cache.Fetch(strings.Join(key, ","))
	return response.Value, ok
}

func (w *WorkerPool) deleteCertificateRequest(key []string) {
	w.cache.Delete(strings.Join(key, ","))
}

func (w *WorkerPool) CancelAll() {
	close(w.cancelChan)
	w.wg.Wait()
}
