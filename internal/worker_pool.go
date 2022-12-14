package publiccerts

import (
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
	handler           *OrdersHandler
	execFunction      ExecFunctionType
}

type HttpClientWrapper struct {
	client *http.Client
	mut    sync.RWMutex
}

type WorkItem struct {
	requestID uuid.UUID //to identify order request in worker pool
	//order data
	caConfig   *CAUserConfig
	dnsConfig  *ProviderConfig
	keyType    certcrypto.KeyType
	privateKey []byte
	csr        *x509.CertificateRequest
	domains    []string //first entry is the CN and the rest are SAN
	isBundle   bool
	//secret data
	secretEntry *secretentry.SecretEntry //this secretEntry should be updated when an order is finished
	storage     logical.Storage          //this storage should be used to save secretEntry
	triggeredBy string                   //the user that triggered the order
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
					//pool.deleteCertificateRequest(workItem.domains)
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
		common.Logger().Info(fmt.Sprintf("Order request reached timeout of %s. Secret Id: %s", timeout, workItem.secretEntry.ID))
		result := Result{
			workItem:    workItem,
			Error:       errors.New("order request reached timeout"),
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
	common.Logger().Info(fmt.Sprintf("Start order certificate (secret Id %s) for domains: %s", workItem.secretEntry.ID, strings.Join(workItem.domains[:], ",")))

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
	client, err := w.createAcmeClient(workItem)
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
		certificateResource, err := client.ObtainCertificate(workItem.domains, workItem.isBundle, workItem.caConfig.PreferredChain)
		if err != nil {
			return nil, err
		}
		result.certificate = certificateResource
	}
	common.Logger().Info(fmt.Sprintf("Finished order certificate (secret Id %s) for domains: %s", workItem.secretEntry.ID, strings.Join(workItem.domains[:], ",")))
	return &result, nil
}

func (w *WorkerPool) PrepareChallenges(workItem WorkItem) ([]Challenge, error) {
	client, err := w.createAcmeClient(workItem)
	if err != nil {
		return nil, err
	}
	challenges, err := client.PrepareChallenges(workItem)
	if err != nil {
		return nil, err
	}
	return challenges, nil
}

func (w *WorkerPool) createAcmeClient(workItem WorkItem) (*Client, error) {
	httpClient, err := w.getOrCreateHttpClient(workItem.caConfig)
	if err != nil {
		common.Logger().Error("Http client create/get error: " + err.Error())
		return nil, err
	}

	client, err := NewACMEClientWithCustomHttpClient(workItem.caConfig, workItem.keyType, httpClient)
	if err != nil {
		return nil, err
	}

	err = client.SetChallengeProviders(workItem.dnsConfig, workItem.domains)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (w *WorkerPool) ScheduleCertificateRequest(workItem WorkItem) (string, error) {

	select {
	case w.workChan <- workItem:
		return workItem.requestID.String(), nil
	default:
		common.Logger().Error(fmt.Sprintf("Order (secret Id %s) couldn't be started. The worker pool is full!", workItem.secretEntry.ID))
		return "", errors.New(workerPoolIsFull)
	}
}

func (w *WorkerPool) CancelAll() {
	close(w.cancelChan)
	w.wg.Wait()
}
