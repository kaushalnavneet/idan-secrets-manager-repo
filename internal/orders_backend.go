package publiccerts

import (
	"context"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-common-utils/feature_util"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/certificate_parser"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"strings"
	"time"
)

type OrdersBackend struct {
	secretBackend secret_backend.SecretBackend
	storage       logical.Storage
	ordersHandler *OrdersHandler
	RestClient    rest_client.RestClientFactory
}

func (ob *OrdersBackend) SetSecretBackend(secretBackend secret_backend.SecretBackend) {
	ob.secretBackend = secretBackend
}

func (ob *OrdersBackend) GetSecretBackendHandler() secret_backend.SecretBackendHandler {
	//first time create order handler
	if ob.ordersHandler == nil {
		oh := &OrdersHandler{
			runningOrders:  make(map[string]WorkItem),
			beforeOrders:   make(map[string]WorkItem),
			parser:         &certificate_parser.CertificateParserImpl{},
			cron:           ob.secretBackend.(*secret_backend.SecretBackendImpl).Cron,
			metadataClient: ob.secretBackend.GetMetadataClient(),
		}
		oh.workerPool = NewWorkerPool(oh,
			GetEnv("MAX_WORKERS", MaxWorkers).(int),
			GetEnv("MAX_CERT_REQUEST", MaxCertRequest).(int),
			GetEnv("CERT_REQUEST_TIMEOUT_SECS", CertRequestTimeout).(time.Duration)*time.Second)
		ob.ordersHandler = oh
	}
	return ob.ordersHandler
}

func (ob *OrdersBackend) GetConcretePath() []*framework.Path {
	path := framework.PathAppend(
		// set + get config
		ob.pathConfigCA(),
		ob.pathConfigDNS(),
		ob.pathConfigRoot(),
		//rotation policy
		ob.pathSecretPolicies(),
		//order
		ob.pathIssueCert(),
		//rotate
		ob.pathRotateCertificate(),
		//secret / metadata
		ob.pathCertificateMetadata(),
		ob.pathCertificate(),
		ob.pathGetVersion(),
		ob.pathGetVersionMetadata(),
		//autorotate+cleanup
		ob.pathAutoRotate(),
		ob.pathResume(),
	)
	if feature_util.IsFeatureEnabled("GetSecretVersion") {
		path = framework.PathAppend(path, ob.pathListVersions())
	}
	return path
}

func (ob *OrdersBackend) PeriodicFunc(ctx context.Context, req *logical.Request) error {
	return common.PerformOperationOnAllSecrets(ctx, req, ob.secretBackend.GetMetadataClient(), ob.secretBackend.GetPluginSecretType(), ob.secretBackend.MarkSecretAsDestroyedIfExpired)
}

func existenceCheck(ctx context.Context, request *logical.Request, data *framework.FieldData) (bool, error) {
	return false, nil
}

var validate = validator.New()

func (ob *OrdersBackend) validateStringField(data *framework.FieldData, fieldName, validator, msg string) (string, error) {
	f := data.Get(fieldName)
	field := ""
	if f != nil {
		field = strings.TrimSpace(f.(string))
	}

	if err := validate.Var(field, validator); err != nil {
		e := fmt.Errorf("field: '%s' failed validation: %s", fieldName, msg)
		common.Logger().Error(e.Error())
		return "", e
	}
	return field, nil
}
