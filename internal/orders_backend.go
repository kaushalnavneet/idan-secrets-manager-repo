package publiccerts

import (
	"context"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/certificate_parser"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
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
			parser:         &certificate_parser.CertificateParserImpl{},
			cron:           ob.secretBackend.(*secret_backend.SecretBackendImpl).Cron,
			metadataClient: ob.secretBackend.GetMetadataClient(),
			metadataMapper: secret_backend.GetDefaultMetadataMapper(secretentry.SecretTypePublicCert),
			secretBackend:  ob.secretBackend,
			inAllowList:    true, //placeHolder for features
		}

		oh.workerPool = NewWorkerPool(oh,
			GetEnvInt("PublicCertMaxWorkers", MaxWorkers),
			GetEnvInt("PublicCertPoolSize", MaxCertRequest),
			GetEnv("PublicCertOrderTimeout", CertRequestTimeout).(time.Duration)*time.Second)
		oh.autoRenewWorkerPool = NewWorkerPool(oh,
			GetEnvInt("PublicCertMaxAutoRenewWorkers", MaxAutoRenewWorkers),
			GetEnvInt("PublicCertAutoRenewPoolSize", MaxAutoRenewCertRequest),
			GetEnv("PublicCertOrderTimeout", CertRequestTimeout).(time.Duration)*time.Second)

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
		ob.pathVersionMetadata(),
		//autorotate+cleanup
		ob.pathAutoRotate(),
		ob.pathResume(),
		//list versions
		ob.pathListVersions(),
		//validate dns challenges
		ob.pathContinueOrder(),
	)
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
