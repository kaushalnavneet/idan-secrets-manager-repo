package publiccerts

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/certificate"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"strings"
	"time"
)

type OrdersBackend struct {
	secretBackend secret_backend.SecretBackend
	storage       logical.Storage
}

func (ob *OrdersBackend) SetSecretBackend(secretBackend secret_backend.SecretBackend) {
	ob.secretBackend = secretBackend
}

func (ob *OrdersBackend) GetConcretePath() []*framework.Path {
	return framework.PathAppend(
		// set + get config
		ob.pathConfigCA(),
		ob.pathConfigDNS(),
		ob.pathConfigRoot(),
		//rotation policy
		//ob.pathSecretPolicies(),
		//order
		ob.pathIssueCert(),
		//rotate
		ob.pathRotateCertificate(),
		//secret / metadata
		ob.pathCertificateMetadata(),
		ob.pathCertificate(),
		ob.pathGetVersion(),
		ob.pathGetVersionMetadata(),
		[]*framework.Path{
			//// Make sure this stays at the end so that the valid paths are processed first.
			//common.PathInvalid(backendHelp),
		})
}

func (ob *OrdersBackend) GetSecretBackendHandler() secret_backend.SecretBackendHandler {
	oh := &OrdersHandler{
		runningOrders: make(map[string]WorkItem),
		beforeOrders:  make(map[string]WorkItem),
		parser:        &certificate.CertificateParserImpl{},
	}
	oh.workerPool = NewWorkerPool(oh,
		GetEnv("MAX_WORKERS", MaxWorkers).(int),
		GetEnv("MAX_CERT_REQUEST", MaxCertRequest).(int),
		GetEnv("CERT_REQUEST_TIMEOUT_SECS", CertRequestTimeout).(time.Duration)*time.Second)
	return oh
}

func existenceCheck(ctx context.Context, request *logical.Request, data *framework.FieldData) (bool, error) {
	return false, nil
}

func (ob *OrdersBackend) checkAuthorization(ctx context.Context, req *logical.Request, action string) error {
	//validate that the user is authorised to perform this action
	if err := ob.secretBackend.GetValidator().ValidateRequestIsAuthorised(ctx, req, action, ""); err != nil {
		if _, ok := err.(logical.HTTPCodedError); ok {
			common.Logger().Error("Failed to validate request is authorised", "error", err)
			common.ErrorLogForCustomer("Internal server error", logdna.Error07001, logdna.InternalErrorMessage, false)
			return err
		}
		common.ErrorLogForCustomer(err.Error(), logdna.Error07002, logdna.PermissionErrorMessage, true)
		return err
	}
	return nil
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

func (ob *OrdersBackend) validateConfigName(d *framework.FieldData) (string, error) {
	name, err := ob.validateStringField(d, secretentry.FieldName, "min=2,max=256", "length should be 2 to 256 chars")
	if err != nil {
		errorMessage := fmt.Sprintf("Parameters validation error: %s", err.Error())
		common.ErrorLogForCustomer(errorMessage, logdna.Error07052, logdna.BadRequestErrorMessage, true)
		return "", errors.New(errorMessage)
	}
	return name, nil
}
