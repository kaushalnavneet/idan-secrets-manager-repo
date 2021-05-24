package publiccerts

import (
	"context"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"strings"
)

type OrdersBackend struct {
	secretBackend secret_backend.SecretBackend
	Auth          common.AuthValidator
}

func (ob *OrdersBackend) SetSecretBackend(secretBackend secret_backend.SecretBackend) {
	ob.secretBackend = secretBackend
	ob.Auth = &common.AuthValidatorImpl{}
}

func (ob *OrdersBackend) GetConcretePath() []*framework.Path {
	return framework.PathAppend(
		// set + get config
		ob.pathConfigCA(),
		ob.pathConfigDNS(),
		ob.pathConfigRoot(),
		[]*framework.Path{
			//// Make sure this stays at the end so that the valid paths are processed first.
			//common.PathInvalid(backendHelp),
		})
}
func (ob *OrdersBackend) GetSecretBackendHandler() secret_backend.SecretBackendHandler {
	return &OrdersHandler{}
}

func existenceCheck(ctx context.Context, request *logical.Request, data *framework.FieldData) (bool, error) {
	return false, nil
}

func (ob *OrdersBackend) checkAuthorization(ctx context.Context, req *logical.Request, action string) error {
	//validate that the user is authorised to perform this action
	if err := ob.Auth.ValidateRequestIsAuthorised(ctx, req, action, ""); err != nil {
		if _, ok := err.(logical.HTTPCodedError); ok {
			common.ErrorLogForCustomer("Internal server error", Error07001, logdna.InternalErrorMessage)
			return err
		}
		common.ErrorLogForCustomer(err.Error(), Error07002, logdna.PermissionErrorMessage)
		return err
	}
	return nil
}

var validate = validator.New()

func getRequestInfo(req *logical.Request) string {
	return fmt.Sprintf("request_id: '%s' path: '%s' operation: '%s'", req.ID, req.Path, req.Operation)
}

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
