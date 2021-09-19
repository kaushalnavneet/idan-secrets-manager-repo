package publiccerts

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/certificate"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"strconv"
	"time"
)

func (ob *OrdersBackend) pathResume() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: ResumeOrderPath,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: ob.resumeOrdersInProgress}},
		},
	}
}

func (ob *OrdersBackend) resumeOrdersInProgress(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	common.Logger().Info("Start resuming orders in progress")
	ordersInProgress := getOrdersInProgress(req.Storage)
	ordersToResume := len(ordersInProgress.SecretIds)
	common.Logger().Info(strconv.Itoa(ordersToResume) + " orders will be checked for resuming")
	//go from the last to the first because they can be deleted in process
	for i := ordersToResume - 1; i >= 0; i-- {
		ob.resumeOrder(ctx, req, ordersInProgress.SecretIds[i])
	}
	return nil, nil
}

func (ob *OrdersBackend) resumeOrder(ctx context.Context, req *logical.Request, item SecretId) {
	secretPath := item.GroupId + "/" + item.Id
	secretEntry, err := common.GetSecretWithoutLocking(secretPath, req.Storage, ctx)
	if err != nil {
		common.Logger().Error(fmt.Sprintf("Couldn't get secret entry '%s' in order to resume its order: %s", secretPath, err.Error()))
		return
	}
	if secretEntry == nil {
		common.Logger().Error(fmt.Sprintf("Couldn't get secret entry '%s'. It doesn't exist", secretPath))
		removeOrderFromOrdersInProgress(req.Storage, item)
		return
	}
	certMetadata, _ := certificate.DecodeMetadata(secretEntry.ExtraData)
	if !isResumingNeeded(certMetadata, secretPath, req.Storage, item) {
		return
	}
	common.Logger().Info(fmt.Sprintf("Trying to resume the secret entry '%s' order ", secretPath))
	if err = ob.prepareAndStartOrder(ctx, req, secretEntry, certMetadata); err != nil {
		removeOrderFromOrdersInProgress(req.Storage, item)
	}
}

func (ob *OrdersBackend) prepareAndStartOrder(ctx context.Context, req *logical.Request, secretEntry *secretentry.SecretEntry, certMetadata *certificate.CertificateMetadata) error {
	secretPath := secretEntry.GroupID + "/" + secretEntry.ID
	var privateKey []byte
	//if order in progress is rotation, get private key if rotate_keys ==false
	if secretEntry.State == secretentry.StateActive && !secretEntry.Policies.Rotation.RotateKeys() {
		common.Logger().Debug(fmt.Sprintf("Secret '%s' with id %s will be rotated with the same private key", secretEntry.Name, secretEntry.ID))
		rawdata, _ := certificate.DecodeRawData(secretEntry.LastVersionData())
		privateKey = []byte(rawdata.PrivateKey)
	}
	oh := ob.GetSecretBackendHandler().(*OrdersHandler)
	err := oh.prepareOrderWorkItem(ctx, req, certMetadata, privateKey)
	if err != nil {
		common.Logger().Error(fmt.Sprintf("Couldn't resume the order '%s'. Error: %s", secretPath, err.Error()))
		updateIssuanceInfoWithError(certMetadata, err)
		secretEntry.ExtraData = certMetadata
		errToStore := common.StoreSecretWithoutLocking(secretEntry, req.Storage, context.Background())
		if errToStore != nil {
			common.Logger().Error(fmt.Sprintf("Couldn't save failed resumed '%s' order data to storage. Error:%s ", secretPath, errToStore.Error()))
		}
		return err
	}
	oh.startOrder(secretEntry)
	return nil
}

func isResumingNeeded(certMetadata *certificate.CertificateMetadata, secretPath string, storage logical.Storage, item SecretId) bool {
	needToResume := true

	orderState := int(certMetadata.IssuanceInfo[secretentry.FieldState].(float64))
	orderTimeString := certMetadata.IssuanceInfo[FieldOrderedOn].(string)
	orderStartTime, err := time.Parse(time.RFC3339, orderTimeString)
	if err != nil {
		common.Logger().Info(fmt.Sprintf("The secret entry '%s' has invalid order time %s.", secretPath, orderTimeString))
		needToResume = false
		//check that order indeed in the progress
	} else if orderState != secretentry.StatePreActivation {
		common.Logger().Info(fmt.Sprintf("The secret entry '%s' is in state %s. No need to resume", secretPath, secretentry.GetNistStateDescription(orderState)))
		needToResume = false
		//check that order is in progress not more than 3 hours
	} else if orderState == secretentry.StatePreActivation && orderStartTime.Add(3*time.Hour).Before(time.Now().UTC()) {
		common.Logger().Info(fmt.Sprintf("The secret entry '%s' order was started more than 3 hours ago (at %s).", secretPath, orderTimeString))
		needToResume = false
	}
	if !needToResume {
		removeOrderFromOrdersInProgress(storage, item)
	}
	return needToResume
}
