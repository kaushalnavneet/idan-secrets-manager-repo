package publiccerts

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-common-utils/secret_metadata_entry"
	"github.ibm.com/security-services/secrets-manager-common-utils/secret_metadata_entry/certificate"
	"github.ibm.com/security-services/secrets-manager-common-utils/types_common"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	commonErrors "github.ibm.com/security-services/secrets-manager-vault-plugins-common/errors"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"net/http"
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
	if common.ReadOnlyEnabled(ob.secretBackend.GetMetadataClient()) {
		common.Logger().Error("vault is in read only mode")
		return commonErrors.GenerateReadOnlyCodedErrorResponse()
	}

	common.Logger().Info("Start resuming orders in progress")
	ordersInProgress := getOrdersInProgress(req.Storage)
	ordersToResume := len(ordersInProgress.Orders)
	common.Logger().Info(strconv.Itoa(ordersToResume) + " orders will be checked for resuming")
	//go from the last to the first because they can be deleted in process
	for i := ordersToResume - 1; i >= 0; i-- {
		ob.resumeOrder(ctx, req, ordersInProgress.Orders[i])
	}
	return nil, nil
}

func (ob *OrdersBackend) resumeOrder(ctx context.Context, req *logical.Request, item OrderDetails) {
	secretPath := item.GroupId + "/" + item.Id
	secretEntry, err := common.GetSecretWithoutLocking(secretPath, secretentry.SecretTypePublicCert, req.Storage, ctx, ob.secretBackend.GetMetadataClient())
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
	resumeInProgress := false
	if item.Attempts >= MaxAttemptsToOrder {
		common.Logger().Info(fmt.Sprintf("The secret entry '%s' has %d attempts to order. Stop trying", secretPath, item.Attempts))
		ob.setOrderFailed(secretEntry, certMetadata, secretPath, req.Storage, ob.secretBackend.GetMetadataClient(), item.TriggeredBy)
	} else if isResumingNeeded(certMetadata, secretPath, req.Storage, item) {
		common.Logger().Info(fmt.Sprintf("Trying to resume the secret entry '%s' order ", secretPath))
		err = ob.prepareAndStartOrder(ctx, req, secretEntry, certMetadata, item.TriggeredBy)
		resumeInProgress = err == nil
	}
	if !resumeInProgress {
		removeOrderFromOrdersInProgress(req.Storage, item)
	}
}

func (ob *OrdersBackend) setOrderFailed(secretEntry *secretentry.SecretEntry, certMetadata *certificate.CertificateMetadata, secretPath string, storage logical.Storage, metadataClient common.MetadataClient, triggeredBy string) {
	common.Logger().Error(fmt.Sprintf("Couldn't resume '%s' order in 2 attempts. Stop trying", secretPath))
	err := commonErrors.GenerateCodedError(logdna.Error07046, http.StatusInternalServerError, orderCouldNotBeProcessed)
	updateIssuanceInfoWithError(certMetadata, secretEntry, err)
	secretEntry.ExtraData = certMetadata

	opp := common.StoreOptions{
		Operation:            types_common.StoreOptionUpdateMetadata,
		OperationTriggeredBy: triggeredBy,
		VersionMapper:        ob.secretBackend.GetMetadataMapper().MapVersionMetadata,
	}
	errToStore := common.StoreSecretAndVersionWithoutLocking(secretEntry, storage, context.Background(), metadataClient, &opp)
	if errToStore != nil {
		common.Logger().Error(fmt.Sprintf("Couldn't save failed resumed '%s' order data to storage. Error:%s ", secretPath, errToStore.Error()))
	}
}

func (ob *OrdersBackend) prepareAndStartOrder(ctx context.Context, req *logical.Request, secretEntry *secretentry.SecretEntry, certMetadata *certificate.CertificateMetadata, triggeredBy string) error {
	secretPath := secretEntry.GroupID + "/" + secretEntry.ID
	var privateKey []byte
	//if order in progress is rotation, get private key if rotate_keys ==false
	if secretEntry.State == secretentry.StateActive && !secretEntry.Policies.Rotation.RotateKeys() {
		common.Logger().Debug(fmt.Sprintf("Secret '%s' with id %s will be rotated with the same private key", secretEntry.Name, secretEntry.ID))
		rawdata, _ := certificate.DecodeRawData(secretEntry.LastVersionData())
		privateKey = []byte(rawdata.PrivateKey)
	}
	oh := ob.GetSecretBackendHandler().(*OrdersHandler)
	err := oh.prepareOrderWorkItem(ctx, req, certMetadata, privateKey, triggeredBy)

	if err != nil {
		common.Logger().Error(fmt.Sprintf("Couldn't resume the order '%s'. Error: %s", secretPath, err.Error()))
		updateIssuanceInfoWithError(certMetadata, secretEntry, err)
		secretEntry.ExtraData = certMetadata
		opp := common.StoreOptions{
			VersionMapper:        ob.secretBackend.GetMetadataMapper().MapVersionMetadata,
			OperationTriggeredBy: triggeredBy,
			Operation:            types_common.StoreOptionUpdateMetadata,
		}
		errToStore := common.StoreSecretAndVersionWithoutLocking(secretEntry, req.Storage, context.Background(), ob.secretBackend.GetMetadataClient(), &opp)
		if errToStore != nil {
			common.Logger().Error(fmt.Sprintf("Couldn't save failed resumed '%s' order data to storage. Error:%s ", secretPath, errToStore.Error()))
		}
		return err
	}
	oh.startOrder(secretEntry, oh.workerPool)
	return nil
}

func isResumingNeeded(certMetadata *certificate.CertificateMetadata, secretPath string, storage logical.Storage, item OrderDetails) bool {
	needToResume := false

	orderState := int(certMetadata.IssuanceInfo[secretentry.FieldState].(float64))
	orderTimeString := certMetadata.IssuanceInfo[FieldOrderedOn].(string)
	orderStartTime, err := time.Parse(time.RFC3339, orderTimeString)
	if err != nil {
		common.Logger().Info(fmt.Sprintf("The secret entry '%s' has invalid order time %s.", secretPath, orderTimeString))
		//check that order indeed in the progress
	} else if orderState != secretentry.StatePreActivation {
		common.Logger().Info(fmt.Sprintf("The secret entry '%s' is in state %s. No need to resume", secretPath, secret_metadata_entry.GetNistStateDescription(orderState)))
		//check that order is in progress not more than 12 hours
	} else if orderState == secretentry.StatePreActivation && orderStartTime.Add(12*time.Hour).Before(time.Now().UTC()) {
		common.Logger().Info(fmt.Sprintf("The secret entry '%s' order was started more than 12 hours ago (at %s).", secretPath, orderTimeString))
	} else {
		needToResume = true
	}

	return needToResume
}
