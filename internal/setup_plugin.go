package publiccerts

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/robfig/cron/v3"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/errors"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/vault_client_factory"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/vault_cliient_impl"
	"net/http"
	"strconv"
	"time"
)

type AutoRotateConfig struct {
	rotatePath  string
	cleanupPath string
	usageToken  string
	client      *vault_cliient_impl.VaultClientFactory
}

const startResumeOrdersInSec = 120 * time.Second

func SetupPublicCertPlugin(ctx context.Context, conf *logical.BackendConfig, backend *secret_backend.SecretBackendImpl) error {
	common.Logger().Debug("SetupPublicCertPlugin: Trying to get Auth config")
	authConfig, err := common.ObtainAuthConfigFromStorage(ctx, conf.StorageView)
	if err != nil || authConfig == nil {
		common.Logger().Warn("SetupPublicCertPlugin: Couldn't get auth config and configure cron job for certificates auto-rotation. Will try to configure it later")
		return nil
	}
	common.Logger().Info("SetupPublicCertPlugin: Engine config is found.")
	common.Logger().Info("SetupPublicCertPlugin: Resume orders will run in " + startResumeOrdersInSec.String())
	time.AfterFunc(startResumeOrdersInSec, func() { resumeOrders(authConfig) })
	common.Logger().Info("SetupPublicCertPlugin: Configuring job for certificates auto-rotation.")
	return ConfigAutoRotationJob(authConfig, backend.Cron)
}

var rotateEntryId cron.EntryID = 0
var cleanupEntryId cron.EntryID = 0

func ConfigAutoRotationJob(config *common.ICAuthConfig, c *cron.Cron) error {
	common.Logger().Debug("ConfigAutoRotationJob: Trying to configure certificates auto-rotation and cleanup jobs")
	rotationSchedule := "5 */3 * * *"
	cleanupSchedule := "00 23 * * *"

	arc := &AutoRotateConfig{
		rotatePath:  config.Vault.Endpoint + PluginMountPath + AutoRotatePath,
		cleanupPath: config.Vault.Endpoint + PluginMountPath + AutoRotateCleanupPath,
		usageToken:  config.Vault.UpToken,
		client:      &vault_cliient_impl.VaultClientFactory{Logger: common.Logger()},
	}
	common.Logger().Info(fmt.Sprintf("Certificates auto-rotation cron job will call to path `%s` with schedule %s", arc.rotatePath, rotationSchedule))
	var err error
	if c == nil {
		common.Logger().Error(logdna.Error07059+" Failed to configure cron job for certificates auto-rotation: cron is nil ", err)
		return errors.GenerateCodedError(logdna.Error07059, http.StatusInternalServerError, errors.InternalServerError)
	}
	if rotateEntryId == 0 {
		rotateEntryId, err = c.AddFunc(rotationSchedule, arc.startAutoRotateProcess)
		if err != nil {
			common.Logger().Error(logdna.Error07061+" Failed to configure cron job for certificates auto-rotation: error while adding cron function ", err)
			return errors.GenerateCodedError(logdna.Error07061, http.StatusInternalServerError, errors.InternalServerError)
		}
		common.Logger().Info(fmt.Sprintf("Certificates auto-rotation cron job is configured. Entry id = %d", rotateEntryId))
	} else {
		common.Logger().Info("Certificates auto-rotation cron job was already configured before and has EntryId = " + strconv.Itoa(int(rotateEntryId)))
	}
	if cleanupEntryId == 0 {
		cleanupEntryId, err = c.AddFunc(cleanupSchedule, arc.startCleanupProcess)
		if err != nil {
			common.Logger().Error(logdna.Error07067+" Failed to configure cron job for certificates auto-rotation cleanup: error while adding cron function ", err)
			return errors.GenerateCodedError(logdna.Error07067, http.StatusInternalServerError, errors.InternalServerError)
		}
		common.Logger().Info(fmt.Sprintf("Certificates auto-rotation cleanup cron job is configured. Entry id = %d", cleanupEntryId))
	} else {
		common.Logger().Info("Certificates auto-rotation cleanup cron job was already configured before and has EntryId = " + strconv.Itoa(int(cleanupEntryId)))
	}
	return nil
}

func (c *AutoRotateConfig) startAutoRotateProcess() {
	common.Logger().Debug("Start running job for certificates auto-rotation.")
	options := &vault_client_factory.RequestOptions{
		URL:    c.rotatePath,
		Method: http.MethodPost,
		Headers: map[string]string{
			vaultTokenHeader:  c.usageToken,
			acceptHeader:      applicationJson,
			contentTypeHeader: applicationJson,
		},
		Body:               []byte("{}"),
		ResponseScheme:     nil,
		ExpectedStatusCode: http.StatusNoContent,
	}
	_, _, err := c.client.SendRequest(options)
	if err != nil {
		common.Logger().Error("Failed to send request for certificates auto-rotation", err)
	}
}

func (c *AutoRotateConfig) startCleanupProcess() {
	common.Logger().Debug("Start running job for certificates auto-rotation finish (send final error).")
	options := &vault_client_factory.RequestOptions{
		URL:    c.cleanupPath,
		Method: http.MethodPost,
		Headers: map[string]string{
			vaultTokenHeader:  c.usageToken,
			acceptHeader:      applicationJson,
			contentTypeHeader: applicationJson,
		},
		Body:               []byte("{}"),
		ResponseScheme:     nil,
		ExpectedStatusCode: http.StatusNoContent,
	}
	_, _, err := c.client.SendRequest(options)
	if err != nil {
		common.Logger().Error("Failed to send request for certificates auto-rotation cleanup", err)
	}
}

func resumeOrders(config *common.ICAuthConfig) {
	common.Logger().Debug("Send request to resume orders in progress.")
	options := &vault_client_factory.RequestOptions{
		URL:    config.Vault.Endpoint + PluginMountPath + ResumeOrderPath,
		Method: http.MethodPost,
		Headers: map[string]string{
			vaultTokenHeader:  config.Vault.UpToken,
			acceptHeader:      applicationJson,
			contentTypeHeader: applicationJson,
		},
		Body:               []byte("{}"),
		ResponseScheme:     nil,
		ExpectedStatusCode: http.StatusNoContent,
	}
	vaultClient := &vault_cliient_impl.VaultClientFactory{Logger: common.Logger()}
	_, _, err := vaultClient.SendRequest(options)
	if err != nil {
		common.Logger().Error("Failed to send request for certificates auto-rotation cleanup", err)
	}
	common.Logger().Info("All orders in progress were handled")
}
