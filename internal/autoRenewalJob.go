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
)

type AutoRenewConfig struct {
	renewPath   string
	cleanupPath string
	usageToken  string
	client      *vault_cliient_impl.VaultClientFactory
}

func SetupPluginWithAutoRenewalJob(ctx context.Context, conf *logical.BackendConfig, backend *secret_backend.SecretBackendImpl) error {
	common.Logger().Debug("SetupPluginWithAutoRenewalJob: Trying to get Auth config")
	authConfig, err := common.ObtainAuthConfigFromStorage(ctx, conf.StorageView)
	if err != nil || authConfig == nil {
		common.Logger().Warn("SetupPluginWithAutoRenewalJob: Couldn't get auth config and configure cron job for certificates auto-renewal. Will try to configure it later")
		return nil
	}
	common.Logger().Info("SetupPluginWithAutoRenewalJob: Auth config is found. Configuring job for certificates auto-renewal.")
	return ConfigAutoRenewalJob(authConfig, backend.Cron)
}

var renewEntryId cron.EntryID = 0
var cleanupEntryId cron.EntryID = 0

func ConfigAutoRenewalJob(config *common.ICAuthConfig, c *cron.Cron) error {
	common.Logger().Debug("ConfigAutoRenewalJob: Trying to configure certificates auto-renewal and cleanup jobs")
	//r := rand.New(rand.NewSource(time.Now().UnixNano()))
	//renewalSchedule := fmt.Sprintf("%d * * * *", r.Intn(60))
	renewalSchedule := "5 */3 * * *"
	cleanupSchedule := "00 23 * * *"

	arc := &AutoRenewConfig{
		renewPath:   config.Vault.Endpoint + PluginMountPath + AutoRenewPath,
		cleanupPath: config.Vault.Endpoint + PluginMountPath + AutoRenewCleanupPath,
		usageToken:  config.Vault.UpToken,
		client:      &vault_cliient_impl.VaultClientFactory{Logger: common.Logger()},
	}
	common.Logger().Info(fmt.Sprintf("Certificates auto-renewal cron job will call to path `%s` with schedule %s", arc.renewPath, renewalSchedule))
	var err error
	if c == nil {
		common.Logger().Error(logdna.Error07059+" Failed to configure cron job for certificates auto-renewal: cron is nil ", err)
		return errors.GenerateCodedError(logdna.Error07059, http.StatusInternalServerError, errors.InternalServerError)
	}
	if renewEntryId == 0 {
		renewEntryId, err = c.AddFunc(renewalSchedule, arc.startAutoRenewProcess)
		if err != nil {
			common.Logger().Error(logdna.Error07061+" Failed to configure cron job for certificates auto-renewal: error while adding cron function ", err)
			return errors.GenerateCodedError(logdna.Error07061, http.StatusInternalServerError, errors.InternalServerError)
		}
		common.Logger().Info(fmt.Sprintf("Certificates auto-renewal cron job is configured. Entry id = %d", renewEntryId))
	} else {
		common.Logger().Info("Certificates auto-renewal cron job was already configured before and has EntryId = " + strconv.Itoa(int(renewEntryId)))
	}
	if cleanupEntryId == 0 {
		cleanupEntryId, err = c.AddFunc(cleanupSchedule, arc.startCleanupProcess)
		if err != nil {
			common.Logger().Error(logdna.Error07067+" Failed to configure cron job for certificates auto-renewal cleanup: error while adding cron function ", err)
			return errors.GenerateCodedError(logdna.Error07067, http.StatusInternalServerError, errors.InternalServerError)
		}
		common.Logger().Info(fmt.Sprintf("Certificates auto-renewal cleanup cron job is configured. Entry id = %d", cleanupEntryId))
	} else {
		common.Logger().Info("Certificates auto-renewal cleanup cron job was already configured before and has EntryId = " + strconv.Itoa(int(cleanupEntryId)))
	}
	return nil
}

func (c *AutoRenewConfig) startAutoRenewProcess() {
	common.Logger().Debug("Start running job for certificates auto-renewal.")
	options := &vault_client_factory.RequestOptions{
		URL:    c.renewPath,
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
		common.Logger().Error("Failed to send request for certificates auto-renewal", err)
	}
	//common.Logger().Info("Request for certificates auto-renewal is sent")
}

func (c *AutoRenewConfig) startCleanupProcess() {
	common.Logger().Debug("Start running job for certificates auto-renewal finish (send final error).")
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
		common.Logger().Error("Failed to send request for certificates auto-renewal cleanup", err)
	}
	//common.Logger().Info("Request for certificates auto-renewal cleanup is sent")
}
