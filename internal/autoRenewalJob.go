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
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

type AutoRenewConfig struct {
	renewPath     string
	vaultEndpoint string
	usageToken    string
	client        *vault_cliient_impl.VaultClientFactory
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

var entryId cron.EntryID = 0

func ConfigAutoRenewalJob(config *common.ICAuthConfig, c *cron.Cron) error {
	common.Logger().Debug("ConfigAutoRenewalJob: Trying to configure certificates auto-renewal job")
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	renewalSchedule := fmt.Sprintf("%d * * * *", r.Intn(60))
	//renewalSchedule := "* * * * *"

	arc := &AutoRenewConfig{
		renewPath:  config.Vault.Endpoint + PluginMountPath + AutoRenewPath,
		usageToken: config.Vault.UpToken,
		client:     &vault_cliient_impl.VaultClientFactory{Logger: common.Logger()},
	}
	common.Logger().Info(fmt.Sprintf("Certificates auto-renewal cron job will call to path `%s` with schedule %s", arc.renewPath, renewalSchedule))
	var err error
	if c == nil {
		common.Logger().Error(logdna.Error07059+" Failed to configure cron job for certificates auto-renewal: cron is nil ", err)
		return errors.GenerateCodedError(logdna.Error07059, http.StatusInternalServerError, errors.InternalServerError)
	}
	if entryId == 0 {
		entryId, err = c.AddFunc(renewalSchedule, arc.startAutoRenewProcess)
		if err != nil {
			common.Logger().Error(logdna.Error07061+" Failed to configure cron job for certificates auto-renewal: error while adding cron function ", err)
			return errors.GenerateCodedError(logdna.Error07061, http.StatusInternalServerError, errors.InternalServerError)
		}
		common.Logger().Info(fmt.Sprintf("Certificates auto-renewal cron job is configured. Entry id = %d", entryId))
	} else {
		common.Logger().Info("Certificates auto-renewal cron job was already configured and has EntryId = " + strconv.Itoa(int(entryId)))
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
	common.Logger().Info("Request for certificates auto-renewal is sent")
}
