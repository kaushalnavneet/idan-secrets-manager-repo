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
)

type AutoRenewConfig struct {
	renewPath     string
	vaultEndpoint string
	usageToken    string
	client        *vault_cliient_impl.VaultClientFactory
}

func SetupPlugin(ctx context.Context, conf *logical.BackendConfig, backend *secret_backend.SecretBackendImpl) error {
	authConfig, err := common.ObtainAuthConfigFromStorage(ctx, conf.StorageView)
	if err != nil || authConfig == nil {
		common.Logger().Warn("SetupPlugin: Couldn't get auth config abd configure cron job for auto renew. Will try to configure it later")
		return nil
	}
	common.Logger().Info("SetupPlugin: Auth config is found. Configuring job for auto renew.")
	return ConfigAutoRenewJob(authConfig, backend.Cron, backend.PluginMountPath)
}

var entryId cron.EntryID = 0

func ConfigAutoRenewJob(config *common.ICAuthConfig, c *cron.Cron, pluginMountPath string) error {
	//r := rand.New(rand.NewSource(time.Now().UnixNano()))
	//renewalSchedule := fmt.Sprintf("%d */3 * * *", r.Intn(60))
	renewalSchedule := "*/2 * * * *"

	arc := &AutoRenewConfig{
		renewPath:     pluginMountPath + AutoRenewPath,
		usageToken:    config.Vault.UpToken,
		vaultEndpoint: config.Vault.Endpoint,
		client:        &vault_cliient_impl.VaultClientFactory{Logger: common.Logger()},
	}
	common.Logger().Debug(fmt.Sprintf("Cron job will call to path `%s` with schedule %s", arc.renewPath, renewalSchedule))
	var err error
	if c != nil && entryId == 0 {
		entryId, err = c.AddFunc(renewalSchedule, arc.startAutoRenewProcess)
		if err != nil {
			common.Logger().Error("Failed to configure cron job for certificates auto renewal ", err)
			return errors.GenerateCodedError(logdna.Error07059, http.StatusInternalServerError, errors.InternalServerError)
		}
		common.Logger().Info(fmt.Sprintf("Cron job is configured. Entry id = %d", entryId))
	}
	return nil
}

func (c *AutoRenewConfig) startAutoRenewProcess() {
	url := fmt.Sprintf("%s%s", c.vaultEndpoint, c.renewPath)
	common.Logger().Debug("Start running job for certificates auto renewal.")
	options := &vault_client_factory.RequestOptions{
		URL:    url,
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
		common.Logger().Error("Failed to send request for certificates auto renewal", err)
	}
	common.Logger().Info("Request for certificates auto renewal is sent")
}
