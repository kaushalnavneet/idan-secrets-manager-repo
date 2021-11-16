package main

import (
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/plugin"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client_impl"
	"github.ibm.com/security-services/secrets-manager-vault-plugin-public-cert-secret/cmd/version"
	"github.ibm.com/security-services/secrets-manager-vault-plugin-public-cert-secret/internal"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"net/http"
	"os"
	"time"
)

func main() {
	//create resty client
	rc := &rest_client_impl.RestClientFactory{}
	//init resty client with not default options
	rc.InitClientWithOptions(rest_client.RestClientOptions{
		Timeout:    10 * time.Second,
		Retries:    2,
		RetryDelay: 1 * time.Second,
	})
	ordersBackend := publiccerts.OrdersBackend{RestClient: rc}

	fac := secret_backend.SecretBackendFactoryImpl{
		ConcreteSecretBackend:         &ordersBackend,
		PluginName:                    "Public Certificates",
		PluginMountPath:               publiccerts.PluginMountPath,
		PluginSecretType:              secretentry.SecretTypePublicCert,
		MetadataMigrationSyncSchedule: common.RandomizeCronScheduleMinutes("0 11,23 * * *"),
		PluginBuildId:                 version.BuildId,
		PluginCommitId:                version.GitCommit,
		BackendHelp:                   "",
		PathInvalidHelp:               "",
		ResponseCodeForAction: map[string]int{
			secret_backend.ActionCreation:     http.StatusAccepted,
			secret_backend.ActionRotation:     http.StatusAccepted,
			secret_backend.ActionUpdatePolicy: http.StatusAccepted,
		},
		PluginSetup: publiccerts.SetupPublicCertPlugin,
	}

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: fac.BackendFactoryFunc,
		TLSProviderFunc:    fac.TLSProviderFunc(),
	}); err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})

		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}

//catch exception

//defer func() {
//	if r := recover(); r != nil {
//		// XXX it is better to check r.Error() to has "unhashable type ..."
//		err = fmt.Errorf("mapSet: %v", r)
//	}
//}()
