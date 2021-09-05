package main

import (
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/plugin"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client"
	"github.ibm.com/security-services/secrets-manager-common-utils/rest_client_impl"
	"github.ibm.com/security-services/secrets-manager-vault-plugin-public-cert-secret/cmd/version"
	"github.ibm.com/security-services/secrets-manager-vault-plugin-public-cert-secret/internal"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
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
		ConcreteSecretBackend: &ordersBackend,
		PluginName:            "Public Certificates",
		PluginMountPath:       publiccerts.PluginMountPath,
		PluginBuildId:         version.BuildId,
		PluginCommitId:        version.GitCommit,
		BackendHelp:           "",
		PathInvalidHelp:       "",
		ResponseCodeForAction: map[string]int{
			secret_backend.ActionCreation:     http.StatusAccepted,
			secret_backend.ActionRotation:     http.StatusAccepted,
			secret_backend.ActionUpdatePolicy: http.StatusAccepted,
		},
		PluginSetup: publiccerts.SetupPluginWithAutoRenewalJob,
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
