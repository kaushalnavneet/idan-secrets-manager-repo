package main

import (
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/plugin"
	"github.ibm.com/security-services/secrets-manager-vault-plugin-public-cert-secret/internal"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"net/http"
	"os"
)

func main() {

	ordersBackend := publiccerts.OrdersBackend{}

	fac := secret_backend.SecretBackendFactoryImpl{
		ConcreteSecretBackend: &ordersBackend,
		PluginName:            "Public Certificates",
		PluginMountPath:       publiccerts.PluginMountPath,
		BackendHelp:           "",
		PathInvalidHelp:       "",
		ResponseCodeForAction: map[string]int{
			secret_backend.ActionCreation: http.StatusAccepted,
			secret_backend.ActionRotation: http.StatusAccepted,
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
