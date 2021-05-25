package local

import (
	"github.ibm.com/project-fortress/vault-client-golang/vault"
	"os"
)

var (
	vaultUrl  = "https://vserv-us.sos.ibm.com:8200"
	vaultPath = "v1/generic/crn/v1/dev/public/secret-manager/us-south/default/YS1/-/-/-"

	vault_role_id   = ""
	vault_secret_id = ""

	// Defaults
	vault_debug             = "false"
	is_deployment           = "false"
	secret_namespace        = "default"
	update_needed           = "false"
	seconds_between_updates = "7200"
)

func init() {

	os.Setenv("vault_url", vaultUrl)
	os.Setenv("vault_path", vaultPath)
	os.Setenv("vault_role_id", vault_role_id)
	os.Setenv("vault_secret_id", vault_secret_id)
	os.Setenv("vault_debug", vault_debug)
	os.Setenv("is_deployment", is_deployment)
	os.Setenv("secret_namespace", secret_namespace)
	os.Setenv("update_needed", update_needed)
	os.Setenv("seconds_between_updates", seconds_between_updates)

	vault.ObtainSecrets()
}
