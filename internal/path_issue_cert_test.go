package publiccerts

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"gotest.tools/v3/assert"
	"testing"
)

const (
	certName   = "certName"
	dnsConfig  = "dnsConfig"
	caConfig   = "caConfig"
	commonName = "domain.com"
	altNames   = "test1.domain.com, test2.domain.com"
)

func Test_Create_Secret_Happy(t *testing.T) {
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{})
	existingConfigs := RootConfig{
		CaConfigs: []*ProviderConfig{{
			Name: caConfig,
			Type: caConfigTypeLEStage,
			Config: map[string]string{
				caConfigPrivateKey: validPrivateKey,
				//this data was added by the code. it should not be shown to a user
				caConfigEmail:        "someEmail",
				caConfigDirectoryUrl: UrlLetsEncryptProd,
				caConfigRegistration: "some registration"},
		}},
		DnsConfigs: []*ProviderConfig{{
			Name: dnsConfig,
			Type: dnsConfigTypeCIS,
			Config: map[string]string{dnsConfigCisCrn: cisCrn,
				dnsConfigCisApikey: "don't show",
				//this data was added by the code. it should not be shown to a user
				dnsConfigSMCrn: "don't show"},
		}}}
	existingConfigs.save(context.Background(), storage)

	data := map[string]interface{}{
		"name":        certName,
		"common_name": commonName,
		"ca":          caConfig,
		"dns":         dnsConfig,
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "secrets",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "0.0.0.0",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	assert.NilError(t, err)
	assert.Equal(t, false, resp.IsError())
	assert.Equal(t, resp.Data["name"], certName)
	assert.Equal(t, resp.Data["key_algorithm"], "RSA2048")
	assert.Equal(t, resp.Data["secret_type"], secretentry.SecretTypePublicCert)
	assert.Equal(t, resp.Data["common_name"], commonName)
	assert.Equal(t, len(resp.Data["alt_names"].([]string)), 0)
	assert.Equal(t, resp.Data["state_description"], secretentry.GetNistStateDescription(secretentry.StatePreActivation))
	assert.Equal(t, resp.Data["created_by"], "iam-ServiceId-MOCK")
	assert.Equal(t, resp.Data["issuance_info"].(map[string]interface{})["auto_rotated"], false)
	assert.Equal(t, resp.Data["issuance_info"].(map[string]interface{})["bundle_certs"], true)
	assert.Equal(t, resp.Data["issuance_info"].(map[string]interface{})["ca"], caConfig)
	assert.Equal(t, resp.Data["issuance_info"].(map[string]interface{})["dns"], dnsConfig)
	assert.Equal(t, resp.Data["issuance_info"].(map[string]interface{})["state"], float64(secretentry.StatePreActivation))
	assert.Equal(t, resp.Data["issuance_info"].(map[string]interface{})["state_description"], secretentry.GetNistStateDescription(secretentry.StatePreActivation))

	assert.Equal(t, len(resp.Data["versions"].([]map[string]interface{})), 0)
	assert.Equal(t, resp.Data["versions_total"], 1)

	assert.Equal(t, resp.Data["rotation"].(map[string]interface{})["auto_rotate"], false)
	assert.Equal(t, resp.Data["rotation"].(map[string]interface{})["rotate_keys"], false)
}
