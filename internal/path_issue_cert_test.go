package publiccerts

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	smErrors "github.ibm.com/security-services/secrets-manager-vault-plugins-common/errors"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry/policies"
	"gotest.tools/v3/assert"
	"net/http"
	"reflect"
	"testing"
)

const (
	certName1  = "certName1"
	certName2  = "certName2"
	dnsConfig  = "dnsConfig"
	caConfig   = "caConfig"
	commonName = "domain.com"

	certDesc = "Description"
	groupId  = "40d085c5-1abd-4086-9b09-3b641b600df5"
	keyType  = "ECDSA256"
)

var (
	labels   = []string{"first", "second"}
	altNames = []string{"test1.domain.com", "test2.domain.com"}
	policy   = map[string]interface{}{policies.FieldAutoRotate: true, policies.FieldRotateKeys: true}
)

func Test_Issue_cert(t *testing.T) {

	t.Run("Happy flow with required fields, check defaults", func(t *testing.T) {
		initBackend()

		data := map[string]interface{}{
			secretentry.FieldName:       certName1,
			secretentry.FieldCommonName: commonName,
			FieldCAConfig:               caConfig,
			FieldDNSConfig:              dnsConfig,
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
		assert.Equal(t, resp.Data[secretentry.FieldSecretType], secretentry.SecretTypePublicCert)
		assert.Equal(t, resp.Data[secretentry.FieldName], certName1)
		assert.Equal(t, resp.Data[secretentry.FieldKeyAlgorithm], "RSA2048")
		assert.Equal(t, resp.Data[secretentry.FieldCommonName], commonName)
		assert.Equal(t, len(resp.Data[secretentry.FieldAltNames].([]string)), 0)
		assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(secretentry.StatePreActivation))
		assert.Equal(t, resp.Data[secretentry.FieldCreatedBy], "iam-ServiceId-MOCK")
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRotated], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldBundleCert], true)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldCAConfig], caConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldDNSConfig], dnsConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(secretentry.StatePreActivation))

		assert.Equal(t, len(resp.Data[secretentry.FieldVersions].([]map[string]interface{})), 0)
		assert.Equal(t, resp.Data[secretentry.FieldVersionsTotal], 1)

		assert.Equal(t, resp.Data[policies.PolicyTypeRotation].(map[string]interface{})[policies.FieldAutoRotate], false)
		assert.Equal(t, resp.Data[policies.PolicyTypeRotation].(map[string]interface{})[policies.FieldRotateKeys], false)
	})

	t.Run("Happy flow with all fields", func(t *testing.T) {
		initBackend()
		data := map[string]interface{}{
			secretentry.FieldName:         certName2,
			secretentry.FieldDescription:  certDesc,
			secretentry.FieldLabels:       labels,
			secretentry.FieldGroupId:      groupId,
			secretentry.FieldCommonName:   commonName,
			secretentry.FieldAltNames:     altNames,
			secretentry.FieldKeyAlgorithm: keyType,
			FieldCAConfig:                 caConfig,
			FieldDNSConfig:                dnsConfig,
			FieldBundleCert:               false,
			FieldRotation:                 policy,
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
		assert.Equal(t, resp.Data[secretentry.FieldSecretType], secretentry.SecretTypePublicCert)
		assert.Equal(t, resp.Data[secretentry.FieldName], certName2)
		assert.Equal(t, resp.Data[secretentry.FieldDescription], certDesc)
		assert.Equal(t, resp.Data[secretentry.FieldGroupId], groupId)
		assert.Equal(t, true, reflect.DeepEqual(resp.Data[secretentry.FieldLabels].([]string), labels))

		assert.Equal(t, len(resp.Data[secretentry.FieldVersions].([]map[string]interface{})), 0)
		assert.Equal(t, resp.Data[secretentry.FieldVersionsTotal], 1)

		assert.Equal(t, resp.Data[secretentry.FieldKeyAlgorithm], keyType)
		assert.Equal(t, resp.Data[secretentry.FieldCommonName], commonName)
		assert.Equal(t, true, reflect.DeepEqual(resp.Data[secretentry.FieldAltNames].([]string), altNames))
		assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(secretentry.StatePreActivation))
		assert.Equal(t, resp.Data[secretentry.FieldCreatedBy], "iam-ServiceId-MOCK")
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRotated], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldBundleCert], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldCAConfig], caConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldDNSConfig], dnsConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(secretentry.StatePreActivation))

		assert.Equal(t, resp.Data[policies.PolicyTypeRotation].(map[string]interface{})[policies.FieldAutoRotate], true)
		assert.Equal(t, resp.Data[policies.PolicyTypeRotation].(map[string]interface{})[policies.FieldRotateKeys], true)
	})

	t.Run("Invalid domain", func(t *testing.T) {
		initBackend()
		data := map[string]interface{}{
			secretentry.FieldName:       certName1,
			secretentry.FieldCommonName: "wrong+",
			FieldCAConfig:               caConfig,
			FieldDNSConfig:              dnsConfig,
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
		expectedMessage := fmt.Sprintf(invalidDomain, "wrong+")
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07107)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(http.StatusBadRequest, expectedMessage)))
	})

	t.Run("Invalid key algorithm", func(t *testing.T) {
		initBackend()
		data := map[string]interface{}{
			secretentry.FieldName:         certName1,
			secretentry.FieldKeyAlgorithm: "wrong",
			secretentry.FieldCommonName:   commonName,
			FieldCAConfig:                 caConfig,
			FieldDNSConfig:                dnsConfig,
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
		expectedMessage := invalidKeyAlgorithm
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07040)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(http.StatusBadRequest, expectedMessage)))
	})
}

func initBackend() {
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
}
