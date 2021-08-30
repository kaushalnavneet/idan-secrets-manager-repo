package publiccerts

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	smErrors "github.ibm.com/security-services/secrets-manager-vault-plugins-common/errors"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"gotest.tools/v3/assert"
	"reflect"
	"testing"
)

const (
	real_cis_int_crn = "crn:v1:staging:public:internet-svcs-ci:global:a/791f5fb10986423e97aa8512f18b7e65:dc08a28a-9181-45db-bf0d-a8733a5796b6::"
	configName       = "configName"
	validPrivateKey  = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4wf+/srUmsj0hSgx\ny0mtPjnFaNrOQHfgL2wvJ+jAuvGhRANCAARK33ZxVYYpFGi5y15tYJMtfHZGxVgy\ndthwHUvcbImrfts+9XrywwOmnY8jc1YMHfgT8AGCguGhUlOKcsC7fTRr\n-----END PRIVATE KEY-----\n"
)

func Test_Config_Path_CreateConfig(t *testing.T) {
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{})

	t.Run("Happy flow for CA config", func(t *testing.T) {
		config := map[string]interface{}{caConfigPrivateKey: validPrivateKey}
		data := map[string]interface{}{
			FieldName:   configName,
			FieldType:   caConfigTypeLEStage,
			FieldConfig: config,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ConfigCAPath,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
		assert.Equal(t, resp.Data[logical.HTTPContentType], applicationJson)
		assert.Equal(t, resp.Data[logical.HTTPStatusCode], 201)
		//expectedBody := fmt.Sprintf(
		//	"{\"request_id\":\"\",\"lease_id\":\"\",\"renewable\":false,\"lease_duration\":0,\"data\":{\"config\":{\"private_key\":%s},\"name\":%s,\"type\":%s},\"wrap_info\":null,\"warnings\":null,\"auth\":null}",
		//	validPrivateKey, configName, caConfigTypeLEStage)
		//assert.Equal(t, resp.Data[logical.HTTPRawBody].(string), expectedBody)
	})

	t.Run("Invalid name", func(t *testing.T) {
		data := map[string]interface{}{
			FieldName: "",
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ConfigDNSPath,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := "field: 'name' failed validation: length should be 2 to 256 chars"
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07015)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(400, expectedMessage)))
	})

	t.Run("Unknown field in data", func(t *testing.T) {
		data := map[string]interface{}{
			FieldName:   "name",
			"SomeField": "something",
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ConfigDNSPath,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(smErrors.UnknownFields, []string{"SomeField"})
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error05111)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(422, expectedMessage)))
	})

	t.Run("Config name already exists", func(t *testing.T) {
		existingName := "existingName"
		existingConfigs := RootConfig{
			CaConfigs:  []*ProviderConfig{},
			DnsConfigs: []*ProviderConfig{{Name: existingName}},
		}
		existingConfigs.save(context.Background(), storage)
		config := map[string]interface{}{
			"key1": "value1",
		}
		data := map[string]interface{}{
			FieldName:   existingName,
			FieldType:   dnsConfigTypeSoftLayer,
			FieldConfig: config,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ConfigDNSPath,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(nameAlreadyExists, providerTypeDNS, existingName)
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07003)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(400, expectedMessage)))
	})

	t.Run("DNS - Invalid type", func(t *testing.T) {
		data := map[string]interface{}{
			FieldName: "name",
			FieldType: "wrong",
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ConfigDNSPath,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(smErrors.InvalidParamMustBeError, FieldType, GetDNSTypesAllowedValues())
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error05176)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(400, expectedMessage)))
	})

	t.Run("DNS - Invalid cis config - missing cis crn", func(t *testing.T) {
		config := map[string]interface{}{}
		data := map[string]interface{}{
			FieldName:   "name",
			FieldType:   dnsConfigTypeCIS,
			FieldConfig: config,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ConfigDNSPath,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(configMissingField, providerTypeDNS, dnsConfigCisCrn)
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07025)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(400, expectedMessage)))
	})

	t.Run("DNS - Invalid SL config - missing SL user", func(t *testing.T) {
		config := map[string]interface{}{}
		data := map[string]interface{}{
			FieldName:   "name",
			FieldType:   dnsConfigTypeSoftLayer,
			FieldConfig: config,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ConfigDNSPath,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(configMissingField, providerTypeDNS, dnsConfigSLUser)
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07033)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(400, expectedMessage)))
	})

	t.Run("CA - Invalid type", func(t *testing.T) {
		data := map[string]interface{}{
			FieldName: "name",
			FieldType: "wrong",
		}
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ConfigCAPath,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(smErrors.InvalidParamMustBeError, FieldType, GetCATypesAllowedValues())
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error05176)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(400, expectedMessage)))
	})

	t.Run("CA - Missing private key", func(t *testing.T) {
		config := map[string]interface{}{}
		data := map[string]interface{}{
			FieldName:   configName,
			FieldType:   caConfigTypeLEProd,
			FieldConfig: config,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ConfigCAPath,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(configMissingField, providerTypeCA, caConfigPrivateKey)
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07018)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(400, expectedMessage)))
	})

	t.Run("CA - Unexpected property in config", func(t *testing.T) {
		config := map[string]interface{}{caConfigPrivateKey: "key", "field": "data"}
		data := map[string]interface{}{
			FieldName:   configName,
			FieldType:   caConfigTypeLEProd,
			FieldConfig: config,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ConfigCAPath,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(invalidConfigStruct, providerTypeCA, caConfigTypeLEProd, "["+caConfigPrivateKey+"]")
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07019)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(400, expectedMessage)))
	})

	t.Run("CA - Invalid private key", func(t *testing.T) {
		config := map[string]interface{}{caConfigPrivateKey: "key"}
		data := map[string]interface{}{
			FieldName:   configName,
			FieldType:   caConfigTypeLEProd,
			FieldConfig: config,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ConfigCAPath,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(invalidKey, "private key is not valid PEM formatted value")
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07021)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(400, expectedMessage)))
	})

	t.Run("CA - wrong private key (staging in prod)", func(t *testing.T) {
		config := map[string]interface{}{caConfigPrivateKey: validPrivateKey}
		data := map[string]interface{}{
			FieldName:   configName,
			FieldType:   caConfigTypeLEProd,
			FieldConfig: config,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ConfigCAPath,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(wrongCAAccount, "acme: error: 400 :: POST :: https://acme-v02.api.letsencrypt.org/acme/new-acct :: urn:ietf:params:acme:error:accountDoesNotExist :: No account exists with the provided key")
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07023)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(400, expectedMessage)))
	})

	t.Run("More than 10 dns configs exists", func(t *testing.T) {
		existingConfigs := RootConfig{
			CaConfigs: []*ProviderConfig{},
			DnsConfigs: []*ProviderConfig{
				{Name: "n1"}, {Name: "n2"}, {Name: "n3"}, {Name: "n4"}, {Name: "n5"},
				{Name: "n6"}, {Name: "n7"}, {Name: "n8"}, {Name: "n9"}, {Name: "n10"}},
		}
		existingConfigs.save(context.Background(), storage)
		config := map[string]interface{}{
			"key1": "value1",
		}
		data := map[string]interface{}{
			FieldName:   "n11",
			FieldType:   dnsConfigTypeSoftLayer,
			FieldConfig: config,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ConfigDNSPath,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(reachedTheMaximum, providerTypeDNS, MaxNumberConfigs)
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07002)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(400, expectedMessage)))
	})

}

func Test_Config_Path_UpdateConfig(t *testing.T) {
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{})
	existingConfigs := RootConfig{
		CaConfigs: []*ProviderConfig{{
			Name:   configName,
			Type:   caConfigTypeLEStage,
			Config: map[string]string{caConfigPrivateKey: "previous key"},
		}},
		DnsConfigs: []*ProviderConfig{},
	}
	existingConfigs.save(context.Background(), storage)

	t.Run("Happy flow for CA config", func(t *testing.T) {
		config := map[string]interface{}{caConfigPrivateKey: validPrivateKey}
		data := map[string]interface{}{
			FieldName:   configName,
			FieldType:   caConfigTypeLEStage,
			FieldConfig: config,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ConfigCAPath + "/" + configName,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
		assert.Equal(t, resp.Data[logical.HTTPContentType], applicationJson)
		assert.Equal(t, resp.Data[logical.HTTPStatusCode], 200)
		//get config from the storage
		rootConfig, _ := getRootConfig(context.Background(), storage)
		assert.Equal(t, len(rootConfig.CaConfigs), 1)
		//private key should be updated
		assert.Equal(t, rootConfig.CaConfigs[0].Config[caConfigPrivateKey], validPrivateKey)
	})

}
