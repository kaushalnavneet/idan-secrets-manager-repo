package publiccerts

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	smErrors "github.ibm.com/security-services/secrets-manager-vault-plugins-common/errors"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	mock "github.ibm.com/security-services/secrets-manager-vault-plugins-common/testing"
	"gotest.tools/v3/assert"
	"net/http"
	"reflect"
	"testing"
)

const (
	configName           = "configName"
	validPrivateKey      = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4wf+/srUmsj0hSgx\ny0mtPjnFaNrOQHfgL2wvJ+jAuvGhRANCAARK33ZxVYYpFGi5y15tYJMtfHZGxVgy\ndthwHUvcbImrfts+9XrywwOmnY8jc1YMHfgT8AGCguGhUlOKcsC7fTRr\n-----END PRIVATE KEY-----\n"
	smInstanceCrn        = "crn:v1:staging:public:secrets-manager:us-south:a/791f5fb10986423e97aa8512f18b7e65:64be543a-3901-4f54-9d60-854382b21f29::"
	responseBodyTemplate = "{\"request_id\":\"\",\"lease_id\":\"\",\"renewable\":false,\"lease_duration\":0,\"data\":%s,\"wrap_info\":null,\"warnings\":null,\"auth\":null}"
)

func Test_Config_Path_CreateConfig(t *testing.T) {
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{
		//mock cis config validation
		RestClient: &RestClientFactoryMock{
			Results: map[RequestKey]RequestResult{
				RequestKey{Method: http.MethodGet, Path: urlCISProd}: {StatusCode: http.StatusOK, JsonBody: `{}`},
			},
		}})

	t.Run("Happy flow for DNS config", func(t *testing.T) {
		config := map[string]interface{}{dnsConfigCisCrn: cisCrn}
		data := map[string]interface{}{
			FieldName:   configName,
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
		expectedConfig, _ := json.Marshal(data)
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
		assert.Equal(t, resp.Data[logical.HTTPContentType], applicationJson)
		assert.Equal(t, resp.Data[logical.HTTPStatusCode], 201)
		expectedBody := fmt.Sprintf(responseBodyTemplate, expectedConfig)
		assert.Equal(t, resp.Data[logical.HTTPRawBody].(string), expectedBody)
	})

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
			FieldName:   configName,
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
			FieldName: configName,
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
			FieldName:   configName,
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
			FieldName:   configName,
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
			FieldName: configName,
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
			FieldName:   configName,
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

func Test_Config_Path_ListConfigs(t *testing.T) {
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{})
	existingConfigs := RootConfig{
		CaConfigs: []*ProviderConfig{
			{
				Name:   configName + "1",
				Type:   caConfigTypeLEStage,
				Config: map[string]string{caConfigPrivateKey: "don't show first"},
			},
			{
				Name:   configName + "2",
				Type:   caConfigTypeLEProd,
				Config: map[string]string{caConfigPrivateKey: "don't show second"},
			}},
		DnsConfigs: []*ProviderConfig{
			{
				Name:   configName + "3",
				Type:   dnsConfigTypeCIS,
				Config: map[string]string{dnsConfigCisCrn: cisCrn, smCrn: smInstanceCrn, dnsConfigCisApikey: "don't show key"},
			},
			{
				Name:   configName + "4",
				Type:   dnsConfigTypeSoftLayer,
				Config: map[string]string{dnsConfigSLUser: "user", dnsConfigSLPassword: "don't show password"},
			}},
	}
	existingConfigs.save(context.Background(), storage)
	expectedCAList := make([]map[string]interface{}, len(existingConfigs.DnsConfigs))
	for i, config := range existingConfigs.CaConfigs {
		expectedCAList[i] = config.getProviderConfigMetadata()
	}
	expectedDNSList := make([]map[string]interface{}, len(existingConfigs.DnsConfigs))
	for i, config := range existingConfigs.DnsConfigs {
		expectedDNSList[i] = config.getProviderConfigMetadata()
	}

	t.Run("Happy flow for CA configs", func(t *testing.T) {
		expectedCAListJson, _ := json.Marshal(expectedCAList)
		data := map[string]interface{}{}
		req := &logical.Request{
			Operation: logical.ReadOperation,
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
		assert.Equal(t, resp.Data[logical.HTTPStatusCode], 200)
		expectedBody := fmt.Sprintf(
			"{\"request_id\":\"\",\"lease_id\":\"\",\"renewable\":false,\"lease_duration\":0,\"data\":{\"certificate_authorities\":%s},\"wrap_info\":null,\"warnings\":null,\"auth\":null}",
			expectedCAListJson)
		assert.Equal(t, resp.Data[logical.HTTPRawBody].(string), expectedBody)
	})

	t.Run("Happy flow for DNS configs", func(t *testing.T) {

		expectedDNSListJson, _ := json.Marshal(expectedDNSList)
		data := map[string]interface{}{}
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      ConfigDNSPath,
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
		expectedBody := fmt.Sprintf(
			"{\"request_id\":\"\",\"lease_id\":\"\",\"renewable\":false,\"lease_duration\":0,\"data\":{\"dns_providers\":%s},\"wrap_info\":null,\"warnings\":null,\"auth\":null}",
			expectedDNSListJson)
		assert.Equal(t, resp.Data[logical.HTTPRawBody].(string), expectedBody)
	})

	t.Run("Happy flow for root configs", func(t *testing.T) {
		expectedRoot := make(map[string]interface{})
		expectedRoot[CA] = expectedCAList
		expectedRoot[DNS] = expectedDNSList

		expectedRootJson, _ := json.Marshal(expectedRoot)
		data := map[string]interface{}{}
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      ConfigRootPath,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
		assert.Equal(t, resp.Data[logical.HTTPStatusCode], 200)
		expectedBody := fmt.Sprintf(responseBodyTemplate, expectedRootJson)
		assert.Equal(t, resp.Data[logical.HTTPRawBody].(string), expectedBody)
	})

}

func Test_Config_Path_UpdateConfig(t *testing.T) {
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{})
	const keyBeforeUpdate = "previous key"
	existingConfigs := RootConfig{
		CaConfigs: []*ProviderConfig{{
			Name:   configName,
			Type:   caConfigTypeLEStage,
			Config: map[string]string{caConfigPrivateKey: keyBeforeUpdate},
		}},
		DnsConfigs: []*ProviderConfig{},
	}
	existingConfigs.save(context.Background(), storage)

	t.Run("Invalid name", func(t *testing.T) {
		config := map[string]interface{}{caConfigPrivateKey: validPrivateKey}
		data := map[string]interface{}{
			FieldName:   "a",
			FieldType:   caConfigTypeLEStage,
			FieldConfig: config,
		}
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ConfigCAPath + "/" + "a",
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
		checkConfigInStorage(t, keyBeforeUpdate)
	})

	t.Run("Unknown field in data", func(t *testing.T) {
		data := map[string]interface{}{
			FieldName:   configName,
			"SomeField": "something",
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
		expectedMessage := fmt.Sprintf(smErrors.UnknownFields, []string{"SomeField"})
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error05111)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(422, expectedMessage)))
		checkConfigInStorage(t, keyBeforeUpdate)
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
			Path:      ConfigCAPath + "/" + configName,
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
		checkConfigInStorage(t, keyBeforeUpdate)
	})

	t.Run("Config to update doesn't exist", func(t *testing.T) {
		config := map[string]interface{}{caConfigPrivateKey: validPrivateKey}
		wrongConfigName := "wrongName"
		data := map[string]interface{}{
			FieldName:   wrongConfigName,
			FieldType:   caConfigTypeLEStage,
			FieldConfig: config,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      ConfigCAPath + "/" + wrongConfigName,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(configNotFound, providerTypeCA, wrongConfigName)
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07006)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(404, expectedMessage)))
		checkConfigInStorage(t, keyBeforeUpdate)
	})

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
		checkConfigInStorage(t, validPrivateKey)
	})
}

func Test_Config_Path_DeleteConfig(t *testing.T) {
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{})
	const keyBeforeUpdate = "previous key"
	existingConfigs := RootConfig{
		CaConfigs: []*ProviderConfig{{
			Name:   configName,
			Type:   caConfigTypeLEStage,
			Config: map[string]string{caConfigPrivateKey: keyBeforeUpdate},
		}},
		DnsConfigs: []*ProviderConfig{},
	}
	existingConfigs.save(context.Background(), storage)

	t.Run("Invalid name", func(t *testing.T) {
		data := map[string]interface{}{}
		req := &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      ConfigCAPath + "/" + "a",
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
		checkConfigInStorage(t, keyBeforeUpdate)
	})

	t.Run("Config to delete doesn't exist", func(t *testing.T) {
		wrongConfigName := "wrongName"
		data := map[string]interface{}{}

		req := &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      ConfigCAPath + "/" + wrongConfigName,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(configNotFound, providerTypeCA, wrongConfigName)
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07009)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(404, expectedMessage)))
		checkConfigInStorage(t, keyBeforeUpdate)
	})

	t.Run("Happy flow for CA config", func(t *testing.T) {
		data := map[string]interface{}{}

		req := &logical.Request{
			Operation: logical.DeleteOperation,
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
		assert.Equal(t, resp.Data[logical.HTTPStatusCode], 204)
		checkConfigInStorage(t, "")
	})
}

func Test_Config_Path_ReadConfig(t *testing.T) {
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{})
	existingConfigs := RootConfig{
		CaConfigs: []*ProviderConfig{{
			Name: configName,
			Type: caConfigTypeLEStage,
			Config: map[string]string{
				caConfigPrivateKey: "saved key",
				//this data was added by the code. it should not be shown to a user
				caConfigEmail:        "someEmail",
				caConfigDirectoryUrl: UrlLetsEncryptProd,
				caConfigRegistration: "some registration"},
		}},
		DnsConfigs: []*ProviderConfig{{
			Name: configName,
			Type: dnsConfigTypeCIS,
			Config: map[string]string{dnsConfigCisCrn: cisCrn,
				dnsConfigCisApikey: "don't show",
				//this data was added by the code. it should not be shown to a user
				dnsConfigSMCrn: "don't show"},
		}}}
	existingConfigs.save(context.Background(), storage)

	t.Run("Invalid name", func(t *testing.T) {
		data := map[string]interface{}{}
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      ConfigCAPath + "/" + "a",
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

	t.Run("Config to read doesn't exist", func(t *testing.T) {
		wrongConfigName := "wrongName"
		data := map[string]interface{}{}

		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      ConfigCAPath + "/" + wrongConfigName,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(configNotFound, providerTypeCA, wrongConfigName)
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07012)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(404, expectedMessage)))
	})

	t.Run("Happy flow for CA config", func(t *testing.T) {
		expectedConfigProps := make(map[string]string)
		expectedConfigProps[caConfigPrivateKey] = existingConfigs.CaConfigs[0].Config[caConfigPrivateKey]
		expectedCAConfig := existingConfigs.CaConfigs[0].getProviderConfigMetadata()
		expectedCAConfig[FieldConfig] = expectedConfigProps
		expectedCAConfigJson, _ := json.Marshal(expectedCAConfig)

		data := map[string]interface{}{}

		req := &logical.Request{
			Operation: logical.ReadOperation,
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
		expectedBody := fmt.Sprintf(responseBodyTemplate, expectedCAConfigJson)
		assert.Equal(t, resp.Data[logical.HTTPRawBody].(string), expectedBody)

	})

	t.Run("Happy flow for DNS config", func(t *testing.T) {
		expectedConfigProps := make(map[string]string)
		expectedConfigProps[dnsConfigCisCrn] = existingConfigs.DnsConfigs[0].Config[dnsConfigCisCrn]
		expectedConfigProps[dnsConfigCisApikey] = existingConfigs.DnsConfigs[0].Config[dnsConfigCisApikey]
		expectedDNSonfig := existingConfigs.DnsConfigs[0].getProviderConfigMetadata()
		expectedDNSonfig[FieldConfig] = expectedConfigProps
		expectedDNSConfigJson, _ := json.Marshal(expectedDNSonfig)

		data := map[string]interface{}{}

		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      ConfigDNSPath + "/" + configName,
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
		expectedBody := fmt.Sprintf(responseBodyTemplate, expectedDNSConfigJson)
		assert.Equal(t, resp.Data[logical.HTTPRawBody].(string), expectedBody)

	})
}

func Test_Config_Path_AuthorizationCheck(t *testing.T) {
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{})
	b.Auth = &mock.AuthUtilsMock{Forbidden: true}

	t.Run("Authorization error when create DNS config", func(t *testing.T) {
		config := map[string]interface{}{dnsConfigCisCrn: cisCrn}
		data := map[string]interface{}{
			FieldName:   configName,
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
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error05113)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(403, smErrors.StatusForbidden)))
	})

	t.Run("Authorization error when read CA config", func(t *testing.T) {
		data := map[string]interface{}{}

		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      ConfigCAPath + "/" + configName,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error05113)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(403, smErrors.StatusForbidden)))
	})

	t.Run("Authorization error when list CA config", func(t *testing.T) {
		data := map[string]interface{}{}

		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      ConfigCAPath,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error05113)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(403, smErrors.StatusForbidden)))
	})

	t.Run("Authorization error when read root config", func(t *testing.T) {
		data := map[string]interface{}{}

		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      ConfigRootPath,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error05113)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(403, smErrors.StatusForbidden)))
	})

	t.Run("Authorization error when delete CA config", func(t *testing.T) {
		data := map[string]interface{}{}

		req := &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      ConfigCAPath + "/" + configName,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error05113)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(403, smErrors.StatusForbidden)))
	})

}
func checkConfigInStorage(t *testing.T, expectedPrivKey string) {
	//get config from the storage
	rootConfig, _ := getRootConfig(context.Background(), storage)
	if expectedPrivKey != "" {
		assert.Equal(t, len(rootConfig.CaConfigs), 1)
		//private key should NOT be updated
		assert.Equal(t, rootConfig.CaConfigs[0].Config[caConfigPrivateKey], expectedPrivKey)
	} else {
		assert.Equal(t, len(rootConfig.CaConfigs), 0)
	}
}
