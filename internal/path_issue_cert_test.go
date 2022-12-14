package publiccerts

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-acme/lego/v4/acme"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-common-utils/secret_metadata_entry"
	"github.ibm.com/security-services/secrets-manager-common-utils/secret_metadata_entry/certificate"
	"github.ibm.com/security-services/secrets-manager-common-utils/secret_metadata_entry/policies"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/certificate_parser"
	smErrors "github.ibm.com/security-services/secrets-manager-vault-plugins-common/errors"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"gotest.tools/v3/assert"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	certName1   = "certName1"
	certName2   = "certName2"
	certName3   = "certName3"
	certName4   = "certName4"
	dnsConfig   = "dnsConfig"
	caConfig    = "caConfig"
	commonName  = "domain.com"
	commonName2 = "domain2.com"

	certDesc = "Description"
	groupId  = "40d085c5-1abd-4086-9b09-3b641b600df5"
	keyType  = "RSA2048"
)

var (
	labels   = []string{"first", "second"}
	altNames = []string{"test1.domain.com", "test2.domain.com"}
	policy   = map[string]interface{}{policies.FieldAutoRotate: true, policies.FieldRotateKeys: true}
	iD       = uuid.New()
	secretID = iD.String()
)

func initOrdersHandler() *OrdersHandler {
	mb := MockSecretBackend{name: "public_cert mock"}
	oh = &OrdersHandler{
		parser:         &certificate_parser.CertificateParserImpl{},
		metadataMapper: secret_backend.GetDefaultMetadataMapper(secretentry.SecretTypePublicCert),
		secretBackend:  &mb,
		inAllowList:    true,
	}
	oh.workerPool = NewWorkerPool(oh, 1, 2, 1*time.Second)
	oh.autoRenewWorkerPool = NewWorkerPool(oh, 1, 2, 1*time.Second)
	return oh
}

func Test_Issue_cert(t *testing.T) {
	oh := initOrdersHandler()
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{ordersHandler: oh})
	initBackend(false)

	t.Run("Happy flow with required fields, check defaults", func(t *testing.T) {
		resetOrdersInProgress()
		data := map[string]interface{}{
			secretentry.FieldName:       certName1,
			secretentry.FieldCommonName: commonName,
			FieldCAConfig:               caConfig,
			FieldDNSConfig:              dnsConfig,
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      PathSecrets,
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
		assert.Equal(t, resp.Data[secretentry.FieldKeyAlgorithm], keyType)
		assert.Equal(t, resp.Data[secretentry.FieldCommonName], commonName)
		assert.Equal(t, len(resp.Data[secretentry.FieldAltNames].([]string)), 0)
		assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secret_metadata_entry.GetNistStateDescription(secretentry.StatePreActivation))
		assert.Equal(t, resp.Data[secretentry.FieldCreatedBy], "iam-ServiceId-MOCK")
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRotated], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldBundleCert], true)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldCAConfig], caConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldDNSConfig], dnsConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], secret_metadata_entry.GetNistStateDescription(secretentry.StatePreActivation))

		assert.Equal(t, len(resp.Data[secretentry.FieldVersions].([]map[string]interface{})), 0)
		assert.Equal(t, resp.Data[secretentry.FieldVersionsTotal], 1)

		assert.Equal(t, resp.Data[policies.PolicyTypeRotation].(map[string]interface{})[policies.FieldAutoRotate], false)
		assert.Equal(t, resp.Data[policies.PolicyTypeRotation].(map[string]interface{})[policies.FieldRotateKeys], false)

		checkOrdersInProgress(t, []OrderDetails{{GroupId: defaultGroup, Id: resp.Data[secretentry.FieldId].(string), Attempts: 1, TriggeredBy: "iam-ServiceId-MOCK"}})
		assert.Equal(t, countOrdersMap(&oh.runningOrders), 1)
	})

	t.Run("Happy flow with all fields", func(t *testing.T) {
		resetOrdersInProgress()
		data := map[string]interface{}{
			secretentry.FieldName:         certName2,
			secretentry.FieldDescription:  certDesc,
			secretentry.FieldLabels:       labels,
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
			Path:      PathSecrets + "groups/" + groupId,
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
		assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secret_metadata_entry.GetNistStateDescription(secretentry.StatePreActivation))
		assert.Equal(t, resp.Data[secretentry.FieldCreatedBy], "iam-ServiceId-MOCK")
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRotated], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldBundleCert], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldCAConfig], caConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldDNSConfig], dnsConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], secret_metadata_entry.GetNistStateDescription(secretentry.StatePreActivation))

		assert.Equal(t, resp.Data[policies.PolicyTypeRotation].(map[string]interface{})[policies.FieldAutoRotate], true)
		assert.Equal(t, resp.Data[policies.PolicyTypeRotation].(map[string]interface{})[policies.FieldRotateKeys], true)

		checkOrdersInProgress(t, []OrderDetails{{GroupId: groupId, Id: resp.Data[secretentry.FieldId].(string), Attempts: 1, TriggeredBy: "iam-ServiceId-MOCK"}})
		assert.Equal(t, countOrdersMap(&oh.runningOrders), 1)
	})

	t.Run("Happy flow + rotation when it's still pre-activate", func(t *testing.T) {
		resetOrdersInProgress()
		data := map[string]interface{}{
			secretentry.FieldName:       certName3,
			secretentry.FieldCommonName: commonName2,
			FieldCAConfig:               caConfig,
			FieldDNSConfig:              dnsConfig,
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      PathSecrets,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
		assert.Equal(t, countOrdersMap(&oh.runningOrders), 1)

		//rotate created secret
		createdSecretId := resp.Data[secretentry.FieldId].(string)
		data = map[string]interface{}{
			policies.FieldRotateKeys: false,
		}
		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      PathSecrets + createdSecretId + "/rotate",
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err = b.HandleRequest(context.Background(), req)
		expectedMessage := secretShouldBeInActiveState
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07062)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(http.StatusBadRequest, expectedMessage)))

		checkOrdersInProgress(t, []OrderDetails{{GroupId: defaultGroup, Id: createdSecretId, Attempts: 1, TriggeredBy: "iam-ServiceId-MOCK"}})
	})

	t.Run("Invalid domain", func(t *testing.T) {
		resetOrdersInProgress()
		data := map[string]interface{}{
			secretentry.FieldName:       certName1,
			secretentry.FieldCommonName: "wrong+",
			FieldCAConfig:               caConfig,
			FieldDNSConfig:              dnsConfig,
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      PathSecrets,
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

		checkOrdersInProgress(t, []OrderDetails{})
		assert.Equal(t, countOrdersMap(&oh.runningOrders), 0)
	})

	t.Run("Invalid key algorithm", func(t *testing.T) {
		resetOrdersInProgress()
		data := map[string]interface{}{
			secretentry.FieldName:         certName1,
			secretentry.FieldKeyAlgorithm: "wrong",
			secretentry.FieldCommonName:   commonName,
			FieldCAConfig:                 caConfig,
			FieldDNSConfig:                dnsConfig,
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      PathSecrets,
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

		checkOrdersInProgress(t, []OrderDetails{})
		assert.Equal(t, countOrdersMap(&oh.runningOrders), 0)
	})

	t.Run("Not existing CA config", func(t *testing.T) {
		resetOrdersInProgress()
		data := map[string]interface{}{
			secretentry.FieldName:         certName1,
			secretentry.FieldKeyAlgorithm: keyType,
			secretentry.FieldCommonName:   commonName,
			FieldCAConfig:                 "not exist",
			FieldDNSConfig:                dnsConfig,
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      PathSecrets,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(configNotFound, providerTypeCA, "not exist")
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07012)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(http.StatusBadRequest, expectedMessage)))

		checkOrdersInProgress(t, []OrderDetails{})
		assert.Equal(t, countOrdersMap(&oh.runningOrders), 0)
	})

	t.Run("Not existing DNS config", func(t *testing.T) {
		resetOrdersInProgress()
		data := map[string]interface{}{
			secretentry.FieldName:         certName1,
			secretentry.FieldKeyAlgorithm: keyType,
			secretentry.FieldCommonName:   commonName,
			FieldCAConfig:                 caConfig,
			FieldDNSConfig:                "not exist",
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      PathSecrets,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := fmt.Sprintf(configNotFound, providerTypeDNS, "not exist")
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07012)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(http.StatusBadRequest, expectedMessage)))

		checkOrdersInProgress(t, []OrderDetails{})
		assert.Equal(t, countOrdersMap(&oh.runningOrders), 0)
	})
}

func countOrdersMap(m *sync.Map) int {
	total := 0
	m.Range(func(key, value interface{}) bool {
		total = total + 1
		return true
	})

	return total
}
func Test_rotation(t *testing.T) {
	oh := initOrdersHandler()
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{ordersHandler: oh})
	oh.metadataClient = b.GetMetadataClient()

	t.Run("Happy flow", func(t *testing.T) {
		initBackend(false)
		//the order was already in progress, it's the second attempt
		setOrdersInProgress(expiresIn20Days_autoRotateTrue_id, 1)
		common.StoreSecretWithoutLocking(expiresIn20Days_autoRotateTrue, storage, context.Background(), oh.metadataClient, false, secret_backend.ServiceName)
		data := map[string]interface{}{
			policies.FieldRotateKeys: true,
		}
		//get secret
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      PathSecrets + expiresIn20Days_autoRotateTrue_id + PathRotate,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		//common fields
		assert.Equal(t, false, resp.IsError())
		// it's the second attempt
		checkOrdersInProgress(t, []OrderDetails{{GroupId: defaultGroup, Id: expiresIn20Days_autoRotateTrue_id, Attempts: 2, TriggeredBy: createdBy}})
		assert.Equal(t, countOrdersMap(&oh.runningOrders), 1)
	})

	t.Run("Happy flow for manual dns provider", func(t *testing.T) {
		initBackend(true)
		resetOrdersInProgress()
		//the order was already in progress, it's the second attempt
		setOrdersInProgress("", 0)
		common.StoreSecretWithoutLocking(expiresIn20Days_autoRotateTrue, storage, context.Background(), oh.metadataClient, false, "IBMid-1110000RRH1")
		data := map[string]interface{}{
			policies.FieldRotateKeys: true,
		}
		//get secret
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      PathSecrets + expiresIn20Days_autoRotateTrue_id + PathRotate,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		//common fields
		assert.Equal(t, false, resp.IsError())
		// it's the second attempt
		checkOrdersInProgress(t, []OrderDetails{{GroupId: defaultGroup, Id: expiresIn20Days_autoRotateTrue_id, Attempts: 1, TriggeredBy: "iam-ServiceId-MOCK"}})
		assert.Equal(t, countOrdersMap(&oh.runningOrders), 1)
	})
}

func Test_Issue_cert_Manual(t *testing.T) {
	oh := initOrdersHandler()
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{ordersHandler: oh})
	initBackend(true)
	oh.metadataClient = b.GetMetadataClient()

	t.Run("Happy flow with manual dns", func(t *testing.T) {
		startMockLEAcmeServer()
		defer stopMockLEAcmeServer()
		resetOrdersInProgress()
		data := map[string]interface{}{
			secretentry.FieldName:       certName4,
			secretentry.FieldCommonName: commonName,
			FieldCAConfig:               caConfig,
			FieldDNSConfig:              dnsConfigTypeManual,
		}
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      PathSecrets,
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
		assert.Equal(t, resp.Data[secretentry.FieldName], certName4)
		assert.Equal(t, resp.Data[secretentry.FieldKeyAlgorithm], keyType)
		assert.Equal(t, resp.Data[secretentry.FieldCommonName], commonName)
		assert.Equal(t, len(resp.Data[secretentry.FieldAltNames].([]string)), 0)
		assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secret_metadata_entry.GetNistStateDescription(secretentry.StatePreActivation))
		assert.Equal(t, resp.Data[secretentry.FieldCreatedBy], "iam-ServiceId-MOCK")
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRotated], false)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldBundleCert], true)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldCAConfig], caConfig)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldDNSConfig], dnsConfigTypeManual)
		assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], secret_metadata_entry.GetNistStateDescription(secretentry.StatePreActivation))

		assert.Equal(t, len(resp.Data[secretentry.FieldVersions].([]map[string]interface{})), 0)
		assert.Equal(t, resp.Data[secretentry.FieldVersionsTotal], 1)

		assert.Equal(t, resp.Data[policies.PolicyTypeRotation].(map[string]interface{})[policies.FieldAutoRotate], false)
		assert.Equal(t, resp.Data[policies.PolicyTypeRotation].(map[string]interface{})[policies.FieldRotateKeys], false)

		assert.Equal(t, countOrdersMap(&oh.runningOrders), 0)
	})
	secretEntry := &secretentry.SecretEntry{
		SecretMetadataEntry: secret_metadata_entry.SecretMetadataEntry{
			ID:             secretID,
			Name:           "manualOrder",
			Description:    certDesc,
			Labels:         []string{},
			CreatedAt:      today.Add(-10 * 24 * time.Hour),
			CreatedBy:      createdBy,
			ExpirationDate: &expirationIn20Days,
			TTL:            0,
			Policies: policies.Policies{
				Rotation: &policies.RotationPolicy{
					Rotation: &policies.RotationData{
						RotateKeys: false,
						AutoRotate: true,
					},
					Type: policies.MIMETypeForPolicyResource}},
			Type:    secretentry.SecretTypePublicCert,
			CRN:     strings.Replace(smInstanceCrn, "::", ":secret:", 1) + secretID,
			GroupID: defaultGroup,
			State:   secretentry.StatePreActivation,
		},
		Versions: versions,
	}

	t.Run("Validate dns challenge - happy flow", func(t *testing.T) {
		goodCertMetadata := certificate.CertificateMetadata{
			KeyAlgorithm: keyType,
			CommonName:   certCommonName,
			IssuanceInfo: map[string]interface{}{
				secretentry.FieldState:            secretentry.StatePreActivation,
				secretentry.FieldStateDescription: secret_metadata_entry.GetNistStateDescription(secretentry.StatePreActivation),
				FieldBundleCert:                   true, FieldCAConfig: caConfig, FieldAutoRotated: true,
				FieldOrderedOn: time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339),
				FieldDNSConfig: dnsConfigTypeManual,
				FieldChallenges: []Challenge{{
					Domain:         "certCommonName",
					TXTRecordName:  "certCommonName.acme_challenge",
					TXTRecordValue: "txtRecordValue",
					Status:         "Pending",
					Expiration:     time.Time{},
				}},
			}}
		secretEntry.ExtraData = goodCertMetadata
		common.StoreSecretWithoutLocking(secretEntry, storage, context.Background(), oh.metadataClient, false, "IBMid-1110000RRH1")

		data := map[string]interface{}{}
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      PathSecrets + secretID + PathValidate,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())

		getMetadataResp := getSecretAndCheckItsContent(t, secretID, secretEntry, goodCertMetadata.IssuanceInfo)

		validationTime := getMetadataResp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldValidationTime]
		assert.Equal(t, validationTime != nil, true)
		assert.Equal(t, countOrdersMap(&oh.runningOrders), 1)
	})

	t.Run("Validate dns challenge - bad extra data in secrets entry", func(t *testing.T) {
		secretEntry.ExtraData = "string"
		common.StoreSecretWithoutLocking(secretEntry, storage, context.Background(), oh.metadataClient, false, "IBMid-1110000RRH1")

		data := map[string]interface{}{}
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      PathSecrets + secretID + PathValidate,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := internalServerError
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07204)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(http.StatusInternalServerError, expectedMessage)))

	})

	t.Run("Validate dns challenge - order is in Active state", func(t *testing.T) {
		activeCertMetadata := certificate.CertificateMetadata{
			KeyAlgorithm: keyType,
			CommonName:   certCommonName,
			IssuanceInfo: map[string]interface{}{
				secretentry.FieldState:            secretentry.StateActive,
				secretentry.FieldStateDescription: secret_metadata_entry.GetNistStateDescription(secretentry.StateActive),
				FieldBundleCert:                   true, FieldCAConfig: caConfig, FieldAutoRotated: true,
				FieldOrderedOn: time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339),
				FieldDNSConfig: dnsConfigTypeManual,
			}}
		secretEntry.ExtraData = activeCertMetadata
		common.StoreSecretWithoutLocking(secretEntry, storage, context.Background(), oh.metadataClient, false, "IBMid-1110000RRH1")

		data := map[string]interface{}{}
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      PathSecrets + secretID + PathValidate,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := challengeValidationError
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07205)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(http.StatusBadRequest, expectedMessage)))

	})

	t.Run("Validate dns challenge - dns is not manual", func(t *testing.T) {
		cisCertMetadata := certificate.CertificateMetadata{
			KeyAlgorithm: keyType,
			CommonName:   certCommonName,
			IssuanceInfo: map[string]interface{}{
				secretentry.FieldState:            secretentry.StatePreActivation,
				secretentry.FieldStateDescription: secret_metadata_entry.GetNistStateDescription(secretentry.StatePreActivation),
				FieldBundleCert:                   true, FieldCAConfig: caConfig, FieldAutoRotated: true,
				FieldOrderedOn: time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339),
				FieldDNSConfig: dnsConfig,
			}}
		secretEntry.ExtraData = cisCertMetadata
		common.StoreSecretWithoutLocking(secretEntry, storage, context.Background(), oh.metadataClient, false, "IBMid-1110000RRH1")

		data := map[string]interface{}{}
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      PathSecrets + secretID + PathValidate,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := challengeValidationErrorNotManual
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07206)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(http.StatusBadRequest, expectedMessage)))

	})

	t.Run("Validate dns challenge - validation is in process", func(t *testing.T) {
		certMetadataWithValidation := certificate.CertificateMetadata{
			KeyAlgorithm: keyType,
			CommonName:   certCommonName,
			IssuanceInfo: map[string]interface{}{
				secretentry.FieldState:            secretentry.StatePreActivation,
				secretentry.FieldStateDescription: secret_metadata_entry.GetNistStateDescription(secretentry.StatePreActivation),
				FieldBundleCert:                   true, FieldCAConfig: caConfig, FieldAutoRotated: true,
				FieldOrderedOn:      time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339),
				FieldDNSConfig:      dnsConfigTypeManual,
				FieldValidationTime: time.Now(),
			}}
		secretEntry.ExtraData = certMetadataWithValidation
		common.StoreSecretWithoutLocking(secretEntry, storage, context.Background(), oh.metadataClient, false, "IBMid-1110000RRH1")

		data := map[string]interface{}{}
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      PathSecrets + secretID + PathValidate,
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		expectedMessage := validationAlreadyInProcess
		assert.Equal(t, len(resp.Headers[smErrors.ErrorCodeHeader]), 1)
		assert.Equal(t, resp.Headers[smErrors.ErrorCodeHeader][0], logdna.Error07211)
		assert.Equal(t, true, reflect.DeepEqual(err, logical.CodedError(http.StatusBadRequest, expectedMessage)))

	})

}

func initBackend(useMockAcmeServer bool) {
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
	if useMockAcmeServer {
		existingConfigs.CaConfigs[0].Config[caConfigDirectoryUrl] = "http://localhost:3333"
	}
	existingConfigs.save(context.Background(), storage)
}

var mockAcmeServer *http.Server

func startMockLEAcmeServer() {
	router := gin.Default()
	gin.SetMode(gin.TestMode)
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, acme.Directory{
			NewNonceURL:   "http://localhost:3333/nonce",
			NewAccountURL: "http://localhost:3333/account",
			NewOrderURL:   "http://localhost:3333/order",
			NewAuthzURL:   "http://localhost:3333/authz",
			RevokeCertURL: "http://localhost:3333/revoke",
			KeyChangeURL:  "http://localhost:3333/key",
			Meta:          acme.Meta{},
		})
	})
	router.GET("/directory", func(c *gin.Context) {
		fmt.Println("Received GET request to " + c.Request.URL.String())
		c.JSON(200, acme.Directory{
			NewNonceURL:   "http://localhost:3333/nonce",
			NewAccountURL: "http://localhost:3333/account",
			NewOrderURL:   "http://localhost:3333/order",
			NewAuthzURL:   "http://localhost:3333/authz",
			RevokeCertURL: "http://localhost:3333/revoke",
			KeyChangeURL:  "http://localhost:3333/key",
			Meta:          acme.Meta{},
		})
	})
	router.POST("/order", func(c *gin.Context) {
		var inputOrder acme.Order
		c.ShouldBindJSON(&inputOrder)
		c.Header("Replay-Nonce", "nonce")
		c.Header("Location", "location")
		c.JSON(200, acme.Order{
			Status:  "Pending",
			Expires: time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			Identifiers: []acme.Identifier{{
				Type:  "dns",
				Value: "domain.com",
			}},
			NotBefore:      "",
			NotAfter:       "",
			Error:          nil,
			Authorizations: []string{"http://localhost:3333/123/authz"},
			Finalize:       "",
			Certificate:    "",
		})
	})
	router.HEAD("/nonce", func(c *gin.Context) {
		c.Header("Replay-Nonce", "nonce")
		c.JSON(200, nil)
	})
	router.POST("/:id/authz", func(c *gin.Context) {
		c.Header("Replay-Nonce", "nonce")
		c.JSON(200, acme.Authorization{
			Status:  "Pending",
			Expires: time.Now().Add(7 * 24 * time.Hour),
			Identifier: acme.Identifier{
				Type:  "dns",
				Value: "domain.com",
			},
			Challenges: []acme.Challenge{{
				Type:             "dns-01",
				URL:              "http://localhost:3333/123/authz/challenge",
				Status:           "Pending",
				Validated:        time.Time{},
				Error:            nil,
				Token:            "token",
				KeyAuthorization: "key",
			}},
			Wildcard: false,
		})
	})
	srv := &http.Server{
		Addr:    "localhost:3333",
		Handler: router,
	}
	go func() {
		fmt.Println("Starting ACME server mock")
		// service connections
		if err := srv.ListenAndServe(); err != nil {
			fmt.Printf("listen: %s\n", err)
			mockAcmeServer = srv
		}
	}()
}

func stopMockLEAcmeServer() {
	if mockAcmeServer != nil {
		mockAcmeServer.Shutdown(context.Background())
	}
}
