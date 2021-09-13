package publiccerts

import (
	"context"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/logical"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/certificate"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry/policies"
	"gotest.tools/v3/assert"
	"reflect"
	"strings"
	"testing"
	"time"
)

//certificates ids and crns
var (
	expiresIn30Days_autoRotateTrue_id                = uuid.New().String()
	expiresIn80Days_autoRotateTrue_id                = uuid.New().String()
	expiresIn30Days_autoRotateFalse_id               = uuid.New().String()
	failedOrder_id                                   = uuid.New().String()
	expiresIn30Days_autoRotateTrue_notExistConfig_id = uuid.New().String()

	expiresIn30Days_autoRotateTrue_crn                = strings.Replace(smInstanceCrn, "::", ":secret:", 1) + expiresIn30Days_autoRotateTrue_id
	expiresIn80Days_autoRotateTrue_crn                = strings.Replace(smInstanceCrn, "::", ":secret:", 1) + expiresIn80Days_autoRotateTrue_id
	expiresIn30Days_autoRotateFalse_crn               = strings.Replace(smInstanceCrn, "::", ":secret:", 1) + expiresIn30Days_autoRotateFalse_id
	failedOrder_crn                                   = strings.Replace(smInstanceCrn, "::", ":secret:", 1) + failedOrder_id
	expiresIn30Days_autoRotateTrue_notExistConfig_crn = strings.Replace(smInstanceCrn, "::", ":secret:", 1) + expiresIn30Days_autoRotateTrue_notExistConfig_id
)

//entries data
var (
	secretData = map[string]interface{}{
		secretentry.FieldCertificate:  previousCert,
		secretentry.FieldIntermediate: previousIntermediate,
		secretentry.FieldPrivateKey:   previousPrivKey,
	}
	versionsWithData = []secretentry.SecretVersion{{
		ID:           uuid.New().String(),
		VersionData:  secretData,
		CreationDate: time.Now().Add(-1 * time.Hour),
		CreatedBy:    createdBy,
		AutoRotated:  false,
		ExtraData: map[string]interface{}{
			secretentry.FieldSerialNumber:   serialNumber,
			secretentry.FieldExpirationDate: expirationIn30Days,
			secretentry.FieldNotAfter:       expirationIn30Days,
			secretentry.FieldNotBefore:      today.Add(-60 * 24 * time.Hour),
		},
	}}
	today              = time.Now()
	expirationIn30Days = today.Add(RotateIfExpirationIsInDays * 24 * time.Hour)
	expirationIn80Days = today.Add(80 * 24 * time.Hour)

	certMetadata = certificate.CertificateMetadata{
		KeyAlgorithm: keyType,
		CommonName:   certCommonName,
		IssuanceInfo: map[string]interface{}{
			//secretentry.FieldState: secretentry.StateActive,
			secretentry.FieldStateDescription: secretentry.GetNistStateDescription(secretentry.StateActive),
			FieldBundleCert:                   true, FieldCAConfig: caConfig, FieldDNSConfig: dnsConfig, FieldAutoRotated: true}}

	certMetadataWithWrongConfig = certificate.CertificateMetadata{
		KeyAlgorithm: keyType,
		CommonName:   certCommonName,
		IssuanceInfo: map[string]interface{}{
			FieldCAConfig: "wrong",
			//secretentry.FieldState: secretentry.StateActive,
			secretentry.FieldStateDescription: secretentry.GetNistStateDescription(secretentry.StateActive),
			FieldBundleCert:                   true,
			FieldDNSConfig:                    dnsConfig,
			FieldAutoRotated:                  false}}
)

//certificates in storage before rotation
var (
	expiresIn30Days_autoRotateTrue = &secretentry.SecretEntry{
		ID:             expiresIn30Days_autoRotateTrue_id,
		Name:           "expiresIn30Days_autoRotateTrue",
		Description:    certDesc,
		Labels:         []string{},
		ExtraData:      certMetadata,
		Versions:       versionsWithData,
		CreatedAt:      today.Add(-60 * 24 * time.Hour),
		CreatedBy:      createdBy,
		ExpirationDate: &expirationIn30Days,
		TTL:            0,
		Policies: policies.Policies{
			Rotation: &policies.RotationPolicy{
				Rotation: &policies.RotationData{
					RotateKeys: false,
					AutoRotate: true,
				},
				Type: policies.MIMETypeForPolicyResource}},
		Type:    secretentry.SecretTypePublicCert,
		CRN:     expiresIn30Days_autoRotateTrue_crn,
		GroupID: "",
		State:   secretentry.StateActive,
	}
	expiresIn80Days_autoRotateTrue = &secretentry.SecretEntry{
		ID:             expiresIn80Days_autoRotateTrue_id,
		Name:           "expiresIn80Days_autoRotateTrue",
		Description:    certDesc,
		Labels:         []string{},
		ExtraData:      certMetadata,
		Versions:       versions,
		CreatedAt:      today.Add(-10 * 24 * time.Hour),
		CreatedBy:      createdBy,
		ExpirationDate: &expirationIn80Days,
		TTL:            0,
		Policies: policies.Policies{
			Rotation: &policies.RotationPolicy{
				Rotation: &policies.RotationData{
					RotateKeys: false,
					AutoRotate: true,
				},
				Type: policies.MIMETypeForPolicyResource}},
		Type:    secretentry.SecretTypePublicCert,
		CRN:     expiresIn80Days_autoRotateTrue_crn,
		GroupID: "",
		State:   secretentry.StateActive,
	}
	expiresIn30Days_autoRotateFalse = &secretentry.SecretEntry{
		ID:             expiresIn30Days_autoRotateFalse_id,
		Name:           "expiresIn30Days_autoRotateFalse",
		Description:    certDesc,
		Labels:         []string{},
		ExtraData:      certMetadata,
		Versions:       versions,
		CreatedAt:      today.Add(-60 * 24 * time.Hour),
		CreatedBy:      createdBy,
		ExpirationDate: &expirationIn30Days,
		TTL:            0,
		Policies: policies.Policies{
			Rotation: &policies.RotationPolicy{
				Rotation: &policies.RotationData{
					RotateKeys: false,
					AutoRotate: false,
				},
				Type: policies.MIMETypeForPolicyResource}},
		Type:    secretentry.SecretTypePublicCert,
		CRN:     expiresIn30Days_autoRotateFalse_crn,
		GroupID: "",
		State:   secretentry.StateActive,
	}
	failedOrder = &secretentry.SecretEntry{
		ID:             failedOrder_id,
		Name:           "failedOrder",
		Description:    certDesc,
		Labels:         []string{},
		ExtraData:      nil,
		Versions:       versions,
		CreatedAt:      today.Add(-60 * 24 * time.Hour),
		CreatedBy:      createdBy,
		ExpirationDate: nil,
		TTL:            0,
		Policies: policies.Policies{
			Rotation: &policies.RotationPolicy{
				Rotation: &policies.RotationData{
					RotateKeys: false,
					AutoRotate: false,
				},
				Type: policies.MIMETypeForPolicyResource}},
		Type:    secretentry.SecretTypePublicCert,
		CRN:     failedOrder_crn,
		GroupID: "",
		State:   secretentry.StateDeactivated,
	}
	expiresIn30Days_autoRotateTrue_notExistConfig = &secretentry.SecretEntry{
		ID:          expiresIn30Days_autoRotateTrue_notExistConfig_id,
		Name:        "expiresIn30Days_autoRotateTrue_notExistConfig_id",
		Description: certDesc,
		Labels:      []string{},
		//Wrong config
		ExtraData: certMetadataWithWrongConfig,
		Versions:  versionsWithData,
		CreatedAt: today.Add(-60 * 24 * time.Hour),
		CreatedBy: createdBy,
		//expiration in 30 days
		ExpirationDate: &expirationIn30Days,
		TTL:            0,
		Policies: policies.Policies{
			Rotation: &policies.RotationPolicy{
				Rotation: &policies.RotationData{
					RotateKeys: false,
					AutoRotate: true,
				},
				Type: policies.MIMETypeForPolicyResource}},
		Type:    secretentry.SecretTypePublicCert,
		CRN:     expiresIn30Days_autoRotateTrue_notExistConfig_crn,
		GroupID: "",
		State:   secretentry.StateActive,
	}
)

var oh *OrdersHandler

func Test_AutoRotate(t *testing.T) {
	oh = &OrdersHandler{
		runningOrders: make(map[string]WorkItem),
		beforeOrders:  make(map[string]WorkItem),
		parser:        &certificate.CertificateParserImpl{},
	}
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{})
	initBackend()

	t.Run("Rotate certificates", func(t *testing.T) {
		createCertificates()
		//get secret
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      AutoRotatePath,
			Storage:   storage,
			Data:      make(map[string]interface{}),
			Connection: &logical.Connection{
				RemoteAddr: "0.0.0.0",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Equal(t, false, resp.IsError())
		expectedIssuanceInfoForRotatedCert := map[string]interface{}{
			secretentry.FieldState:            secretentry.StatePreActivation,
			secretentry.FieldStateDescription: secretentry.GetNistStateDescription(secretentry.StatePreActivation),
			FieldBundleCert:                   true,
			FieldCAConfig:                     caConfig,
			FieldDNSConfig:                    dnsConfig,
			FieldAutoRotated:                  true}

		expectedIssuanceInfoForFailedRotation := map[string]interface{}{
			secretentry.FieldState:            secretentry.StateDeactivated,
			secretentry.FieldStateDescription: secretentry.GetNistStateDescription(secretentry.StateDeactivated),
			FieldErrorCode:                    "secrets-manager.Error07012",
			FieldErrorMessage:                 "Certificate authority configuration with name 'wrong' was not found",
			FieldBundleCert:                   true, FieldCAConfig: "wrong", FieldDNSConfig: dnsConfig, FieldAutoRotated: true}

		getSecretAndCheckItsContent(t, expiresIn80Days_autoRotateTrue_id, expiresIn80Days_autoRotateTrue, certMetadata.IssuanceInfo)
		getSecretAndCheckItsContent(t, expiresIn30Days_autoRotateFalse_id, expiresIn30Days_autoRotateFalse, certMetadata.IssuanceInfo)
		getSecretAndCheckItsContent(t, expiresIn30Days_autoRotateFalse_id, expiresIn30Days_autoRotateFalse, certMetadata.IssuanceInfo)
		getSecretAndCheckItsContent(t, expiresIn30Days_autoRotateTrue_id, expiresIn30Days_autoRotateTrue, expectedIssuanceInfoForRotatedCert)
		getSecretAndCheckItsContent(t, expiresIn30Days_autoRotateTrue_notExistConfig_id, expiresIn30Days_autoRotateTrue_notExistConfig, expectedIssuanceInfoForFailedRotation)
	})
}

func getSecretAndCheckItsContent(t *testing.T, secretId string, expectedentry *secretentry.SecretEntry, expectedIssuanceInfo map[string]interface{}) {
	//get secret
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      PathSecrets + secretId + PathMetadata,
		Storage:   storage,
		Data:      make(map[string]interface{}),
		Connection: &logical.Connection{
			RemoteAddr: "0.0.0.0",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	assert.NilError(t, err)
	assert.Equal(t, false, resp.IsError())
	//common fields
	assert.Equal(t, resp.Data[secretentry.FieldSecretType], secretentry.SecretTypePublicCert)
	assert.Equal(t, resp.Data[secretentry.FieldName], expectedentry.Name)
	assert.Equal(t, resp.Data[secretentry.FieldDescription], expectedentry.Description)
	assert.Equal(t, true, reflect.DeepEqual(resp.Data[secretentry.FieldLabels].([]string), expectedentry.Labels))
	assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secretentry.GetNistStateDescription(expectedentry.State))
	assert.Equal(t, resp.Data[secretentry.FieldCreatedBy], expectedentry.CreatedBy)
	//issuance info

	assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRotated], expectedIssuanceInfo[FieldAutoRotated])
	assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldBundleCert], expectedIssuanceInfo[FieldBundleCert])
	assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldCAConfig], expectedIssuanceInfo[FieldCAConfig])
	assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldDNSConfig], expectedIssuanceInfo[FieldDNSConfig])
	assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], expectedIssuanceInfo[secretentry.FieldStateDescription])
	assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldErrorCode], expectedIssuanceInfo[FieldErrorCode])
	assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldErrorMessage], expectedIssuanceInfo[FieldErrorMessage])
}

func createCertificates() {

	common.StoreSecretWithoutLocking(expiresIn30Days_autoRotateTrue, storage, context.Background())

	common.StoreSecretWithoutLocking(expiresIn80Days_autoRotateTrue, storage, context.Background())

	common.StoreSecretWithoutLocking(expiresIn30Days_autoRotateFalse, storage, context.Background())

	common.StoreSecretWithoutLocking(failedOrder, storage, context.Background())

	common.StoreSecretWithoutLocking(expiresIn30Days_autoRotateTrue_notExistConfig, storage, context.Background())
}
