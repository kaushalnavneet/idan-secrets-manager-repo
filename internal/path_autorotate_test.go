package publiccerts

import (
	"context"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/security-services/secrets-manager-common-utils/secret_metadata_entry"
	"github.ibm.com/security-services/secrets-manager-common-utils/secret_metadata_entry/certificate"
	"github.ibm.com/security-services/secrets-manager-common-utils/secret_metadata_entry/policies"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secret_backend"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/secretentry"
	"gotest.tools/v3/assert"
	"reflect"
	"strings"
	"testing"
	"time"
)

//certificates ids and crns
var (
	expiresIn30Days_autoRotateTrue_id                = uuid.New().String()
	expiresIn20Days_autoRotateTrue_id                = uuid.New().String()
	expiresIn30Days_autoRotateFalse_id               = uuid.New().String()
	failedOrder_id                                   = uuid.New().String()
	expiresIn30Days_autoRotateTrue_notExistConfig_id = uuid.New().String()

	expiresIn30Days_autoRotateTrue_crn                = strings.Replace(smInstanceCrn, "::", ":secret:", 1) + expiresIn30Days_autoRotateTrue_id
	expiresIn20Days_autoRotateTrue_crn                = strings.Replace(smInstanceCrn, "::", ":secret:", 1) + expiresIn20Days_autoRotateTrue_id
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
	expirationIn30Days = today.Add((RotateIfExpirationIsInDays*24 + 10) * time.Hour) //between 31 and 32 days
	expirationIn20Days = today.Add(20 * 24 * time.Hour)

	certMetadata = certificate.CertificateMetadata{
		KeyAlgorithm: keyType,
		CommonName:   certCommonName,
		IssuanceInfo: map[string]interface{}{
			secretentry.FieldState:            secretentry.StateActive,
			secretentry.FieldStateDescription: secret_metadata_entry.GetNistStateDescription(secretentry.StateActive),
			FieldBundleCert:                   true, FieldCAConfig: caConfig, FieldDNSConfig: dnsConfig, FieldAutoRotated: true,
			FieldOrderedOn: time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339),
		}}

	certMetadataWithWrongConfig = certificate.CertificateMetadata{
		KeyAlgorithm: keyType,
		CommonName:   certCommonName,
		IssuanceInfo: map[string]interface{}{
			FieldCAConfig: "wrong",
			//secretentry.FieldState: secretentry.StateActive,
			secretentry.FieldStateDescription: secret_metadata_entry.GetNistStateDescription(secretentry.StateActive),
			FieldBundleCert:                   true,
			FieldDNSConfig:                    dnsConfig,
			FieldAutoRotated:                  false}}

	expectedIssuanceInfoForRotatedCert = map[string]interface{}{
		secretentry.FieldState:            secretentry.StatePreActivation,
		secretentry.FieldStateDescription: secret_metadata_entry.GetNistStateDescription(secretentry.StatePreActivation),
		FieldBundleCert:                   true,
		FieldCAConfig:                     caConfig,
		FieldDNSConfig:                    dnsConfig,
		FieldAutoRotated:                  true}

	expectedIssuanceInfoForFailedRotation = map[string]interface{}{
		secretentry.FieldState:            secretentry.StateDeactivated,
		FieldAutoRenewAttempts:            float64(1),
		secretentry.FieldStateDescription: secret_metadata_entry.GetNistStateDescription(secretentry.StateDeactivated),
		FieldErrorCode:                    "secrets-manager.Error07012",
		FieldErrorMessage:                 "Certificate authority configuration with name 'wrong' was not found",
		FieldBundleCert:                   true, FieldCAConfig: "wrong", FieldDNSConfig: dnsConfig, FieldAutoRotated: true}
)

//certificates in storage before rotation
var (
	expiresIn30Days_autoRotateTrue = &secretentry.SecretEntry{
		SecretMetadataEntry: secret_metadata_entry.SecretMetadataEntry{
			ID:             expiresIn30Days_autoRotateTrue_id,
			Name:           "expiresIn30Days_autoRotateTrue",
			Description:    certDesc,
			Labels:         []string{},
			ExtraData:      certMetadata,
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
			GroupID: defaultGroup,
			State:   secretentry.StateActive,
		},
		Versions: versionsWithData,
	}
	expiresIn20Days_autoRotateTrue = &secretentry.SecretEntry{
		SecretMetadataEntry: secret_metadata_entry.SecretMetadataEntry{
			ID:             expiresIn20Days_autoRotateTrue_id,
			Name:           "expiresIn20Days_autoRotateTrue",
			Description:    certDesc,
			Labels:         []string{},
			ExtraData:      certMetadata,
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
			CRN:     expiresIn20Days_autoRotateTrue_crn,
			GroupID: defaultGroup,
			State:   secretentry.StateActive,
		},
		Versions: versions,
	}
	expiresIn30Days_autoRotateFalse = &secretentry.SecretEntry{
		SecretMetadataEntry: secret_metadata_entry.SecretMetadataEntry{
			ID:             expiresIn30Days_autoRotateFalse_id,
			Name:           "expiresIn30Days_autoRotateFalse",
			Description:    certDesc,
			Labels:         []string{},
			ExtraData:      certMetadata,
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
		},
		Versions: versions,
	}
	failedOrder = &secretentry.SecretEntry{
		SecretMetadataEntry: secret_metadata_entry.SecretMetadataEntry{
			ID:             failedOrder_id,
			Name:           "failedOrder",
			Description:    certDesc,
			Labels:         []string{},
			ExtraData:      nil,
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
		},
		Versions: versions,
	}
	expiresIn30Days_autoRotateTrue_notExistConfig = &secretentry.SecretEntry{
		SecretMetadataEntry: secret_metadata_entry.SecretMetadataEntry{
			ID:          expiresIn30Days_autoRotateTrue_notExistConfig_id,
			Name:        "expiresIn30Days_autoRotateTrue_notExistConfig_id",
			Description: certDesc,
			Labels:      []string{},
			//Wrong config
			ExtraData: certMetadataWithWrongConfig,
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
			GroupID: defaultGroup,
			State:   secretentry.StateActive,
		},
		Versions: versionsWithData,
	}
)

var oh *OrdersHandler
var mcm *common.MetadataManagerMock

func Test_AutoRotate(t *testing.T) {
	oh := initOrdersHandler()
	b, storage = secret_backend.SetupTestBackend(&OrdersBackend{ordersHandler: oh})
	oh.metadataClient = b.GetMetadataClient()
	mcm = oh.metadataClient.(*common.MetadataManagerMock)
	initBackend(false)

	t.Run("Auto Rotate certificates", func(t *testing.T) {
		createCertificates()
		mcm.FakeListResponse = []*secretentry.SecretEntry{expiresIn20Days_autoRotateTrue, expiresIn30Days_autoRotateFalse, failedOrder, expiresIn30Days_autoRotateTrue_notExistConfig}
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

		//should be changed
		getSecretAndCheckItsContent(t, expiresIn20Days_autoRotateTrue_id, expiresIn20Days_autoRotateTrue, expectedIssuanceInfoForRotatedCert)
		//should not be changed
		getSecretAndCheckItsContent(t, expiresIn30Days_autoRotateFalse_id, expiresIn30Days_autoRotateFalse, certMetadata.IssuanceInfo)
		//should not be changed
		getSecretAndCheckItsContent(t, expiresIn30Days_autoRotateFalse_id, expiresIn30Days_autoRotateFalse, certMetadata.IssuanceInfo)
		//should become Deactivated
		getSecretAndCheckItsContent(t, expiresIn30Days_autoRotateTrue_notExistConfig_id, expiresIn30Days_autoRotateTrue_notExistConfig, expectedIssuanceInfoForFailedRotation)
		checkOrdersInProgress(t, []OrderDetails{{GroupId: defaultGroup, Id: expiresIn20Days_autoRotateTrue_id, Attempts: 1}})
	})
}

func getSecretAndCheckItsContent(t *testing.T, secretId string, expectedentry *secretentry.SecretEntry, expectedIssuanceInfo map[string]interface{}) *logical.Response {
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
	assert.Equal(t, resp.Data[secretentry.FieldStateDescription], secret_metadata_entry.GetNistStateDescription(expectedentry.State))
	assert.Equal(t, resp.Data[secretentry.FieldCreatedBy], expectedentry.CreatedBy)
	//issuance info

	assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRotated], expectedIssuanceInfo[FieldAutoRotated])
	assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldBundleCert], expectedIssuanceInfo[FieldBundleCert])
	assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldCAConfig], expectedIssuanceInfo[FieldCAConfig])
	assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldDNSConfig], expectedIssuanceInfo[FieldDNSConfig])
	assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[secretentry.FieldStateDescription], expectedIssuanceInfo[secretentry.FieldStateDescription])
	assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldErrorCode], expectedIssuanceInfo[FieldErrorCode])
	assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldErrorMessage], expectedIssuanceInfo[FieldErrorMessage])
	assert.Equal(t, resp.Data[FieldIssuanceInfo].(map[string]interface{})[FieldAutoRenewAttempts], expectedIssuanceInfo[FieldAutoRenewAttempts])
	return resp
}

func createCertificates() {

	common.StoreSecretWithoutLocking(expiresIn20Days_autoRotateTrue, storage, context.Background(), mcm, false)

	common.StoreSecretWithoutLocking(expiresIn30Days_autoRotateFalse, storage, context.Background(), mcm, false)

	common.StoreSecretWithoutLocking(failedOrder, storage, context.Background(), mcm, false)

	common.StoreSecretWithoutLocking(expiresIn30Days_autoRotateTrue_notExistConfig, storage, context.Background(), mcm, false)
}
