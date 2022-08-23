package publiccerts

import (
	"errors"
	"fmt"
	"github.com/hashicorp/go-hclog"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	commonErrors "github.ibm.com/security-services/secrets-manager-vault-plugins-common/errors"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"gotest.tools/v3/assert"
	"net/http"
	"os"
	"testing"
)

func Test_Utils_ValidateDomains(t *testing.T) {
	common.SetLogger(hclog.L())
	t.Run("Invalid domain", func(t *testing.T) {
		wrongDomain := "isuy876$#@"
		err := validateNames([]string{wrongDomain})
		expectedMessage := fmt.Sprintf(invalidDomain, wrongDomain)
		assert.DeepEqual(t, err, commonErrors.GenerateCodedError(logdna.Error07107, http.StatusBadRequest, expectedMessage))
	})

	t.Run("Invalid ASCII domain", func(t *testing.T) {
		wrongDomain := "xn--домейнדומין"
		err := validateNames([]string{wrongDomain})
		expectedMessage := fmt.Sprintf(invalidDomain, wrongDomain)
		assert.DeepEqual(t, err, commonErrors.GenerateCodedError(logdna.Error07105, http.StatusBadRequest, expectedMessage))
	})

	t.Run("Duplicate domain", func(t *testing.T) {
		domain := "domain.com"
		err := validateNames([]string{domain, domain})
		expectedMessage := fmt.Sprintf(duplicateDomain, domain)
		assert.DeepEqual(t, err, commonErrors.GenerateCodedError(logdna.Error07108, http.StatusBadRequest, expectedMessage))
	})

	t.Run("Redundant domains", func(t *testing.T) {
		err := validateNames([]string{"*.domain.com", "test.domain.com"})
		expectedMessage := redundantDomain
		assert.DeepEqual(t, err, commonErrors.GenerateCodedError(logdna.Error07109, http.StatusBadRequest, expectedMessage))
	})

	t.Run("Too long domain", func(t *testing.T) {
		err := validateNames([]string{"longlonglonglonglonglonglonglong.longlonglonglonglonglonglonglong.longlonglonglonglonglonglonglong.test1.secrets-manager.test.appdomain.cloud"})
		expectedMessage := commonNameTooLong
		assert.DeepEqual(t, err, commonErrors.GenerateCodedError(logdna.Error07106, http.StatusBadRequest, expectedMessage))
	})

	t.Run("Too many domains", func(t *testing.T) {
		err := validateNames(make([]string, 101))
		expectedMessage := tooManyDomain
		assert.DeepEqual(t, err, commonErrors.GenerateCodedError(logdna.Error07101, http.StatusBadRequest, expectedMessage))
	})
}

func Test_Utils_GetOrderError(t *testing.T) {
	common.SetLogger(hclog.L())
	t.Run("Formatted error", func(t *testing.T) {
		err := buildOrderError("errorCode", "errorMessage")
		orderResult := Result{
			workItem:    WorkItem{},
			Error:       errors.New("some additional text from ACME client " + err.Error() + "another text"),
			certificate: nil,
		}
		orderError := getOrderError(orderResult)
		assert.DeepEqual(t, orderError, &OrderError{
			Code:    "errorCode",
			Message: "errorMessage",
		})
	})

	t.Run("Test GetEnvInt fallback should be used", func(t *testing.T) {
		value := GetEnvInt("MyKey", 10)
		assert.Equal(t, 10, value)
	})

	t.Run("Test GetEnvInt invalid int fallback should be used", func(t *testing.T) {
		os.Setenv("MyKey", "not_int")
		value := GetEnvInt("MyKey", 10)
		assert.Equal(t, 10, value)
	})

	t.Run("Test GetEnvInt env should be used", func(t *testing.T) {
		os.Setenv("MyKey", "5")
		value := GetEnvInt("MyKey", 10)
		assert.Equal(t, 5, value)
	})

	t.Run("Not formatted error", func(t *testing.T) {
		orderResult := Result{
			workItem:    WorkItem{},
			Error:       errors.New("some error from ACME client "),
			certificate: nil,
		}
		orderError := getOrderError(orderResult)
		assert.DeepEqual(t, orderError, &OrderError{
			Code:    "ACME_Error",
			Message: "some error from ACME client ",
		})
	})
}
