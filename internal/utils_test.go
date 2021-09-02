package publiccerts

import (
	"fmt"
	"github.com/hashicorp/go-hclog"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	commonErrors "github.ibm.com/security-services/secrets-manager-vault-plugins-common/errors"
	"github.ibm.com/security-services/secrets-manager-vault-plugins-common/logdna"
	"gotest.tools/v3/assert"
	"net/http"
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

	t.Run("Too long domains", func(t *testing.T) {
		err := validateNames([]string{"longlonglonglonglonglonglonglong.longlonglonglonglonglonglonglong.longlonglonglonglonglonglonglong.test1.secrets-manager.test.appdomain.cloud"})
		expectedMessage := commonNameTooLong
		assert.DeepEqual(t, err, commonErrors.GenerateCodedError(logdna.Error07106, http.StatusBadRequest, expectedMessage))
	})
}
