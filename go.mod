module github.ibm.com/security-services/secrets-manager-vault-plugin-public-cert-secret

go 1.14

replace github.com/pkg/sftp => github.com/pkg/sftp v1.13.4

replace github.com/labstack/echo/v4 => github.com/labstack/echo/v4 v4.6.3

//replace github.com/dgrijalva/jwt-go => github.com/dgrijalva/jwt-go v4.0.0-preview1

require (
	github.com/go-acme/lego/v4 v4.5.3
	github.com/go-playground/validator/v10 v10.10.0
	github.com/go-resty/resty/v2 v2.7.0
	github.com/google/uuid v1.3.0
	github.com/hashicorp/go-hclog v1.1.0
	github.com/hashicorp/vault/sdk v0.3.0
	github.com/robfig/cron/v3 v3.0.1
	github.ibm.com/security-services/secrets-manager-common-utils v0.0.10043
	github.ibm.com/security-services/secrets-manager-iam v0.0.10097
	github.ibm.com/security-services/secrets-manager-vault-plugins-common v0.0.10128
	golang.org/x/net v0.0.0-20220114011407-0dd24b26b47d
	gotest.tools/v3 v3.1.0
)
