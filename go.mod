module github.ibm.com/security-services/secrets-manager-vault-plugin-public-cert-secret

go 1.14

replace github.com/pkg/sftp => github.com/pkg/sftp v1.13.3

replace github.com/labstack/echo/v4 => github.com/labstack/echo/v4 v4.5.0

//replace github.com/dgrijalva/jwt-go => github.com/dgrijalva/jwt-go v4.0.0-preview1

require (
	github.com/go-acme/lego/v4 v4.4.0
	github.com/go-playground/validator/v10 v10.9.0
	github.com/go-resty/resty/v2 v2.7.0
	github.com/google/uuid v1.3.0
	github.com/hashicorp/go-hclog v1.0.0
	github.com/hashicorp/vault/sdk v0.3.0
	github.com/robfig/cron/v3 v3.0.1
	github.ibm.com/security-services/secrets-manager-common-utils v0.0.8913
	github.ibm.com/security-services/secrets-manager-iam v0.0.8072
	github.ibm.com/security-services/secrets-manager-vault-plugins-common v0.0.9188
	golang.org/x/net v0.0.0-20211029224645-99673261e6eb
	gotest.tools/v3 v3.0.3
)
