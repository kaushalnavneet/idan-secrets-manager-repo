module github.ibm.com/security-services/secrets-manager-vault-plugin-public-cert-secret

go 1.14

replace github.com/pkg/sftp => github.com/pkg/sftp v1.11.0

replace github.com/labstack/echo/v4 => github.com/labstack/echo/v4 v4.2.0

//replace github.com/dgrijalva/jwt-go => github.com/dgrijalva/jwt-go v4.0.0-preview1

require (
	github.com/go-acme/lego/v4 v4.3.1
	github.com/go-playground/validator/v10 v10.6.1
	github.com/hashicorp/go-hclog v0.16.1
	github.com/hashicorp/vault/sdk v0.2.0
	github.ibm.com/project-fortress/vault-client-golang v0.0.4
	github.ibm.com/security-services/secrets-manager-common-utils v0.0.6212
	github.ibm.com/security-services/secrets-manager-vault-plugins-common v0.0.675-0.20210518053427-7e99b2e08500
	golang.org/x/net v0.0.0-20210521195947-fe42d452be8f
)
