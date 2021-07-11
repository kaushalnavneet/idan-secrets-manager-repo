module github.ibm.com/security-services/secrets-manager-vault-plugin-public-cert-secret

go 1.14

replace github.com/pkg/sftp => github.com/pkg/sftp v1.13.2

replace github.com/labstack/echo/v4 => github.com/labstack/echo/v4 v4.3.0

//replace github.com/dgrijalva/jwt-go => github.com/dgrijalva/jwt-go v4.0.0-preview1

require (
	github.com/go-acme/lego/v4 v4.4.0
	github.com/go-playground/validator/v10 v10.7.0
	github.com/google/uuid v1.2.0
	github.com/hashicorp/go-hclog v0.16.2
	github.com/hashicorp/vault/sdk v0.2.0
	github.ibm.com/project-fortress/vault-client-golang v0.0.4
	github.ibm.com/security-services/secrets-manager-common-utils v0.0.6894
	github.ibm.com/security-services/secrets-manager-iam v0.0.6887
	github.ibm.com/security-services/secrets-manager-vault-plugins-common v0.0.6899
	golang.org/x/net v0.0.0-20210614182718-04defd469f4e
)
