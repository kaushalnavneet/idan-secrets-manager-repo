module github.ibm.com/security-services/secrets-manager-vault-plugin-public-cert-secret

go 1.14

require (
	github.com/go-acme/lego/v4 v4.3.1
	github.com/go-playground/validator/v10 v10.5.0
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-hclog v0.16.0
	github.com/hashicorp/vault/sdk v0.2.0
	github.ibm.com/IAM/token/v2 v2.2.6 // indirect
	github.ibm.com/project-fortress/vault-client-golang v0.0.3
	github.ibm.com/security-services/secrets-manager-common-utils v0.0.668
	github.ibm.com/security-services/secrets-manager-iam v0.0.531
	github.ibm.com/security-services/secrets-manager-vault-plugins-common v0.0.675-0.20210518053427-7e99b2e08500
	golang.org/x/net v0.0.0-20210405180319-a5a99cb37ef4
)
