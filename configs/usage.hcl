path "/ibmcloud/public_cert/usage_token/check" { capabilities = ["update"] }
path "/ibmcloud/public_cert/autorenew" { capabilities = ["update"] }
path "/ibmcloud/public_cert/autorenew/final" { capabilities = ["update"] }
path "/ibmcloud_internal/usage/*" { capabilities = ["create", "read", "update", "delete", "list"] }