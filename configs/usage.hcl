path "/ibmcloud/public_cert/usage_token/check" { capabilities = ["update"] }
path "/ibmcloud_internal/usage/*" { capabilities = ["create", "read", "update", "delete", "list"] }