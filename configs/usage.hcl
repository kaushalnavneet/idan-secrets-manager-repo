path "/ibmcloud/public_cert/usage_token/check" { capabilities = ["update"] }
path "/ibmcloud/public_cert/autorotate" { capabilities = ["update"] }
path "/ibmcloud/public_cert/autorotate/final" { capabilities = ["update"] }
path "/ibmcloud/public_cert/resume" { capabilities = ["update"] }
path "/ibmcloud_internal/usage/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "/auth/ibmcloud/internal/*" { capabilities = ["update"] }