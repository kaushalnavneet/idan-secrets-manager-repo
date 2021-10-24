// usage token check path
path "/ibmcloud/public_cert/usage_token/check" { capabilities = ["update"] }

path "/ibmcloud/public_cert/autorotate" { capabilities = ["update"] }
path "/ibmcloud/public_cert/autorotate/final" { capabilities = ["update"] }
path "/ibmcloud/public_cert/resume" { capabilities = ["update"] }

// usage plugin api
path "/ibmcloud_internal/usage/*" { capabilities = ["create", "read", "update", "delete", "list"] }
// auth plugin internal api - read for getting internal service token, update for obtain cached tokens and validating requests
path "/auth/ibmcloud/internal/*" { capabilities = ["read", "update"] }