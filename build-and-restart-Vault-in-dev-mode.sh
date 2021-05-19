#!/bin/bash
pkill vault
make fmt
make build
vault server -dev -dev-root-token-id=root -log-level=debug -dev-plugin-dir=./vault/plugins &
export VAULT_ADDR='http://127.0.0.1:8200'
VAULT_ROOT=secrets-manager-vault-plugin-public-cert-secret/vault
PLUGIN_DIR=$VAULT_ROOT/plugins
PLUGIN_NAME=public_cert
PLUGIN_MOUNT_PATH=ibmcloud/$PLUGIN_NAME
PLUGIN_SRC=$PWD

# Collect Vault secrets
cd ./local/out; ./secrets; cd ../..
LOCAL_OUTPUT=$(cat ./local/out/.iam_auth.json)
OPERATOR_API_KEY=$(echo "$LOCAL_OUTPUT" | jq -j ".operator.api_key")
CLIENT_ID=$(echo "$LOCAL_OUTPUT" | jq -j ".client.id")
CLIENT_SECRET=$(echo "$LOCAL_OUTPUT" | jq -j ".client.secret")
LOCAL_CONFIG=$(cat local/config.json)
IAM_ENDPOINT=$(echo "$LOCAL_CONFIG" | jq -j ".iam_endpoint")
VAULT_ENDPOINT=$(echo "$LOCAL_CONFIG" | jq -j ".vault_endpoint")
INSTANCE_CRN=$(echo "$LOCAL_CONFIG" | jq -j ".instance_crn")
INTERNAL_SERVICE_ID=$(echo "$LOCAL_OUTPUT" | jq -j ".internal.service_id")

cd $VAULT_ROOT

echo Add auth iam-plugin
#add ibm-iam plugin
vault auth disable /ibmcloud

SHA256=$(shasum -a 256 "plugins/ibm-iam" | cut -d' ' -f1)
echo iam-iam sha_256 $SHA256

vault write sys/plugins/catalog/auth/ibm-iam \
  sha_256="${SHA256}" \
  command="ibm-iam"

# Enable Auth Method - https://www.vaultproject.io/api-docs/system/auth
vault auth enable \
  -description="IBM Cloud IAM auth method" \
  -path="ibmcloud" \
  -plugin-name="ibm-iam" plugin

# Resister Vault policies for mapping IAM instance policies
vault policy write instance-manager "$VAULT_ROOT"/configs/manager.hcl
vault policy write instance-writer "$VAULT_ROOT"/configs/writer.hcl
vault policy write instance-secrets-reader "$VAULT_ROOT"/configs/secrets-reader.hcl
vault policy write instance-reader "$VAULT_ROOT"/configs/reader.hcl
vault policy write operator "$VAULT_ROOT"/configs/operator.hcl

# Create operator token role with period of 30 days
vault write auth/token/roles/operator allowed_policies="operator" period="720h"

# Create periodic token for operator role and set as env variable OP_TOKEN
OP_TOKEN="$(vault token create -role=operator -format=json | jq -j '.auth.client_token')"

set -x

# Configure the Auth Plugin
vault write auth/ibmcloud/config \
  api_key="$OPERATOR_API_KEY" \
  client_id="$CLIENT_ID" \
  client_secret="$CLIENT_SECRET" \
  instance_crn="$INSTANCE_CRN" \
  iam_endpoint="$IAM_ENDPOINT" \
  vault_endpoint="$VAULT_ENDPOINT" \
  op_token="$OP_TOKEN" \
  internal_service_id="$INTERNAL_SERVICE_ID"


echo "AUTH PLUGIN IS REGISTERED"

vault secrets disable ibmcloud_internal/usage

SHA256=$(shasum -a 256 "$PLUGIN_DIR/usage" | cut -d' ' -f1)
echo usage sha $SHA256

vault write sys/plugins/catalog/secret/usage  sha_256="${SHA256}" command="usage"

# Enable Auth Method - https://www.vaultproject.io/api-docs/system/auth
vault secrets enable   -description="IBM Cloud usage secret engine"  -path="ibmcloud_internal/usage"   -plugin-name="usage" plugin

vault write ibmcloud_internal/usage/config  instance_crn="$INSTANCE_CRN"

echo "USAGE PLUGIN IS REGISTERED"

vault secrets disable ibmcloud/$PLUGIN_NAME
SHA256=$(shasum -a 256 "$PLUGIN_DIR/$PLUGIN_NAME" | cut -d' ' -f1)
echo $SHA256
vault write sys/plugins/catalog/secret/$PLUGIN_NAME  sha_256="${SHA256}" command="$PLUGIN_NAME"
# Enable Auth Method - https://www.vaultproject.io/api-docs/system/auth
vault secrets enable \
    -description="IBM Cloud $PLUGIN_NAME secret engine" \
    -path="ibmcloud/$PLUGIN_NAME" \
    -plugin-name="$PLUGIN_NAME" plugin

cd $VAULT_ROOT
# Register Vault policy for usage
vault policy write usage "$PLUGIN_SRC"/configs/usage.hcl
# Create usage token role with period of 30 days
vault write auth/token/roles/usage allowed_policies="usage" period="720h"
# Create periodic token for usage role and set as env variable USAGE_TOKEN
USAGE_TOKEN="$(vault token create -role=usage -format=json | jq -j '.auth.client_token')"

vault write ibmcloud/$PLUGIN_NAME/config/iam \
  api_key="$OPERATOR_API_KEY" \
  client_id="$CLIENT_ID" \
  client_secret="$CLIENT_SECRET" \
  instance_crn="$INSTANCE_CRN" \
  iam_endpoint="$IAM_ENDPOINT" \
  vault_endpoint="$VAULT_ENDPOINT" \
  usage_token="$USAGE_TOKEN"