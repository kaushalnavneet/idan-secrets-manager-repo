#!/usr/bin/env bash

export VAULT_ADDR='http://127.0.0.1:8200'
VAULT_ROOT=<VAULT_ROOT_PATH>
PLUGIN_DIR=$VAULT_ROOT/plugins
PLUGIN_NAME=public_cert
PLUGIN_MOUNT_PATH=ibmcloud/$PLUGIN_NAME
PLUGIN_SRC=$PWD
set -ex
go build -o $PLUGIN_DIR/$PLUGIN_NAME ./cmd/plugin
go build -o ./local/out/secrets ./local/cmd/secrets

cd $VAULT_ROOT
vault login token=root
vault secrets disable ibmcloud/$PLUGIN_NAME

SHA256=$(shasum -a 256 "$PLUGIN_DIR/$PLUGIN_NAME" | cut -d' ' -f1)
echo $SHA256

vault write sys/plugins/catalog/secret/$PLUGIN_NAME  sha_256="${SHA256}" command="$PLUGIN_NAME"

# Enable Auth Method - https://www.vaultproject.io/api-docs/system/auth
vault secrets enable \
    -description="IBM Cloud $PLUGIN_NAME secret engine" \
    -path="ibmcloud/$PLUGIN_NAME" \
    -plugin-name="$PLUGIN_NAME" plugin

# Collect Vault secrets
cd $PLUGIN_SRC
cd ./local/out; ./secrets; cd ../..
LOCAL_OUTPUT=$(cat ./local/out/.iam_auth.json)
OPERATOR_API_KEY=$(echo "$LOCAL_OUTPUT" | jq -j ".operator.api_key")
CLIENT_ID=$(echo "$LOCAL_OUTPUT" | jq -j ".client.id")
CLIENT_SECRET=$(echo "$LOCAL_OUTPUT" | jq -j ".client.secret")
LOCAL_CONFIG=$(cat local/config.json)
IAM_ENDPOINT=$(echo "$LOCAL_CONFIG" | jq -j ".iam_endpoint")
VAULT_ENDPOINT=$(echo "$LOCAL_CONFIG" | jq -j ".vault_endpoint")
INSTANCE_CRN=$(echo "$LOCAL_CONFIG" | jq -j ".instance_crn")

cd $VAULT_ROOT
# Register Vault policy for usage
vault policy write usage "$PLUGIN_SRC"/configs/usage.hcl
# Create usage token role with period of 30 days
vault write auth/token/roles/public_cert_usage allowed_policies="usage" period="720h"
# Create periodic token for usage role and set as env variable USAGE_TOKEN
USAGE_TOKEN="$(vault token create -role=public_cert_usage -format=json | jq -j '.auth.client_token')"

vault write ibmcloud/$PLUGIN_NAME/config/iam \
  api_key="$OPERATOR_API_KEY" \
  client_id="$CLIENT_ID" \
  client_secret="$CLIENT_SECRET" \
  instance_crn="$INSTANCE_CRN" \
  iam_endpoint="$IAM_ENDPOINT" \
  vault_endpoint="$VAULT_ENDPOINT" \
  usage_token="$USAGE_TOKEN"

