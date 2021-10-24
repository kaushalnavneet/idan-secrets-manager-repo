#!/usr/bin/env bash

export VAULT_ADDR='http://127.0.0.1:8200'
VAULT_ROOT=<VAULT_ROOT_PATH>
PLUGIN_DIR=$VAULT_ROOT/plugins
PLUGIN_NAME=public_cert
PLUGIN_MOUNT_PATH=ibmcloud/$PLUGIN_NAME
PLUGIN_SRC=$PWD

set -ex
go build -o $PLUGIN_DIR/$PLUGIN_NAME ./cmd/plugin

cd $VAULT_ROOT

vault login token=root

if ! vault secrets disable ibmcloud/$PLUGIN_NAME; then
	echo "Couldn't disable"
fi

SHA256=$(shasum -a 256 "$PLUGIN_DIR/$PLUGIN_NAME" | cut -d' ' -f1)
echo $SHA256

vault write sys/plugins/catalog/secret/$PLUGIN_NAME  sha_256="${SHA256}" command="$PLUGIN_NAME"

# Enable Auth Method - https://www.vaultproject.io/api-docs/system/auth
vault secrets enable \
    -description="IBM Cloud $PLUGIN_NAME secret engine" \
    -path="ibmcloud/$PLUGIN_NAME" \
    -plugin-name="$PLUGIN_NAME" plugin

VAULT_ENDPOINT=http://127.0.0.1:8200
METADATA_MANAGER_URL=<local-metadata-managet-url>
INSTANCE_CRN=crn:v1:staging:public:secrets-manager:us-south:a/791f5fb10986423e97aa8512f18b7e65:64be543a-3901-4f54-9d60-854382b21f29::

cd $VAULT_ROOT

# Register Vault policy for usage
vault policy write ${PLUGIN_NAME}_usage "$PLUGIN_SRC"/configs/usage.hcl
# Create usage token role with period of 30 days
vault write auth/token/roles/${PLUGIN_NAME}_usage allowed_policies=${PLUGIN_NAME}_usage period="720h"
# Create periodic token for usage role and set as env variable USAGE_TOKEN
USAGE_TOKEN="$(vault token create -role=${PLUGIN_NAME}_usage -format=json | jq -j '.auth.client_token')"

vault write ibmcloud/$PLUGIN_NAME/config/engine \
  instance_crn="$INSTANCE_CRN" \
  vault_endpoint="$VAULT_ENDPOINT" \
  usage_token="$USAGE_TOKEN" \
  metadata_manager_url="$METADATA_MANAGER_URL"