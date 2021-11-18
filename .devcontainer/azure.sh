#!/bin/bash
if [ "$CLIENT_SECRET" != "" ]; then
    exit
fi

if [ "$VAULT_NAME" == "" ] && [ "$VAULT_SECRET_KEY" = "" ]; then
    exit
fi

islogged=$(az account show -o json | jq ".")

if [ "$islogged" == "" ]; then 
    az_login=$(az login -t $TENANT_ID)
    az_account=$(az account set -s $SUBSCRIPTION_ID)
fi

printf "%b\n" "## Checking KeyVault \e[32m$VAULT_NAME\e[0m."
kv=$(az keyvault show -n $VAULT_NAME -o json | jq '.')

if [ "$kv" == "" ]; then
    printf "%b\n" "   KeyVault \e[32m$VAULT_NAME\e[0m does not seems to be reachable."
    exit 3
fi

printf "%b\n" "## Getting vault url"
kv_url=$kv | jq -r '.properties.vaultUri'

printf "%b\n" "## Getting vault secret"
kv_secret=$(az keyvault secret show --vault-name "$VAULT_NAME" --name "$VAULT_SECRET_KEY" --query 'value' --output json | jq -r '.')
if [ "$kv_secret" == "" ]; then
    printf "%b\n" "   Secret \e[32m$VAULT_SECRET_KEY\e[0m does not seems to be reachable."
    exit 3
fi

if ! grep -R "^[#]*\s*CLIENT_SECRET=.*" ~/.bashrc > /dev/null; then
  printf "%b\n" "## Appending \e[32mCLIENT_SECRET\e[0m value in environment variables."
  echo "export CLIENT_SECRET=$kv_secret" >> ~/.bashrc
else
  printf "%b\n" "## Setting \e[32mCLIENT_SECRET\e[0m value because it already exists."
  sed "s,CLIENT_SECRET=[^;]*,export CLIENT_SECRET=$kv_secret," -i ~/.bashrc
fi

