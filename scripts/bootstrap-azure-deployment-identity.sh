#!/usr/bin/env bash
set -euo pipefail

: "${GL_HOST:?Set GL_HOST to the GitLab hostname}"
: "${GITLAB_PROJECT_PATH:?Set GITLAB_PROJECT_PATH to the target GitLab project}"
: "${AZURE_DEPLOYMENT_APP_NAME:=wheelguard-gitlab-deploy}"

command -v az >/dev/null
command -v glab >/dev/null
command -v jq >/dev/null

account_json="$(az account show --output json)"
tenant_id="$(jq -r .tenantId <<<"$account_json")"
subscription_id="$(jq -r .id <<<"$account_json")"

app_id="$(az ad app list --display-name "$AZURE_DEPLOYMENT_APP_NAME" --query '[0].appId' --output tsv)"
if [[ -z "$app_id" ]]; then
  app_id="$(az ad app create --display-name "$AZURE_DEPLOYMENT_APP_NAME" --query appId --output tsv)"
fi
principal_id="$(az ad sp list --filter "appId eq '$app_id'" --query '[0].id' --output tsv)"
if [[ -z "$principal_id" ]]; then
  principal_id="$(az ad sp create --id "$app_id" --query id --output tsv)"
fi

upsert_variable() {
  local key="$1"
  local value="$2"
  if GL_HOST="$GL_HOST" glab variable get --repo "$GITLAB_PROJECT_PATH" "$key" >/dev/null 2>&1; then
    GL_HOST="$GL_HOST" glab variable update --repo "$GITLAB_PROJECT_PATH" "$key" "$value" >/dev/null
  else
    GL_HOST="$GL_HOST" glab variable set --repo "$GITLAB_PROJECT_PATH" "$key" --value "$value" >/dev/null
  fi
}

upsert_variable AZURE_CLIENT_ID "$app_id"
upsert_variable AZURE_TENANT_ID "$tenant_id"
upsert_variable AZURE_SUBSCRIPTION_ID "$subscription_id"
upsert_variable WHEELGUARD_AZURE_DEPLOY_ENABLED false

printf 'Deployment application client ID: %s\n' "$app_id"
printf 'Deployment service principal object ID: %s\n' "$principal_id"
printf 'Terraform input: TF_VAR_deployment_principal_id=%s\n' "$principal_id"
printf 'Next: run scripts/configure-azure-deployment-certificate.sh\n'
