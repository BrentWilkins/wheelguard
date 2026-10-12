#!/usr/bin/env bash
set -euo pipefail

: "${GL_HOST:?Set GL_HOST to the GitLab hostname}"
: "${GITLAB_PROJECT_PATH:?Set GITLAB_PROJECT_PATH to the target GitLab project}"
: "${AZURE_DEPLOYMENT_APP_NAME:=wheelguard-gitlab-deploy}"
: "${AZURE_CLIENT_CERTIFICATE_DAYS:=365}"

command -v az >/dev/null
command -v glab >/dev/null
command -v openssl >/dev/null

if [[ ! "$AZURE_CLIENT_CERTIFICATE_DAYS" =~ ^[0-9]+$ ]] || ((AZURE_CLIENT_CERTIFICATE_DAYS < 30)); then
  printf 'AZURE_CLIENT_CERTIFICATE_DAYS must be an integer of at least 30\n' >&2
  exit 2
fi

umask 077
certificate_dir="$(mktemp -d)"
private_key="$certificate_dir/private-key.pem"
public_certificate="$certificate_dir/public-certificate.pem"
client_certificate="$certificate_dir/client-certificate.pem"
cleanup() {
  rm -f "$private_key" "$public_certificate" "$client_certificate"
  rmdir "$certificate_dir"
}
trap cleanup EXIT

app_id="$(az ad app list --display-name "$AZURE_DEPLOYMENT_APP_NAME" --query '[0].appId' --output tsv)"
if [[ -z "$app_id" ]]; then
  printf 'Entra application %s does not exist; run bootstrap-azure-deployment-identity.sh first\n' \
    "$AZURE_DEPLOYMENT_APP_NAME" >&2
  exit 1
fi

credential_name="gitlab-certificate-$(date -u +%Y%m%d)"
end_date="$(date -u -d "+${AZURE_CLIENT_CERTIFICATE_DAYS} days" +%Y-%m-%dT%H:%M:%SZ)"
openssl req -x509 -newkey rsa:3072 -sha256 -nodes \
  -days "$AZURE_CLIENT_CERTIFICATE_DAYS" \
  -subj "/CN=$AZURE_DEPLOYMENT_APP_NAME" \
  -keyout "$private_key" \
  -out "$public_certificate" \
  >/dev/null 2>&1
cp "$private_key" "$client_certificate"
openssl x509 -in "$public_certificate" -outform PEM >>"$client_certificate"
chmod 600 "$client_certificate"

# --cert receives only the public certificate. --append preserves the old
# certificate during the rotation overlap period.
az ad app credential reset \
  --id "$app_id" \
  --append \
  --cert "@$public_certificate" \
  --display-name "$credential_name" \
  --end-date "$end_date" \
  --output none

if GL_HOST="$GL_HOST" \
  glab variable get --repo "$GITLAB_PROJECT_PATH" AZURE_CLIENT_CERTIFICATE >/dev/null 2>&1; then
  GL_HOST="$GL_HOST" \
    glab variable update --repo "$GITLAB_PROJECT_PATH" AZURE_CLIENT_CERTIFICATE \
      --type file --protected --raw <"$client_certificate" >/dev/null
else
  GL_HOST="$GL_HOST" \
    glab variable set --repo "$GITLAB_PROJECT_PATH" AZURE_CLIENT_CERTIFICATE \
      --type file --protected --raw <"$client_certificate" >/dev/null
fi

printf 'Registered certificate %s with expiration %s and updated protected GitLab file variable.\n' \
  "$credential_name" "$end_date"
printf 'Keep the previous credential through a successful pipeline before removing it.\n'
