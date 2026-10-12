#!/usr/bin/env bash
# Grant the narrow Microsoft Graph permission required by legacy Azure
# PostgreSQL pgaadauth releases to resolve a managed identity by display name.
#
# Security notes for the tenant administrator reviewing this script:
# - The target is an existing managed-identity service principal, not a user.
# - The only granted app role is Application.Read.All. It permits directory
#   application metadata reads; it does not permit Graph writes.
# - The script never creates credentials, prints tokens, or changes Azure RBAC.
# - A Privileged Role Administrator or Global Administrator must run it because
#   granting a Microsoft Graph application role requires tenant admin consent.
# - Repeated execution is safe: an existing assignment is detected and kept.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  grant-postgres-graph-access.sh \
    --cloud <Azure cloud> \
    --tenant-id <Entra tenant UUID> \
    --principal-id <PostgreSQL managed-identity object UUID>

Example for Azure Government:
  grant-postgres-graph-access.sh \
    --cloud AzureUSGovernment \
    --tenant-id 00000000-0000-0000-0000-000000000000 \
    --principal-id 11111111-1111-1111-1111-111111111111

The script uses an existing Azure CLI login for the requested tenant. If no
matching login exists, it starts the normal interactive browser login flow.
EOF
}

cloud_name=""
tenant_id=""
principal_id=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cloud)
      cloud_name="${2:-}"
      shift 2
      ;;
    --tenant-id)
      tenant_id="${2:-}"
      shift 2
      ;;
    --principal-id)
      principal_id="${2:-}"
      shift 2
      ;;
    --help | -h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$cloud_name" || -z "$tenant_id" || -z "$principal_id" ]]; then
  usage >&2
  exit 2
fi

for command in az jq; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command is not installed: $command" >&2
    exit 1
  fi
done

# Selecting the cloud before login ensures both the authority and Microsoft
# Graph audience use the sovereign-cloud endpoints with normal TLS validation.
az cloud set --name "$cloud_name"

signed_in_tenant="$(az account show --query tenantId --output tsv 2>/dev/null || true)"
if [[ "$signed_in_tenant" != "$tenant_id" ]]; then
  echo "Signing in to tenant ${tenant_id} using the interactive browser flow..."
  az login --tenant "$tenant_id" --allow-no-subscriptions --output none
  signed_in_tenant="$(az account show --query tenantId --output tsv)"
fi

if [[ "$signed_in_tenant" != "$tenant_id" ]]; then
  echo "Azure CLI is signed into tenant ${signed_in_tenant}, not ${tenant_id}" >&2
  exit 1
fi

graph_app_id="00000003-0000-0000-c000-000000000000"
graph_resource="$(az cloud show --query endpoints.microsoftGraphResourceId --output tsv)"
graph_api="${graph_resource%/}/v1.0"

if [[ -z "$graph_resource" ]]; then
  echo "The selected Azure cloud does not publish a Microsoft Graph endpoint" >&2
  exit 1
fi

# Confirm the target exists before looking up or changing any assignment.
target_name="$(az rest \
  --method get \
  --resource "$graph_resource" \
  --url "${graph_api}/servicePrincipals/${principal_id}?\$select=id,displayName,servicePrincipalType" \
  --query displayName --output tsv)"

graph_service_principal="$(az rest \
  --method get \
  --resource "$graph_resource" \
  --url "${graph_api}/servicePrincipals?\$filter=appId%20eq%20'${graph_app_id}'" \
  --query 'value[0].id' --output tsv)"

application_read_role="$(az rest \
  --method get \
  --resource "$graph_resource" \
  --url "${graph_api}/servicePrincipals/${graph_service_principal}" \
  --query "appRoles[?value=='Application.Read.All' && contains(allowedMemberTypes, 'Application')].id | [0]" \
  --output tsv)"

if [[ -z "$graph_service_principal" || -z "$application_read_role" ]]; then
  echo "Could not resolve the Microsoft Graph Application.Read.All application role" >&2
  exit 1
fi

existing="$(az rest \
  --method get \
  --resource "$graph_resource" \
  --url "${graph_api}/servicePrincipals/${principal_id}/appRoleAssignments" \
  --query "length(value[?resourceId=='${graph_service_principal}' && appRoleId=='${application_read_role}'])" \
  --output tsv)"

if [[ "$existing" != "0" ]]; then
  echo "Microsoft Graph Application.Read.All is already assigned to ${target_name} (${principal_id})"
  exit 0
fi

body="$(jq -nc \
  --arg principal_id "$principal_id" \
  --arg resource_id "$graph_service_principal" \
  --arg app_role_id "$application_read_role" \
  '{principalId:$principal_id,resourceId:$resource_id,appRoleId:$app_role_id}')"

error_file="$(mktemp)"
trap 'rm -f "$error_file"' EXIT
if ! az rest \
  --method post \
  --resource "$graph_resource" \
  --url "${graph_api}/servicePrincipals/${principal_id}/appRoleAssignments" \
  --headers Content-Type=application/json \
  --body "$body" \
  --output none 2>"$error_file"; then
  cat "$error_file" >&2
  echo >&2
  echo "Grant failed. The signed-in account must be an active Privileged Role Administrator" >&2
  echo "or Global Administrator in tenant ${tenant_id}; Azure subscription Owner is insufficient." >&2
  exit 1
fi

# Read the assignment back so a successful exit means the requested permission
# is observable, rather than merely that Microsoft Graph accepted the request.
verified="$(az rest \
  --method get \
  --resource "$graph_resource" \
  --url "${graph_api}/servicePrincipals/${principal_id}/appRoleAssignments" \
  --query "length(value[?resourceId=='${graph_service_principal}' && appRoleId=='${application_read_role}'])" \
  --output tsv)"

if [[ "$verified" == "0" ]]; then
  echo "Microsoft Graph accepted the request, but the assignment could not be verified" >&2
  exit 1
fi

echo "Assigned Microsoft Graph Application.Read.All to ${target_name} (${principal_id})"
