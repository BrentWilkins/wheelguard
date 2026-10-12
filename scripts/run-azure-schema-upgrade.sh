#!/usr/bin/env bash
set -euo pipefail

: "${WHEELGUARD_RESOURCE_GROUP:?Set WHEELGUARD_RESOURCE_GROUP}"
: "${WHEELGUARD_SCHEMA_JOB:?Set WHEELGUARD_SCHEMA_JOB}"

execution_name="$(az containerapp job start \
  --resource-group "$WHEELGUARD_RESOURCE_GROUP" \
  --name "$WHEELGUARD_SCHEMA_JOB" \
  --query name --output tsv)"

if [[ -z "$execution_name" ]]; then
  echo "Azure did not return a schema upgrade execution name" >&2
  exit 1
fi

for _ in {1..120}; do
  status="$(az containerapp job execution show \
    --resource-group "$WHEELGUARD_RESOURCE_GROUP" \
    --name "$WHEELGUARD_SCHEMA_JOB" \
    --job-execution-name "$execution_name" \
    --query properties.status --output tsv)"
  case "$status" in
    Succeeded)
      echo "Schema upgrade succeeded: $execution_name"
      exit 0
      ;;
    Failed | Degraded | Canceled)
      echo "Schema upgrade failed with status $status: $execution_name" >&2
      exit 1
      ;;
  esac
  sleep 5
done

echo "Timed out waiting for schema upgrade: $execution_name" >&2
exit 1
