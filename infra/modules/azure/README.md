# Wheelguard Azure module

This module deploys Wheelguard into an internal Azure Container Apps environment with Azure Database for PostgreSQL
and Blob Storage. It contains no organization-specific subscriptions, hostnames, network IDs, or GitLab projects.

The caller supplies existing workload subnets and central private DNS zone IDs. The Container Apps subnet must have
enough address space for the environment; the PostgreSQL subnet must be delegated to
`Microsoft.DBforPostgreSQL/flexibleServers`; Blob and ACR use a dedicated private-endpoint subnet.
Pass an `azurerm.network` provider alias for the subscription that owns the VNet and application private DNS zone.

`wheelguard-schema-upgrade` is a schema upgrade job, not an import or data-movement job. The first execution creates an
empty database schema. Later executions apply only new, numbered structural upgrades under a PostgreSQL advisory lock.
Run it before directing traffic to a new application revision.

The application hostname is private DNS and package reads are credential-free by default for VPN users. Set the module
input `managed_token_auth_enabled = true` to require individually revocable repository tokens stored as digests in
PostgreSQL; create, list, and revoke them with `wheelguard token` inside the application container. Container Apps
authentication protects `/admin/*` with Entra ID. `/upload/` independently validates GitLab CI ID tokens issued to an
approved project and protected ref.
Set `documentation_url` to link the neutral landing page to your deployment's user guide.

Start with `minimum_replicas = 1` and `postgres_ha_mode = "Disabled"`. Moving to two replicas and
`postgres_ha_mode = "ZoneRedundant"` does not require a data migration.

The PostgreSQL Entra audience defaults to Microsoft's documented OSS RDBMS scope. Override `postgres_token_scope` only
when the selected sovereign cloud and tenant configuration require a different audience.
The schema job prefers creating the application database role by managed-identity object ID, avoiding a Microsoft
Graph lookup. Older PostgreSQL environments that do not expose `pgaadauth_create_principal_with_oid` fall back to
`pgaadauth_create_principal`. The module attaches the schema identity to the PostgreSQL server for this purpose; grant
that identity the Microsoft Graph `Application.Read.All` application role once, using a tenant administrator. This
directory grant is intentionally outside the module so ordinary infrastructure automation does not receive permission
to modify tenant-wide Graph role assignments. The `schema_identity_principal_id` output identifies the principal to
grant. Environments with the OID function do not use the Graph permission.
Set `entra_authority_host` to the sovereign-cloud authority; the Azure Government example uses
`https://login.microsoftonline.us`.

The module expects versioned Key Vault secret URLs for the TLS certificate and Entra application secret. Its managed
identity receives read access; certificate and secret values never enter Terraform state.

For shared vaults, set `key_vault_secret_resource_ids` to the exact certificate, Entra, and temporary administrator
secret resource IDs. This keeps `Key Vault Secrets User` grants scoped to Wheelguard secrets instead of the whole vault.
The optional `admin_token_key_vault_secret_url` enables a temporary Key Vault-backed administrator token, while
`temporary_schema_runtime_enabled` explicitly models the elevated database-identity bridge used only until the normal
application principal can be created.

For an initial private-network bootstrap, set `enable_tls = false` and `enable_entra_admin = false`. The custom hostname
then serves HTTP and `/admin/*` remains disabled, so no Key Vault or certificate access is required. Re-enable both after
provisioning the certificate and Entra application; this changes ingress and authentication configuration without moving
PostgreSQL or Blob data.

On a new registry, first apply with `deploy_workloads = false`. This creates ACR and the backing infrastructure without
requiring an image. Build Wheelguard into that ACR, set `image` to its digest reference, and apply again with
`deploy_workloads = true` to create the application and scheduled jobs.

Blob storage defaults to `ZRS`; the Azure Government example selects `LRS` because zone-redundant Standard storage is
not available in every sovereign-cloud region.
The storage account, Blob service, and artifact container use ARM-only AzAPI resources so provisioning never requires a
shared key or data-plane access before the private endpoint exists.

ACR keeps a private endpoint for Container Apps pulls. Its public service endpoint is enabled with a default-deny
firewall solely because Microsoft-hosted ACR Tasks agents cannot enter the VNet; Azure trusted-services and Tasks bypass
are enabled, while arbitrary public clients remain denied. When quick-build agents cannot use that bypass, provide only
their regional egress CIDRs through `acr_task_agent_ip_ranges`; prefer a VNet agent pool for sustained production use.
