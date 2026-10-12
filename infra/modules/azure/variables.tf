variable "name" {
  description = "Short DNS-safe deployment name."
  type        = string
  default     = "wheelguard"
}

variable "resource_group_name" {
  description = "Existing resource group for Wheelguard resources."
  type        = string
}

variable "location" {
  description = "Azure region supported by Container Apps and PostgreSQL Flexible Server."
  type        = string
}

variable "container_apps_subnet_id" {
  description = "Delegated/infrastructure subnet for the internal Container Apps environment."
  type        = string
}

variable "postgres_subnet_id" {
  description = "Subnet delegated to Microsoft.DBforPostgreSQL/flexibleServers."
  type        = string
}

variable "private_endpoint_subnet_id" {
  description = "Subnet for Blob and ACR private endpoints."
  type        = string
}

variable "postgres_private_dns_zone_id" {
  description = "Private DNS zone ID for PostgreSQL Flexible Server."
  type        = string
}

variable "blob_private_dns_zone_id" {
  description = "Existing privatelink.blob private DNS zone ID."
  type        = string
}

variable "acr_private_dns_zone_id" {
  description = "Existing privatelink.azurecr.io private DNS zone ID."
  type        = string
}

variable "private_dns_zone_name" {
  description = "Dedicated private zone for the Wheelguard hostname, for example pypi.example.com."
  type        = string
}

variable "private_dns_zone_resource_group_name" {
  description = "Resource group in which to create the application private DNS zone."
  type        = string
}

variable "virtual_network_id" {
  description = "VPN-connected VNet linked to the application private DNS zone."
  type        = string
}

variable "hostname" {
  description = "Private HTTPS hostname exposed to package clients."
  type        = string
}

variable "documentation_url" {
  description = "Optional public URL linked as the Wheelguard user guide."
  type        = string
  default     = null
}

variable "certificate_key_vault_secret_url" {
  description = "Versioned Key Vault secret URL containing the hostname certificate."
  type        = string
  default     = null
}

variable "key_vault_id" {
  description = "Key Vault holding the TLS certificate and Entra application secret."
  type        = string
  default     = null
}

variable "key_vault_secret_resource_ids" {
  description = "Exact Key Vault secret resource IDs the application identity may read; omit only for a dedicated vault."
  type        = set(string)
  default     = []
}

variable "entra_client_secret_key_vault_url" {
  description = "Versioned Key Vault secret URL for the Container Apps Entra application secret."
  type        = string
  default     = null
}

variable "enable_tls" {
  description = "Bind the custom hostname with a Key Vault TLS certificate. Disable only for private HTTP bootstrap."
  type        = bool
  default     = true
}

variable "enable_entra_admin" {
  description = "Enable Easy Auth and the Wheelguard administrator interface."
  type        = bool
  default     = true
}

variable "admin_token_key_vault_secret_url" {
  description = "Versioned Key Vault secret URL for the temporary administrator HTTP Basic token."
  type        = string
  default     = null
}

variable "admin_token_actor" {
  description = "Audit actor recorded for the temporary administrator token."
  type        = string
  default     = "temporary-admin"
}

variable "temporary_schema_runtime_enabled" {
  description = "Temporarily run the web and advisory workloads with the schema identity until the app database principal exists."
  type        = bool
  default     = false
}

variable "image" {
  description = "Immutable Wheelguard container image reference, preferably pinned by digest."
  type        = string
}

variable "deploy_workloads" {
  description = "Create the Container App and jobs after the first Wheelguard image exists in ACR."
  type        = bool
  default     = true
}

variable "managed_token_auth_enabled" {
  description = "Require individually managed PostgreSQL tokens for package reads in addition to private network access."
  type        = bool
  default     = false
}

variable "acr_task_agent_ip_ranges" {
  description = "Narrow public CIDRs used by Microsoft-hosted ACR Tasks agents when no private agent pool is configured."
  type        = set(string)
  default     = []

  validation {
    condition     = alltrue([for prefix in var.acr_task_agent_ip_ranges : can(cidrnetmask(prefix))])
    error_message = "acr_task_agent_ip_ranges must contain valid CIDR prefixes."
  }
}

variable "entra_client_id" {
  description = "Entra application client ID used by Container Apps authentication for /admin paths."
  type        = string
  default     = null
}

variable "entra_tenant_id" {
  description = "Entra tenant containing the administrator application."
  type        = string
}

variable "entra_authority_host" {
  description = "Microsoft Entra authority host for the selected Azure cloud, without a trailing slash."
  type        = string
  default     = "https://login.microsoftonline.com"
  validation {
    condition     = startswith(var.entra_authority_host, "https://") && !endswith(var.entra_authority_host, "/")
    error_message = "entra_authority_host must be an HTTPS URL without a trailing slash."
  }
}

variable "entra_allowed_group_ids" {
  description = "Entra group object IDs authorized to administer Wheelguard."
  type        = list(string)
  default     = []
}

variable "publisher_oidc_issuer" {
  description = "HTTPS issuer for GitLab CI ID tokens."
  type        = string
}

variable "publisher_oidc_projects" {
  description = "GitLab project paths authorized to publish from protected refs; use [\"*\"] to authorize all projects."
  type        = list(string)
}

variable "publisher_oidc_audience" {
  description = "Required audience for GitLab publishing ID tokens."
  type        = string
  default     = "wheelguard-publisher"
}

variable "deployment_principal_id" {
  description = "Object ID of the GitLab deployment service principal."
  type        = string
}

variable "minimum_replicas" {
  description = "Minimum web replicas; use 1 initially and 2 or more for application HA."
  type        = number
  default     = 1
}

variable "maximum_replicas" {
  description = "Maximum web replicas."
  type        = number
  default     = 3
}

variable "postgres_sku_name" {
  description = "PostgreSQL Flexible Server SKU."
  type        = string
  default     = "B_Standard_B1ms"
}

variable "postgres_storage_mb" {
  description = "PostgreSQL storage allocation."
  type        = number
  default     = 32768
}

variable "storage_replication_type" {
  description = "Blob storage replication type supported by the selected Azure region."
  type        = string
  default     = "ZRS"
  validation {
    condition     = contains(["LRS", "ZRS", "GRS", "RAGRS", "GZRS", "RAGZRS"], var.storage_replication_type)
    error_message = "storage_replication_type must be a supported Standard storage replication type."
  }
}

variable "storage_blob_dns_suffix" {
  description = "Blob service DNS suffix for the selected Azure cloud."
  type        = string
  default     = "blob.core.windows.net"
}

variable "postgres_ha_mode" {
  description = "Disabled initially; use ZoneRedundant when database HA is required."
  type        = string
  default     = "Disabled"
  validation {
    condition     = contains(["Disabled", "SameZone", "ZoneRedundant"], var.postgres_ha_mode)
    error_message = "postgres_ha_mode must be Disabled, SameZone, or ZoneRedundant."
  }
}

variable "postgres_database_name" {
  type    = string
  default = "wheelguard"
}

variable "postgres_token_scope" {
  description = "Azure Database for PostgreSQL Entra token scope for the selected cloud."
  type        = string
  default     = "https://ossrdbms-aad.database.windows.net/.default"
}

variable "upstream_url" {
  type    = string
  default = "https://pypi.org/simple/"
}

variable "osv_url" {
  type    = string
  default = "https://api.osv.dev/v1/querybatch"
}

variable "tags" {
  type    = map(string)
  default = {}
}
