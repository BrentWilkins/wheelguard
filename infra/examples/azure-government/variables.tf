variable "name" {
  type    = string
  default = "wheelguard"
}
variable "resource_group_name" {
  type    = string
  default = "wheelguard-dev-rg"
}
variable "location" { type = string }
variable "network_subscription_id" { type = string }
variable "virtual_network_id" { type = string }
variable "private_dns_zone_resource_group_name" { type = string }
variable "container_apps_subnet_name" {
  type    = string
  default = "WheelguardContainerAppsSubnet"
}
variable "container_apps_subnet_prefix" { type = string }
variable "postgres_subnet_name" {
  type    = string
  default = "WheelguardPostgresSubnet"
}
variable "postgres_subnet_prefix" { type = string }
variable "private_endpoint_subnet_name" {
  type    = string
  default = "WheelguardPrivateEndpointSubnet"
}
variable "private_endpoint_subnet_prefix" { type = string }
variable "postgres_private_dns_zone_name" {
  type    = string
  default = "wheelguard.postgres.database.usgovcloudapi.net"
}
variable "acr_private_dns_zone_name" {
  type    = string
  default = "privatelink.azurecr.us"
}
variable "blob_private_dns_zone_name" {
  type    = string
  default = "privatelink.blob.core.usgovcloudapi.net"
}
variable "blob_private_dns_zone_resource_group_name" { type = string }
variable "hostname" { type = string }
variable "documentation_url" {
  type    = string
  default = null
}
variable "certificate_key_vault_secret_url" {
  type    = string
  default = null
}
variable "key_vault_id" {
  type    = string
  default = null
}
variable "key_vault_secret_resource_ids" {
  type    = set(string)
  default = []
}
variable "entra_client_secret_key_vault_url" {
  type    = string
  default = null
}
variable "enable_tls" {
  description = "Bind the private hostname to the configured Key Vault TLS certificate."
  type        = bool
  default     = false
}
variable "admin_token_key_vault_secret_url" {
  type    = string
  default = null
}
variable "admin_token_actor" {
  type    = string
  default = "temporary-admin"
}
variable "temporary_schema_runtime_enabled" {
  type    = bool
  default = false
}
variable "image" { type = string }
variable "deploy_workloads" {
  type    = bool
  default = false
}
variable "managed_token_auth_enabled" {
  description = "Require individually managed repository tokens for package reads."
  type        = bool
  default     = false
}
variable "acr_task_agent_ip_ranges" {
  description = "Approved Microsoft-hosted ACR Tasks agent egress CIDRs for this region."
  type        = set(string)
  default     = []
}
variable "entra_client_id" {
  type    = string
  default = null
}
variable "entra_tenant_id" { type = string }
variable "entra_allowed_group_ids" {
  type    = list(string)
  default = []
}
variable "publisher_oidc_issuer" { type = string }
variable "publisher_oidc_projects" {
  description = "GitLab project paths authorized to publish from protected refs; use [\"*\"] for all projects."
  type        = list(string)
}
variable "deployment_principal_id" { type = string }
variable "tags" {
  type    = map(string)
  default = {}
}
