terraform {
  backend "azurerm" {}

  required_providers {
    azapi   = { source = "Azure/azapi", version = "~> 2.8" }
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
  }
}

provider "azurerm" {
  features {}
  environment = "usgovernment"
}

provider "azurerm" {
  alias = "network"
  features {}
  environment     = "usgovernment"
  subscription_id = var.network_subscription_id
}

provider "azapi" {
  environment = "usgovernment"
}

locals {
  virtual_network_parts = split("/", var.virtual_network_id)
  virtual_network_name  = local.virtual_network_parts[8]
  virtual_network_rg    = local.virtual_network_parts[4]
}

resource "azurerm_resource_group" "wheelguard" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

resource "azurerm_subnet" "container_apps" {
  provider             = azurerm.network
  name                 = var.container_apps_subnet_name
  resource_group_name  = local.virtual_network_rg
  virtual_network_name = local.virtual_network_name
  address_prefixes     = [var.container_apps_subnet_prefix]

  delegation {
    name = "container-apps"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "postgres" {
  provider             = azurerm.network
  name                 = var.postgres_subnet_name
  resource_group_name  = local.virtual_network_rg
  virtual_network_name = local.virtual_network_name
  address_prefixes     = [var.postgres_subnet_prefix]
  service_endpoints    = ["Microsoft.Storage"]

  delegation {
    name = "postgres-flexible-server"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "private_endpoints" {
  provider                          = azurerm.network
  name                              = var.private_endpoint_subnet_name
  resource_group_name               = local.virtual_network_rg
  virtual_network_name              = local.virtual_network_name
  address_prefixes                  = [var.private_endpoint_subnet_prefix]
  private_endpoint_network_policies = "Disabled"
}

resource "azurerm_private_dns_zone" "postgres" {
  provider            = azurerm.network
  name                = var.postgres_private_dns_zone_name
  resource_group_name = var.private_dns_zone_resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgres" {
  provider              = azurerm.network
  name                  = "${var.name}-postgres-vnet"
  resource_group_name   = var.private_dns_zone_resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.postgres.name
  virtual_network_id    = var.virtual_network_id
  registration_enabled  = false
  tags                  = var.tags
}

resource "azurerm_private_dns_zone" "acr" {
  provider            = azurerm.network
  name                = var.acr_private_dns_zone_name
  resource_group_name = var.private_dns_zone_resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "acr" {
  provider              = azurerm.network
  name                  = "${var.name}-acr-vnet"
  resource_group_name   = var.private_dns_zone_resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.acr.name
  virtual_network_id    = var.virtual_network_id
  registration_enabled  = false
  tags                  = var.tags
}

data "azurerm_private_dns_zone" "blob" {
  provider            = azurerm.network
  name                = var.blob_private_dns_zone_name
  resource_group_name = var.blob_private_dns_zone_resource_group_name
}

module "wheelguard" {
  source     = "../../modules/azure"
  depends_on = [azurerm_resource_group.wheelguard]
  providers = {
    azurerm         = azurerm
    azurerm.network = azurerm.network
  }

  name                                 = var.name
  resource_group_name                  = azurerm_resource_group.wheelguard.name
  location                             = var.location
  container_apps_subnet_id             = azurerm_subnet.container_apps.id
  postgres_subnet_id                   = azurerm_subnet.postgres.id
  private_endpoint_subnet_id           = azurerm_subnet.private_endpoints.id
  postgres_private_dns_zone_id         = azurerm_private_dns_zone.postgres.id
  blob_private_dns_zone_id             = data.azurerm_private_dns_zone.blob.id
  acr_private_dns_zone_id              = azurerm_private_dns_zone.acr.id
  virtual_network_id                   = var.virtual_network_id
  private_dns_zone_name                = var.hostname
  private_dns_zone_resource_group_name = var.private_dns_zone_resource_group_name
  hostname                             = var.hostname
  documentation_url                    = var.documentation_url
  certificate_key_vault_secret_url     = var.certificate_key_vault_secret_url
  key_vault_id                         = var.key_vault_id
  key_vault_secret_resource_ids        = var.key_vault_secret_resource_ids
  entra_client_secret_key_vault_url    = var.entra_client_secret_key_vault_url
  enable_tls                           = var.enable_tls
  enable_entra_admin                   = false
  admin_token_key_vault_secret_url     = var.admin_token_key_vault_secret_url
  admin_token_actor                    = var.admin_token_actor
  temporary_schema_runtime_enabled     = var.temporary_schema_runtime_enabled
  deploy_workloads                     = var.deploy_workloads
  managed_token_auth_enabled           = var.managed_token_auth_enabled
  acr_task_agent_ip_ranges             = var.acr_task_agent_ip_ranges
  storage_replication_type             = "LRS"
  storage_blob_dns_suffix              = "blob.core.usgovcloudapi.net"
  postgres_token_scope                 = "https://ossrdbms-aad.database.usgovcloudapi.net/.default"
  image                                = var.image
  entra_client_id                      = var.entra_client_id
  entra_tenant_id                      = var.entra_tenant_id
  entra_authority_host                 = "https://login.microsoftonline.us"
  entra_allowed_group_ids              = var.entra_allowed_group_ids
  publisher_oidc_issuer                = var.publisher_oidc_issuer
  publisher_oidc_projects              = var.publisher_oidc_projects
  deployment_principal_id              = var.deployment_principal_id
  tags                                 = var.tags
}

output "container_registry_name" { value = module.wheelguard.container_registry_name }
output "container_registry_login_server" { value = module.wheelguard.container_registry_login_server }
output "application_url" { value = module.wheelguard.application_url }
output "container_app_name" { value = module.wheelguard.container_app_name }
output "schema_upgrade_job_name" { value = module.wheelguard.schema_upgrade_job_name }
output "schema_identity_principal_id" { value = module.wheelguard.schema_identity_principal_id }
output "advisory_refresh_job_name" { value = module.wheelguard.advisory_refresh_job_name }
