data "azurerm_resource_group" "this" {
  name = var.resource_group_name
}

locals {
  compact_name           = replace(lower(var.name), "-", "")
  storage_account_name   = substr("${local.compact_name}${substr(md5(data.azurerm_resource_group.this.id), 0, 8)}", 0, 24)
  storage_account_url    = "https://${local.storage_account_name}.${var.storage_blob_dns_suffix}"
  runtime_identity       = var.temporary_schema_runtime_enabled ? azurerm_user_assigned_identity.schema : azurerm_user_assigned_identity.app
  runtime_identity_ids   = var.temporary_schema_runtime_enabled ? [azurerm_user_assigned_identity.app.id, azurerm_user_assigned_identity.schema.id] : [azurerm_user_assigned_identity.app.id]
  database_url           = "host=${azurerm_postgresql_flexible_server.this.fqdn} dbname=${var.postgres_database_name} user=${local.runtime_identity.name} sslmode=require"
  broad_key_vault_access = (var.enable_tls || var.enable_entra_admin || var.admin_token_key_vault_secret_url != null) && length(var.key_vault_secret_resource_ids) == 0
  common_env = merge({
    AZURE_CLIENT_ID                       = local.runtime_identity.client_id
    WHEELGUARD_DATABASE_URL               = local.database_url
    WHEELGUARD_DATABASE_TOKEN_SCOPE       = var.postgres_token_scope
    WHEELGUARD_AZURE_STORAGE_ACCOUNT_URL  = local.storage_account_url
    WHEELGUARD_AZURE_ARTIFACT_CONTAINER   = azapi_resource.artifacts.name
    WHEELGUARD_UPSTREAM_URL               = var.upstream_url
    WHEELGUARD_PUBLIC_URL                 = "${var.enable_tls ? "https" : "http"}://${var.hostname}"
    WHEELGUARD_ALLOWED_ARTIFACT_HOSTS     = "files.pythonhosted.org"
    WHEELGUARD_OSV_URL                    = var.osv_url
    WHEELGUARD_OSV_ENABLED                = "true"
    WHEELGUARD_TRUST_PRIVATE_INGRESS      = "true"
    WHEELGUARD_ENTRA_ADMIN_ENABLED        = tostring(var.enable_entra_admin)
    WHEELGUARD_MANAGED_TOKEN_AUTH_ENABLED = tostring(var.managed_token_auth_enabled)
    WHEELGUARD_PUBLISHER_OIDC_ISSUER      = var.publisher_oidc_issuer
    WHEELGUARD_PUBLISHER_OIDC_AUDIENCE    = var.publisher_oidc_audience
    WHEELGUARD_PUBLISHER_OIDC_PROJECTS    = join(",", var.publisher_oidc_projects)
    WHEELGUARD_HOST                       = "0.0.0.0"
    WHEELGUARD_PORT                       = "8000"
    }, var.documentation_url == null ? {} : {
    WHEELGUARD_DOCUMENTATION_URL = var.documentation_url
    }, var.temporary_schema_runtime_enabled ? {} : {
    WHEELGUARD_DATABASE_APP_PRINCIPAL = azurerm_user_assigned_identity.app.name
    WHEELGUARD_DATABASE_APP_OBJECT_ID = azurerm_user_assigned_identity.app.principal_id
  })
  app_env = merge(local.common_env, var.admin_token_key_vault_secret_url == null ? {} : {
    WHEELGUARD_ADMIN_TOKEN_ACTOR = var.admin_token_actor
  })
}

resource "azurerm_log_analytics_workspace" "this" {
  name                = "${var.name}-logs"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = var.tags
}

resource "azurerm_user_assigned_identity" "app" {
  name                = "${var.name}-app"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.this.name
  tags                = var.tags
}

resource "azurerm_user_assigned_identity" "schema" {
  name                = "${var.name}-schema"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.this.name
  tags                = var.tags
}

resource "azapi_resource" "storage" {
  type      = "Microsoft.Storage/storageAccounts@2023-05-01"
  name      = local.storage_account_name
  parent_id = data.azurerm_resource_group.this.id
  location  = var.location
  tags      = var.tags
  body = {
    kind = "StorageV2"
    sku  = { name = "Standard_${var.storage_replication_type}" }
    properties = {
      accessTier                   = "Hot"
      allowBlobPublicAccess        = false
      allowCrossTenantReplication  = false
      allowSharedKeyAccess         = false
      defaultToOAuthAuthentication = true
      minimumTlsVersion            = "TLS1_2"
      publicNetworkAccess          = "Disabled"
      supportsHttpsTrafficOnly     = true
    }
  }
}

resource "azapi_resource" "blob_service" {
  type      = "Microsoft.Storage/storageAccounts/blobServices@2023-05-01"
  name      = "default"
  parent_id = azapi_resource.storage.id
  body = {
    properties = {
      isVersioningEnabled            = true
      deleteRetentionPolicy          = { enabled = true, days = 30 }
      containerDeleteRetentionPolicy = { enabled = true, days = 30 }
    }
  }
}

resource "azapi_resource" "artifacts" {
  type      = "Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01"
  name      = "artifacts"
  parent_id = azapi_resource.blob_service.id
  body      = { properties = { publicAccess = "None" } }
}

resource "azurerm_private_endpoint" "blob" {
  name                = "${var.name}-blob-pe"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.this.name
  subnet_id           = var.private_endpoint_subnet_id
  tags                = var.tags
  private_service_connection {
    name                           = "blob"
    private_connection_resource_id = azapi_resource.storage.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "blob"
    private_dns_zone_ids = [var.blob_private_dns_zone_id]
  }
}

resource "azurerm_container_registry" "this" {
  name                = substr("${local.compact_name}${substr(md5(var.resource_group_name), 0, 8)}", 0, 50)
  resource_group_name = data.azurerm_resource_group.this.name
  location            = var.location
  sku                 = "Premium"
  admin_enabled       = false
  # Hosted ACR Tasks reaches the registry through its public service endpoint.
  # Keep that endpoint default-deny and permit only Azure trusted services and
  # Tasks; Container Apps continues to pull through the private endpoint.
  public_network_access_enabled         = true
  network_rule_bypass_option            = "AzureServices"
  network_rule_bypass_for_tasks_enabled = true
  tags                                  = var.tags

  network_rule_set {
    default_action = "Deny"
    ip_rule = [
      for prefix in var.acr_task_agent_ip_ranges : {
        action   = "Allow"
        ip_range = prefix
      }
    ]
  }
}

resource "azurerm_private_endpoint" "acr" {
  name                = "${var.name}-acr-pe"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.this.name
  subnet_id           = var.private_endpoint_subnet_id
  tags                = var.tags
  private_service_connection {
    name                           = "acr"
    private_connection_resource_id = azurerm_container_registry.this.id
    subresource_names              = ["registry"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "acr"
    private_dns_zone_ids = [var.acr_private_dns_zone_id]
  }
}

resource "azurerm_role_assignment" "app_blob" {
  scope                = azapi_resource.storage.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

resource "azurerm_role_assignment" "app_acr" {
  scope                = azurerm_container_registry.this.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

resource "azurerm_role_assignment" "app_key_vault" {
  count                = local.broad_key_vault_access ? 1 : 0
  scope                = coalesce(var.key_vault_id, data.azurerm_resource_group.this.id)
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

resource "azurerm_role_assignment" "app_key_vault_secrets" {
  for_each             = var.key_vault_secret_resource_ids
  scope                = each.value
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

resource "azurerm_role_assignment" "schema_blob" {
  count                = var.temporary_schema_runtime_enabled ? 1 : 0
  scope                = azapi_resource.storage.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.schema.principal_id
}

resource "azurerm_role_assignment" "schema_acr" {
  scope                = azurerm_container_registry.this.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.schema.principal_id
}

resource "azurerm_role_assignment" "deployment_acr" {
  scope                = azurerm_container_registry.this.id
  role_definition_name = "AcrPush"
  principal_id         = var.deployment_principal_id
}

resource "azurerm_role_assignment" "deployment_acr_tasks" {
  scope                = azurerm_container_registry.this.id
  role_definition_name = "Container Registry Tasks Contributor"
  principal_id         = var.deployment_principal_id
}

resource "azurerm_role_assignment" "deployment_container_apps" {
  scope                = data.azurerm_resource_group.this.id
  role_definition_name = "Container Apps Contributor"
  principal_id         = var.deployment_principal_id
}

resource "azurerm_role_assignment" "deployment_container_app_jobs" {
  scope                = data.azurerm_resource_group.this.id
  role_definition_name = "Container Apps Jobs Contributor"
  principal_id         = var.deployment_principal_id
}

resource "azurerm_postgresql_flexible_server" "this" {
  name                          = "${var.name}-postgres"
  resource_group_name           = data.azurerm_resource_group.this.name
  location                      = var.location
  version                       = "16"
  delegated_subnet_id           = var.postgres_subnet_id
  private_dns_zone_id           = var.postgres_private_dns_zone_id
  public_network_access_enabled = false
  authentication {
    active_directory_auth_enabled = true
    password_auth_enabled         = false
    tenant_id                     = var.entra_tenant_id
  }
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.schema.id]
  }
  sku_name                     = var.postgres_sku_name
  storage_mb                   = var.postgres_storage_mb
  backup_retention_days        = 14
  geo_redundant_backup_enabled = false
  dynamic "high_availability" {
    for_each = var.postgres_ha_mode == "Disabled" ? [] : [var.postgres_ha_mode]
    content { mode = high_availability.value }
  }
  tags = var.tags
}

resource "azurerm_postgresql_flexible_server_database" "this" {
  name      = var.postgres_database_name
  server_id = azurerm_postgresql_flexible_server.this.id
  collation = "en_US.utf8"
  charset   = "UTF8"
}

resource "azurerm_postgresql_flexible_server_active_directory_administrator" "schema" {
  server_name         = azurerm_postgresql_flexible_server.this.name
  resource_group_name = data.azurerm_resource_group.this.name
  tenant_id           = var.entra_tenant_id
  object_id           = azurerm_user_assigned_identity.schema.principal_id
  principal_name      = azurerm_user_assigned_identity.schema.name
  principal_type      = "ServicePrincipal"
}

resource "azurerm_container_app_environment" "this" {
  name                           = "${var.name}-env"
  location                       = var.location
  resource_group_name            = data.azurerm_resource_group.this.name
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.this.id
  infrastructure_subnet_id       = var.container_apps_subnet_id
  internal_load_balancer_enabled = true
  zone_redundancy_enabled        = var.minimum_replicas >= 2
  tags                           = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }

  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
    minimum_count         = 0
    maximum_count         = 0
  }
}

resource "azapi_resource" "certificate" {
  count                     = var.deploy_workloads && var.enable_tls ? 1 : 0
  type                      = "Microsoft.App/managedEnvironments/certificates@2024-03-01"
  name                      = "${var.name}-tls"
  parent_id                 = azurerm_container_app_environment.this.id
  location                  = var.location
  schema_validation_enabled = false
  body = {
    properties = {
      certificateKeyVaultProperties = {
        identity    = azurerm_user_assigned_identity.app.id
        keyVaultUrl = var.certificate_key_vault_secret_url
      }
    }
  }
  depends_on = [azurerm_role_assignment.app_key_vault, azurerm_role_assignment.app_key_vault_secrets]
}

resource "azurerm_container_app" "this" {
  count                        = var.deploy_workloads ? 1 : 0
  name                         = var.name
  resource_group_name          = data.azurerm_resource_group.this.name
  container_app_environment_id = azurerm_container_app_environment.this.id
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  tags                         = var.tags
  identity {
    type         = "UserAssigned"
    identity_ids = local.runtime_identity_ids
  }
  registry {
    server   = azurerm_container_registry.this.login_server
    identity = azurerm_user_assigned_identity.app.id
  }
  dynamic "secret" {
    for_each = var.enable_entra_admin ? [1] : []
    content {
      name                = "entra-client-secret"
      identity            = azurerm_user_assigned_identity.app.id
      key_vault_secret_id = var.entra_client_secret_key_vault_url
    }
  }
  dynamic "secret" {
    for_each = var.admin_token_key_vault_secret_url == null ? [] : [1]
    content {
      name                = "temporary-admin-token"
      identity            = azurerm_user_assigned_identity.app.id
      key_vault_secret_id = var.admin_token_key_vault_secret_url
    }
  }
  ingress {
    # "External" exposes the app through the environment ingress. The environment
    # itself has an internal load balancer, so this remains private to the VNet.
    external_enabled           = true
    allow_insecure_connections = !var.enable_tls
    target_port                = 8000
    transport                  = "http"
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }
  template {
    min_replicas = var.minimum_replicas
    max_replicas = var.maximum_replicas
    container {
      name   = "wheelguard"
      image  = var.image
      cpu    = 0.5
      memory = "1Gi"
      dynamic "env" {
        for_each = local.app_env
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = var.admin_token_key_vault_secret_url == null ? [] : [1]
        content {
          name        = "WHEELGUARD_ADMIN_TOKEN"
          secret_name = "temporary-admin-token"
        }
      }
      liveness_probe {
        transport = "HTTP"
        port      = 8000
        path      = "/healthz"
      }
      readiness_probe {
        transport = "HTTP"
        port      = 8000
        path      = "/readyz"
      }
    }
  }
  depends_on = [
    azurerm_role_assignment.app_acr,
    azurerm_role_assignment.app_blob,
    azurerm_role_assignment.app_key_vault,
    azurerm_role_assignment.app_key_vault_secrets,
  ]
  lifecycle {
    precondition {
      condition = !var.enable_tls || (
        var.key_vault_id != null && var.certificate_key_vault_secret_url != null
      )
      error_message = "TLS requires key_vault_id and certificate_key_vault_secret_url."
    }
    precondition {
      condition = !var.enable_entra_admin || (
        var.key_vault_id != null &&
        var.entra_client_secret_key_vault_url != null &&
        var.entra_client_id != null &&
        length(var.entra_allowed_group_ids) > 0
      )
      error_message = "Entra administration requires Key Vault, client secret, client ID, and an administrator group."
    }
    precondition {
      condition     = var.admin_token_key_vault_secret_url == null || var.key_vault_id != null
      error_message = "Temporary administrator token authentication requires Key Vault."
    }
  }
}

resource "azapi_update_resource" "custom_domain" {
  count       = var.deploy_workloads ? 1 : 0
  type        = "Microsoft.App/containerApps@2024-03-01"
  resource_id = azurerm_container_app.this[0].id
  body = {
    properties = {
      configuration = {
        ingress = {
          customDomains = [
            {
              name          = var.hostname
              bindingType   = var.enable_tls ? "SniEnabled" : "Disabled"
              certificateId = var.enable_tls ? azapi_resource.certificate[0].id : null
            }
          ]
        }
      }
    }
  }
}

resource "azapi_resource" "auth" {
  count     = var.deploy_workloads && var.enable_entra_admin ? 1 : 0
  type      = "Microsoft.App/containerApps/authConfigs@2024-03-01"
  name      = "current"
  parent_id = azurerm_container_app.this[0].id
  body = {
    properties = {
      globalValidation = {
        excludedPaths               = ["/healthz", "/readyz", "/simple/*", "/files/*", "/upload", "/upload/"]
        redirectToProvider          = "azureactivedirectory"
        unauthenticatedClientAction = "RedirectToLoginPage"
      }
      identityProviders = {
        azureActiveDirectory = {
          enabled = true
          registration = {
            clientId                = var.entra_client_id
            clientSecretSettingName = "entra-client-secret"
            openIdIssuer            = "${var.entra_authority_host}/${var.entra_tenant_id}/v2.0"
          }
          validation = {
            defaultAuthorizationPolicy = {
              allowedApplications = [var.entra_client_id]
              allowedPrincipals = {
                groups = var.entra_allowed_group_ids
              }
            }
          }
        }
      }
      platform = { enabled = true }
    }
  }
}

resource "azurerm_private_dns_zone" "application" {
  provider            = azurerm.network
  name                = var.private_dns_zone_name
  resource_group_name = var.private_dns_zone_resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "application" {
  provider              = azurerm.network
  name                  = "${var.name}-vnet"
  resource_group_name   = var.private_dns_zone_resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.application.name
  virtual_network_id    = var.virtual_network_id
  registration_enabled  = false
  tags                  = var.tags
}

resource "azurerm_private_dns_a_record" "application" {
  provider            = azurerm.network
  name                = var.hostname == var.private_dns_zone_name ? "@" : trimsuffix(var.hostname, ".${var.private_dns_zone_name}")
  zone_name           = azurerm_private_dns_zone.application.name
  resource_group_name = var.private_dns_zone_resource_group_name
  ttl                 = 300
  records             = [azurerm_container_app_environment.this.static_ip_address]
}

resource "azurerm_container_app_job" "advisory_refresh" {
  count                        = var.deploy_workloads ? 1 : 0
  name                         = "${var.name}-advisory-refresh"
  location                     = var.location
  resource_group_name          = data.azurerm_resource_group.this.name
  container_app_environment_id = azurerm_container_app_environment.this.id
  replica_timeout_in_seconds   = 1800
  replica_retry_limit          = 2
  workload_profile_name        = "Consumption"
  identity {
    type         = "UserAssigned"
    identity_ids = local.runtime_identity_ids
  }
  registry {
    server   = azurerm_container_registry.this.login_server
    identity = azurerm_user_assigned_identity.app.id
  }
  schedule_trigger_config {
    cron_expression          = "0 * * * *"
    parallelism              = 1
    replica_completion_count = 1
  }
  template {
    container {
      name    = "refresh"
      image   = var.image
      cpu     = 0.25
      memory  = "0.5Gi"
      command = ["wheelguard-refresh-advisories"]
      dynamic "env" {
        for_each = local.common_env
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }
}

resource "azurerm_container_app_job" "schema_upgrade" {
  count                        = var.deploy_workloads ? 1 : 0
  name                         = "${var.name}-schema-upgrade"
  location                     = var.location
  resource_group_name          = data.azurerm_resource_group.this.name
  container_app_environment_id = azurerm_container_app_environment.this.id
  replica_timeout_in_seconds   = 1800
  replica_retry_limit          = 0
  workload_profile_name        = "Consumption"
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.schema.id]
  }
  registry {
    server   = azurerm_container_registry.this.login_server
    identity = azurerm_user_assigned_identity.schema.id
  }
  manual_trigger_config {
    parallelism              = 1
    replica_completion_count = 1
  }
  template {
    container {
      name    = "schema-upgrade"
      image   = var.image
      cpu     = 0.25
      memory  = "0.5Gi"
      command = ["wheelguard-migrate"]
      dynamic "env" {
        for_each = merge(local.common_env, {
          WHEELGUARD_DATABASE_URL = "host=${azurerm_postgresql_flexible_server.this.fqdn} dbname=${var.postgres_database_name} user=${azurerm_user_assigned_identity.schema.name} sslmode=require"
          AZURE_CLIENT_ID         = azurerm_user_assigned_identity.schema.client_id
        })
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }
  depends_on = [
    azurerm_postgresql_flexible_server_active_directory_administrator.schema,
    azurerm_role_assignment.schema_acr,
  ]
}
