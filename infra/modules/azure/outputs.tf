output "application_url" {
  value = "${var.enable_tls ? "https" : "http"}://${var.hostname}"
}

output "container_registry_login_server" {
  value = azurerm_container_registry.this.login_server
}

output "container_registry_name" {
  value = azurerm_container_registry.this.name
}

output "container_app_id" {
  value = var.deploy_workloads ? azurerm_container_app.this[0].id : null
}

output "container_app_name" {
  value = var.deploy_workloads ? azurerm_container_app.this[0].name : var.name
}

output "schema_identity_client_id" {
  description = "Identity used by the one-shot schema upgrade job."
  value       = azurerm_user_assigned_identity.schema.client_id
}

output "schema_identity_principal_id" {
  description = "Object ID of the schema identity also attached to PostgreSQL for Microsoft Graph lookups."
  value       = azurerm_user_assigned_identity.schema.principal_id
}

output "schema_upgrade_job_name" {
  value = var.deploy_workloads ? azurerm_container_app_job.schema_upgrade[0].name : "${var.name}-schema-upgrade"
}

output "advisory_refresh_job_name" {
  value = var.deploy_workloads ? azurerm_container_app_job.advisory_refresh[0].name : "${var.name}-advisory-refresh"
}

output "storage_account_id" {
  value = azapi_resource.storage.id
}

output "postgres_server_id" {
  value = azurerm_postgresql_flexible_server.this.id
}
