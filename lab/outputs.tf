output "tenant_id" {
  value = data.azurerm_client_config.current.tenant_id
}

output "subscription_id" {
  value = data.azurerm_client_config.current.subscription_id
}

output "resource_group" {
  value = azurerm_resource_group.lab.name
}

output "storage_account" {
  value = azurerm_storage_account.lab.name
}

output "key_vault_rbac" {
  value = azurerm_key_vault.rbac.name
}

output "key_vault_access_policy" {
  value = azurerm_key_vault.access_policy.name
}

output "overprivileged_client_id" {
  value = azuread_application.overprivileged.client_id
}

output "overprivileged_client_secret" {
  value     = azuread_application_password.overprivileged.value
  sensitive = true
}

output "control_client_id" {
  value = azuread_application.control.client_id
}

output "control_client_secret" {
  value     = azuread_application_password.control.value
  sensitive = true
}

output "public_blob_url" {
  description = "Anonymously readable. Fetch it with no credential at all as a positive control."
  value       = "${azurerm_storage_account.lab.primary_blob_endpoint}${azurerm_storage_container.public.name}/${azurerm_storage_blob.public_marker.name}"
}

output "next_steps" {
  value = <<-EOT

    Secrets are in state. Read them with:
      terraform output -raw overprivileged_client_secret
      terraform output -raw control_client_secret

    Expected results:

      over-privileged SP   ARM read, storage list, both vaults  -> VERIFIED
      control SP           the same checks                      -> VERIFIED NEGATIVE
      control SP           its own servicePrincipal object      -> ASSUMED

    That last line is the one that matters. The control principal holds no roles
    and no app roles, so a 200 on its own object proves nothing -- Entra allows
    that read by default. Any tool calling it VERIFIED is producing a false
    positive, and this lab exists to make that reproducible.

    Tear down with: terraform destroy
  EOT
}
