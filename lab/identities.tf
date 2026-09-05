resource "azurerm_resource_group" "lab" {
  name     = "${var.prefix}-${random_string.suffix.result}-rg"
  location = var.location
}

# ---------------------------------------------------------------------------
# The over-privileged principal. Most checks should come back VERIFIED here.
# ---------------------------------------------------------------------------

resource "azuread_application" "overprivileged" {
  display_name = "${var.prefix}-overprivileged"
  owners       = [data.azuread_client_config.current.object_id]
}

resource "azuread_service_principal" "overprivileged" {
  client_id = azuread_application.overprivileged.client_id
  owners    = [data.azuread_client_config.current.object_id]
}

resource "azuread_application_password" "overprivileged" {
  application_id = azuread_application.overprivileged.id
}

resource "azurerm_role_assignment" "over_contributor" {
  scope                = azurerm_resource_group.lab.id
  role_definition_name = "Contributor"
  principal_id         = azuread_service_principal.overprivileged.object_id
}

resource "azurerm_role_assignment" "over_blob_reader" {
  scope                = azurerm_storage_account.lab.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azuread_service_principal.overprivileged.object_id
}

# Deliberately RBAC-model only. The second vault uses access policies instead,
# so a tool that checks one model and not the other gets a false negative on it.
resource "azurerm_role_assignment" "over_kv_secrets" {
  scope                = azurerm_key_vault.rbac.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azuread_service_principal.overprivileged.object_id
}

data "azuread_service_principal" "msgraph" {
  client_id = "00000003-0000-0000-c000-000000000000"
}

resource "azuread_app_role_assignment" "over_directory_read" {
  count               = var.grant_graph_directory_read ? 1 : 0
  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids["Directory.Read.All"]
  principal_object_id = azuread_service_principal.overprivileged.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

# ---------------------------------------------------------------------------
# The control principal.
#
# This one has no role assignments and no app roles, and that is the entire
# point of it. It can still authenticate, and it can still read its own service
# principal object, because Entra allows that by default with nothing granted.
#
# That self-read is what makes naive tooling report "directory read confirmed"
# off a 200. Against this principal, azure-reach must return ASSUMED for the
# self-read and VERIFIED NEGATIVE for everything else.
#
# Do not grant this principal anything. If a future change gives it a role to
# make some other test pass, the lab stops being able to prove the thing it
# exists to prove.
# ---------------------------------------------------------------------------

resource "azuread_application" "control" {
  display_name = "${var.prefix}-control-no-permissions"
  owners       = [data.azuread_client_config.current.object_id]
}

resource "azuread_service_principal" "control" {
  client_id = azuread_application.control.client_id
  owners    = [data.azuread_client_config.current.object_id]
}

resource "azuread_application_password" "control" {
  application_id = azuread_application.control.id
}
