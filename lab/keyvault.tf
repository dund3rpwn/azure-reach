// Two vaults on purpose. A vault authorizes through EITHER Azure RBAC OR the
// legacy access policy model, and they are mutually exclusive per vault. A tool
// that only checks one reports "no access" against the other and is quietly
// wrong. Both are here so that false negative is reproducible.

resource "azurerm_key_vault" "rbac" {
  name                = "${var.prefix}-rbac-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  rbac_authorization_enabled = true

  # Purge protection off and the shortest retention Azure allows, so the lab can
  # be torn down and stood back up under the same name. Never do this for real.
  purge_protection_enabled   = false
  soft_delete_retention_days = 7
}

resource "azurerm_key_vault" "access_policy" {
  name                = "${var.prefix}-pol-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  rbac_authorization_enabled = false
  purge_protection_enabled   = false
  soft_delete_retention_days = 7
}

# The deployer needs data-plane rights to write the secrets below; being Owner
# of the subscription does not grant them on an RBAC vault.
resource "azurerm_role_assignment" "deployer_kv_officer" {
  scope                = azurerm_key_vault.rbac.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# Data-plane RBAC takes a little while to propagate, and the secret write fails
# with a 403 if it lands too early.
resource "time_sleep" "kv_rbac_propagation" {
  depends_on      = [azurerm_role_assignment.deployer_kv_officer]
  create_duration = "60s"
}

resource "azurerm_key_vault_access_policy" "deployer" {
  key_vault_id       = azurerm_key_vault.access_policy.id
  tenant_id          = data.azurerm_client_config.current.tenant_id
  object_id          = data.azurerm_client_config.current.object_id
  secret_permissions = ["Get", "List", "Set", "Delete", "Purge"]
}

# The over-privileged SP reaches this vault through an access policy rather than
# a role assignment. Same capability, different model.
resource "azurerm_key_vault_access_policy" "overprivileged" {
  key_vault_id       = azurerm_key_vault.access_policy.id
  tenant_id          = data.azurerm_client_config.current.tenant_id
  object_id          = azuread_service_principal.overprivileged.object_id
  secret_permissions = ["Get", "List"]
}

# Recursion target: a credential inside a vault the tool can reach. It must be
# queued for a second, explicit run rather than followed automatically -- that
# is what keeps one authorized test from becoming an unbounded one.
resource "azurerm_key_vault_secret" "planted_rbac" {
  name         = "storage-connection-string"
  key_vault_id = azurerm_key_vault.rbac.id
  depends_on   = [time_sleep.kv_rbac_propagation]

  value = join("", [
    "DefaultEndpointsProtocol=https;AccountName=", azurerm_storage_account.lab.name,
    ";AccountKey=", base64encode("not-a-real-key-azure-reach-lab-fixture"),
    ";EndpointSuffix=core.windows.net",
  ])
}

resource "azurerm_key_vault_secret" "planted_policy" {
  name         = "legacy-api-password"
  key_vault_id = azurerm_key_vault.access_policy.id
  depends_on   = [azurerm_key_vault_access_policy.deployer]
  value        = "azure-reach-lab-fixture-not-a-real-password"
}
