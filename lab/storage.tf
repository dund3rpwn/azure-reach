resource "azurerm_storage_account" "lab" {
  name                     = "${var.prefix}${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.lab.name
  location                 = azurerm_resource_group.lab.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # Required for the public container below. Azure defaults this to false on
  # newer accounts, so a container asking for anonymous access fails without it.
  allow_nested_items_to_be_public = true
}

# Anonymous read at object level: readable by anyone who knows the blob name,
# but not enumerable. The tool should distinguish this from "container".
resource "azurerm_storage_container" "public" {
  name                  = "public-assets"
  storage_account_id    = azurerm_storage_account.lab.id
  container_access_type = "blob"
}

resource "azurerm_storage_container" "private" {
  name                  = "private-backups"
  storage_account_id    = azurerm_storage_account.lab.id
  container_access_type = "private"
}

resource "azurerm_storage_blob" "public_marker" {
  name                   = "readme.txt"
  storage_account_name   = azurerm_storage_account.lab.name
  storage_container_name = azurerm_storage_container.public.name
  type                   = "Block"
  source_content         = "azure-reach lab. Anonymous read of this blob is intentional.\n"
}

resource "azurerm_storage_blob" "private_marker" {
  name                   = "backup-manifest.txt"
  storage_account_name   = azurerm_storage_account.lab.name
  storage_container_name = azurerm_storage_container.private.name
  type                   = "Block"
  source_content         = "azure-reach lab. Reaching this without credentials is a finding.\n"
}
