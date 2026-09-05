// Optional. Exists only to give the over-privileged SP a Contributor-on-VM
// edge: Contributor can call runCommand, runCommand executes as the machine,
// and the machine carries a managed identity that may hold roles the original
// credential never had. azure-reach reports that edge; it does not take it.
//
// No public IP. Nothing needs to reach this VM for the edge to exist, and an
// exposed SSH port on a deliberately weak lab is somebody else's bad afternoon.

resource "azurerm_virtual_network" "lab" {
  count               = var.enable_vm ? 1 : 0
  name                = "${var.prefix}-vnet"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  address_space       = ["10.42.0.0/16"]
}

resource "azurerm_subnet" "lab" {
  count                = var.enable_vm ? 1 : 0
  name                 = "default"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab[0].name
  address_prefixes     = ["10.42.1.0/24"]
}

resource "azurerm_network_interface" "lab" {
  count               = var.enable_vm ? 1 : 0
  name                = "${var.prefix}-nic"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.lab[0].id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "tls_private_key" "vm" {
  count     = var.enable_vm ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "azurerm_linux_virtual_machine" "lab" {
  count               = var.enable_vm ? 1 : 0
  name                = "${var.prefix}-vm"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  size                = "Standard_B1s"
  admin_username      = "labadmin"

  network_interface_ids = [azurerm_network_interface.lab[0].id]

  admin_ssh_key {
    username   = "labadmin"
    public_key = tls_private_key.vm[0].public_key_openssh
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  identity {
    type = "SystemAssigned"
  }
}

# The identity is worth more than the machine: this is what makes the
# Contributor-on-VM edge an escalation rather than a curiosity.
resource "azurerm_role_assignment" "vm_identity_reader" {
  count                = var.enable_vm ? 1 : 0
  scope                = azurerm_resource_group.lab.id
  role_definition_name = "Reader"
  principal_id         = azurerm_linux_virtual_machine.lab[0].identity[0].principal_id
}
