terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
    azuread = { source = "hashicorp/azuread", version = "~> 3.0" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
    time    = { source = "hashicorp/time", version = "~> 0.12" }
    tls     = { source = "hashicorp/tls", version = "~> 4.0" }
  }
}

provider "azurerm" {
  features {
    key_vault {
      # Without this a destroyed vault sits in soft-delete and the next apply
      # fails on a name collision, which makes the lab single-use.
      purge_soft_delete_on_destroy = true
    }
    resource_group {
      # The lab creates resources outside Terraform's view when you test against
      # it; without this, destroy leaves the group behind.
      prevent_deletion_if_contains_resources = false
    }
  }
}

provider "azuread" {}

data "azurerm_client_config" "current" {}
data "azuread_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}
