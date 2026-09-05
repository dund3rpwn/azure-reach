variable "prefix" {
  description = "Name prefix for every resource. Keep it short; storage account names cap at 24 chars."
  type        = string
  default     = "azreach"
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "enable_vm" {
  description = <<-EOT
    Create the VM used to demonstrate the Contributor -> runCommand -> managed
    identity edge. This is the only resource in the lab that costs real money
    (a B1s plus its disk, a few dollars a month). Everything else is free or
    fractions of a cent. Leave it off unless you are exercising that edge.
  EOT
  type        = bool
  default     = false
}

variable "grant_graph_directory_read" {
  description = <<-EOT
    Grant the over-privileged SP Directory.Read.All on Microsoft Graph. Needs
    Global Administrator or Privileged Role Administrator to apply, because it
    is an admin-consented app role. Off by default so the lab still comes up in
    a tenant where you are only a subscription Owner.
  EOT
  type        = bool
  default     = false
}
