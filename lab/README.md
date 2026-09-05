# azure-reach lab

A deliberately misconfigured Azure environment, so every claim azure-reach makes
can be reproduced by anyone rather than taken on trust.

**Use a throwaway subscription.** This creates a publicly readable blob
container, two service principals with client secrets, and key vaults with purge
protection disabled. None of it belongs anywhere near a tenant you care about.

## What it builds

| resource | why |
| --- | --- |
| over-privileged SP | Contributor on the group, Storage Blob Data Reader, Key Vault Secrets User. Most checks should come back `VERIFIED`. |
| control SP | **No roles, no app roles.** Proves the self-read returns `ASSUMED`. |
| storage account | one anonymously readable container, one private |
| key vault (RBAC) | authorizes via Azure RBAC |
| key vault (access policy) | authorizes via the legacy model — check one and not the other and you get a false negative |
| planted secrets | a connection string and a password, as recursion targets |
| VM + managed identity | *optional*, off by default — the Contributor → runCommand → MI edge |

## Running it

```
az login
az account set --subscription <throwaway-subscription-id>

terraform init
terraform apply
```

Then point the tool at it:

```
cd ..
./azure-reach.py --cred "$(terraform -chdir=lab output -raw control_client_secret)" \
                 --subscriptions "$(terraform -chdir=lab output -raw subscription_id)"
```

## Cost

Everything except the VM is free or fractions of a cent a month — service
principals, role assignments and empty containers cost nothing, and two standard
vaults with two secrets round to zero.

`enable_vm = true` adds a `Standard_B1s` plus a managed disk, a few dollars a
month, and it is the only thing here worth remembering to destroy. It is off by
default for that reason.

```
terraform destroy
```

## Permissions you need

Subscription **Owner** (or Contributor + User Access Administrator — the role
assignments need the second one), plus enough directory rights to create
applications.

`grant_graph_directory_read = true` additionally needs **Global Administrator**
or **Privileged Role Administrator**, because admin-consented Graph app roles
cannot be self-granted. It is off by default so the lab still comes up without
them.

## Known rough edges

- Data-plane RBAC on the vault takes time to propagate. There is a 60-second
  `time_sleep` before the secret write for exactly this reason; if `apply` still
  fails there with a 403, re-run it.
- Key Vault names are globally unique and soft-deleted names stay reserved.
  `purge_soft_delete_on_destroy` is on so the lab can be recycled, but if you
  destroy it in a way Terraform does not see, the next apply may collide.
- `terraform.tfstate` holds both client secrets in cleartext. It is gitignored;
  keep it that way.
