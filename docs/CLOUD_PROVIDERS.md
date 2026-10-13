# Cloud providers: read-only inventory reference

Collected 2026-10-13 from vendor documentation for the cloud scan. Items
marked **[verify]** could not be confirmed from an official page during
research (page not retrievable, or from memory); check them against the
live API before relying on them. Implementation status is in `DEVLOG.md`.

| Provider | Credential (least privilege) | Auth | Region per call |
|---|---|---|---|
| AWS | IAM access key, policy `ReadOnlyAccess` (or `job-function/ViewOnlyAccess`) | SigV4 via `aws` CLI, env `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`/`AWS_DEFAULT_REGION` | yes |
| Azure | service principal, role `Reader` at subscription | `az login --service-principal -u APP --password @file --tenant T` (`@file` on `--password` **[verify]**), `AZURE_CONFIG_DIR` isolates the login | no |
| Google Cloud | service account JSON key, `roles/viewer` (or `compute.viewer` + `dns.reader`) | `gcloud auth activate-service-account --key-file`, `CLOUDSDK_CONFIG` isolates | no |
| Kubernetes | kubeconfig with a ServiceAccount bound to ClusterRole `view` (+ `get/list nodes` for nodes) | `KUBECONFIG=file` | - |
| DigitalOcean | token, scope "Read Only" (`api:read`) | `Authorization: Bearer` | no |
| Akamai / Linode | token, every scope "Read Only" | `Authorization: Bearer` | no |
| Hetzner Cloud | project API token, permission "Read" (one project per token) | `Authorization: Bearer` | no |
| Vultr | API key - **no read-only option**, only an IP allowlist **[verify]** | `Authorization: Bearer` | no |
| Scaleway | IAM application API key, permission set `AllProductsReadOnly` | `X-Auth-Token: <secret key>` | yes (zones / regions) |
| Cloudflare | API token: Zone Read, DNS Read, Account Settings Read | `Authorization: Bearer` | no |
| IBM Cloud VPC | API key (Service ID), Viewer + Reader on VPC Infrastructure **[verify pairing]** | API key -> `POST https://iam.cloud.ibm.com/identity/token` -> Bearer (1 h) | yes |
| Oracle Cloud | API signing key; policy `read all-resources in tenancy` | HTTP signatures (draft-cavage, RSA-SHA256) | yes |
| Alibaba Cloud | RAM AccessKey, `ReadOnlyAccess` **[verify names]** | RPC signature V1 / V3 `ACS3-HMAC-SHA256` | yes |
| OVHcloud | application key + secret + consumer key with `GET /*` only | `X-Ovh-*` headers, `$1$` + SHA1 signature | for IPs / LBs |

## Endpoints

### DigitalOcean - `https://api.digitalocean.com/v2`
`/vpcs` [vpcs], `/droplets` [droplets], `/firewalls` [firewalls],
`/load_balancers` [load_balancers], `/reserved_ips` [reserved_ips],
`/domains` [domains]. `?page=&per_page=` (max 200), follow
`links.pages.next`. Scopes: https://docs.digitalocean.com/reference/api/scopes/

### Akamai / Linode - `https://api.linode.com/v4`
`/vpcs`, `/linode/instances`, `/networking/firewalls`, `/nodebalancers`,
`/networking/ips`, `/domains`; body `{data, page, pages, results}`,
`?page=&page_size=` (25-500). **[verify]**

### Hetzner Cloud - `https://api.hetzner.cloud/v1`
`/networks`, `/servers`, `/firewalls`, `/load_balancers`, `/floating_ips`,
`/primary_ips`, DNS `/zones` **[verify path]**; list key = resource name;
`?page=&per_page=` (max 50), stop when `meta.pagination.next_page` is null.
https://docs.hetzner.cloud/reference/cloud

### Vultr - `https://api.vultr.com/v2` **[verify all]**
`/vpcs` [vpcs], `/instances` [instances], `/firewalls` [firewall_groups],
`/load-balancers` [load_balancers], `/reserved-ips` [reserved_ips],
`/domains` [domains]; `?per_page=` (max 500) + `cursor` from `meta.links.next`.

### Scaleway - `https://api.scaleway.com`
Per zone (`fr-par-1..3`, `nl-ams-1..3`, `pl-waw-1..3`):
`/instance/v1/zones/{zone}/servers` [servers], `.../security_groups`,
`.../ips` [ips], `/lb/v1/zones/{zone}/lbs` [lbs]. Per region (`fr-par`,
`nl-ams`, `pl-waw`): `/vpc/v2/regions/{region}/vpcs` [vpcs],
`.../private-networks` [private_networks]. DNS:
`/domain/v2beta1/dns-zones` [dns_zones]. `?page=&per_page=` (max 100) up to
`total_count`. https://www.scaleway.com/en/docs/iam/reference-content/permission-sets/

### Cloudflare - `https://api.cloudflare.com/client/v4`
`/user/tokens/verify`, `/accounts`, `/zones`, `/zones/{id}/dns_records`;
list in `result`, `?page=&per_page=`, `result_info.total_pages`.
https://developers.cloudflare.com/api/

### IBM Cloud VPC - `https://{region}.iaas.cloud.ibm.com/v1`
`?version=YYYY-MM-DD&generation=2`; `/vpcs`, `/instances`,
`/security_groups`, `/load_balancers`, `/floating_ips`; `limit` (max 100),
follow `next.href`; regions from `/regions`.
https://cloud.ibm.com/apidocs/vpc/latest

### Oracle Cloud - `https://iaas.{region}.oraclecloud.com`
`/20160918/vcns|subnets|instances|securityLists|networkSecurityGroups`,
`/20160918/publicIps?scope=REGION`, `/20170115/loadBalancers`, all with
`compartmentId`; compartments from Identity
`/20160918/compartments?compartmentIdInSubtree=true`; bare JSON arrays,
`opc-next-page` header. https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm **[verify]**

### Alibaba Cloud (RPC, `?Action=&Version=&RegionId=`)
ECS `ecs.{region}.aliyuncs.com` 2014-05-26 `DescribeInstances`,
`DescribeSecurityGroups`; VPC 2016-04-28 `DescribeVpcs`,
`DescribeEipAddresses`; SLB 2014-05-15 `DescribeLoadBalancers`; DNS
`alidns.aliyuncs.com` 2015-01-09 `DescribeDomains`. **[verify]**

### OVHcloud - `https://eu.api.ovh.com/1.0`
`/cloud/project`, `/cloud/project/{sn}/instance`,
`.../network/private`, `.../region/{r}/floatingip`,
`.../region/{r}/loadbalancing/loadbalancer`, `/domain/zone`; arrays of IDs,
one GET per object. Signature: `"$1$" + sha1(AS+"+"+CK+"+"+METHOD+"+"+URL+"+"+BODY+"+"+TS)`.
https://docs.ovhcloud.com/en/guides/manage-and-operate/api/first-steps
