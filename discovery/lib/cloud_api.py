#!/usr/bin/env python3
"""Read-only cloud inventory over each provider's official REST API.

  cloud_api.py PROVIDER SECURE_DIR OUT_DIR

Reads the provider's credential card from SECURE_DIR/creds.json (see
creds.py), lists networks, servers, firewalls, load balancers, public IPs
and DNS zones, and writes OUT_DIR/api-PROVIDER.json:

  {"provider": "...", "label": "...", "counts": {"Servers": 3, ...},
   "resources": {"Servers": [...], ...}, "errors": [...]}

Prints one result line for the login record: ok | auth_failed | unreachable | error.
Endpoints and auth schemes: docs/CLOUD_PROVIDERS.md. Standard library only
(Oracle Cloud signing also needs python3-cryptography).

Only GET requests are ever sent. Pagination links are followed only on the
host the request went to. For tests, CLOUD_API_BASE_<PROVIDER> may point a
provider at a local simulator (http://127.0.0.1 or https only).
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import creds  # noqa: E402

TIMEOUT = 20
MAX_PAGES = 200          # safety net against a pagination loop
UA = "SentinelScan-inventory/1.0 (read-only)"


class AuthError(Exception):
    pass


class Unreachable(Exception):
    pass


def base(provider: str, default: str) -> str:
    """Default base URL, or a local simulator for tests."""
    o = os.environ.get(f"CLOUD_API_BASE_{provider.upper()}", "")
    if o and (o.startswith("https://") or o.startswith("http://127.0.0.1")):
        return o.rstrip("/")
    return default


def request(url: str, headers: dict | None = None, data: bytes | None = None, method: str = "GET"):
    """Returns (json body, response headers). 401/403 -> AuthError."""
    h = {"User-Agent": UA, "Accept": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            raw = r.read()
            return (json.loads(raw) if raw.strip() else {}), r.headers
    except urllib.error.HTTPError as e:
        body = e.read()[:300].decode("utf-8", "replace")
        if e.code in (401, 403):
            raise AuthError(f"HTTP {e.code} from {urllib.parse.urlsplit(url).netloc}: {body}")
        raise Unreachable(f"HTTP {e.code} from {urllib.parse.urlsplit(url).netloc}{urllib.parse.urlsplit(url).path}: {body}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise Unreachable(f"{urllib.parse.urlsplit(url).netloc}: {getattr(e, 'reason', e)}")


def same_host(a: str, b: str) -> bool:
    return urllib.parse.urlsplit(a).netloc == urllib.parse.urlsplit(b).netloc


def add_query(url: str, **params) -> str:
    u = urllib.parse.urlsplit(url)
    q = dict(urllib.parse.parse_qsl(u.query))
    q.update({k: str(v) for k, v in params.items() if v is not None})
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, urllib.parse.urlencode(q), ""))


# ── pagination styles ────────────────────────────────────────────────────────
def pages_links(url, headers, key, per_page=200):
    """DigitalOcean: links.pages.next."""
    out, nxt = [], add_query(url, per_page=per_page)
    for _ in range(MAX_PAGES):
        body, _ = request(nxt, headers)
        out += body.get(key, [])
        n = ((body.get("links") or {}).get("pages") or {}).get("next")
        if not n or not same_host(n, url):
            break
        nxt = n
    return out


def pages_count(url, headers, key, size_param="page_size", size=500, pages_field="pages"):
    """Linode: {data, page, pages}."""
    out = []
    for page in range(1, MAX_PAGES + 1):
        body, _ = request(add_query(url, page=page, **{size_param: size}), headers)
        out += body.get(key, [])
        if page >= int(body.get(pages_field) or 1):
            break
    return out


def pages_meta_next(url, headers, key, per_page=50):
    """Hetzner: meta.pagination.next_page."""
    out, page = [], 1
    for _ in range(MAX_PAGES):
        body, _ = request(add_query(url, page=page, per_page=per_page), headers)
        out += body.get(key, [])
        page = ((body.get("meta") or {}).get("pagination") or {}).get("next_page")
        if not page:
            break
    return out


def pages_cursor(url, headers, key, per_page=500):
    """Vultr: meta.links.next cursor."""
    out, cursor = [], None
    for _ in range(MAX_PAGES):
        body, _ = request(add_query(url, per_page=per_page, cursor=cursor), headers)
        out += body.get(key, [])
        cursor = ((body.get("meta") or {}).get("links") or {}).get("next")
        if not cursor:
            break
    return out


def pages_total(url, headers, key, per_page=100):
    """Scaleway: total_count."""
    out = []
    for page in range(1, MAX_PAGES + 1):
        body, _ = request(add_query(url, page=page, per_page=per_page), headers)
        items = body.get(key, [])
        out += items
        if not items or len(out) >= int(body.get("total_count") or 0):
            break
    return out


def pages_result_info(url, headers, per_page=50):
    """Cloudflare: result + result_info.total_pages."""
    out = []
    for page in range(1, MAX_PAGES + 1):
        body, _ = request(add_query(url, page=page, per_page=per_page), headers)
        out += body.get("result") or []
        if page >= int(((body.get("result_info") or {}).get("total_pages")) or 1):
            break
    return out


def pages_next_href(url, headers, key, limit=100):
    """IBM Cloud VPC: next.href."""
    out, nxt = [], add_query(url, limit=limit)
    for _ in range(MAX_PAGES):
        body, _ = request(nxt, headers)
        out += body.get(key, [])
        n = (body.get("next") or {}).get("href")
        if not n or not same_host(n, url):
            break
        nxt = n
    return out


# ── providers ────────────────────────────────────────────────────────────────
def digitalocean(f):
    b, h = base("digitalocean", "https://api.digitalocean.com/v2"), {"Authorization": f"Bearer {f['token']}"}
    return {label: pages_links(f"{b}{path}", h, key) for label, path, key in [
        ("VPCs", "/vpcs", "vpcs"), ("Droplets", "/droplets", "droplets"), ("Firewalls", "/firewalls", "firewalls"),
        ("Load balancers", "/load_balancers", "load_balancers"), ("Reserved IPs", "/reserved_ips", "reserved_ips"),
        ("Domains", "/domains", "domains")]}


def linode(f):
    b, h = base("linode", "https://api.linode.com/v4"), {"Authorization": f"Bearer {f['token']}"}
    return {label: pages_count(f"{b}{path}", h, "data") for label, path in [
        ("VPCs", "/vpcs"), ("Linodes", "/linode/instances"), ("Firewalls", "/networking/firewalls"),
        ("NodeBalancers", "/nodebalancers"), ("IP addresses", "/networking/ips"), ("Domains", "/domains")]}


def hetzner(f):
    b, h = base("hetzner", "https://api.hetzner.cloud/v1"), {"Authorization": f"Bearer {f['token']}"}
    out = {label: pages_meta_next(f"{b}{path}", h, key) for label, path, key in [
        ("Networks", "/networks", "networks"), ("Servers", "/servers", "servers"), ("Firewalls", "/firewalls", "firewalls"),
        ("Load balancers", "/load_balancers", "load_balancers"), ("Floating IPs", "/floating_ips", "floating_ips"),
        ("Primary IPs", "/primary_ips", "primary_ips")]}
    try:                                   # DNS moved into the Cloud API; path [verify]
        out["DNS zones"] = pages_meta_next(f"{b}/zones", h, "zones")
    except Unreachable:
        pass
    return out


def vultr(f):
    b, h = base("vultr", "https://api.vultr.com/v2"), {"Authorization": f"Bearer {f['token']}"}
    return {label: pages_cursor(f"{b}{path}", h, key) for label, path, key in [
        ("VPCs", "/vpcs", "vpcs"), ("Instances", "/instances", "instances"), ("Firewall groups", "/firewalls", "firewall_groups"),
        ("Load balancers", "/load-balancers", "load_balancers"), ("Reserved IPs", "/reserved-ips", "reserved_ips"),
        ("Domains", "/domains", "domains")]}


SCW_ZONES = ["fr-par-1", "fr-par-2", "fr-par-3", "nl-ams-1", "nl-ams-2", "nl-ams-3", "pl-waw-1", "pl-waw-2", "pl-waw-3"]
SCW_REGIONS = ["fr-par", "nl-ams", "pl-waw"]


def scaleway(f):
    b, h = base("scaleway", "https://api.scaleway.com"), {"X-Auth-Token": f["secret_key"]}
    q = {"project": f["project_id"]} if f.get("project_id") else {}
    out = {k: [] for k in ("VPCs", "Private networks", "Servers", "Security groups", "Flexible IPs", "Load balancers", "DNS zones")}

    def each(label, url, key):
        try:
            out[label] += pages_total(add_query(url, **q), h, key)
        except Unreachable:                # product not available in that zone/region
            pass
    for z in SCW_ZONES:
        each("Servers", f"{b}/instance/v1/zones/{z}/servers", "servers")
        each("Security groups", f"{b}/instance/v1/zones/{z}/security_groups", "security_groups")
        each("Flexible IPs", f"{b}/instance/v1/zones/{z}/ips", "ips")
        each("Load balancers", f"{b}/lb/v1/zones/{z}/lbs", "lbs")
    for r in SCW_REGIONS:
        each("VPCs", f"{b}/vpc/v2/regions/{r}/vpcs", "vpcs")
        each("Private networks", f"{b}/vpc/v2/regions/{r}/private-networks", "private_networks")
    each("DNS zones", f"{b}/domain/v2beta1/dns-zones", "dns_zones")
    return out


def cloudflare(f):
    b, h = base("cloudflare", "https://api.cloudflare.com/client/v4"), {"Authorization": f"Bearer {f['token']}"}
    body, _ = request(f"{b}/user/tokens/verify", h)
    if not body.get("success"):
        raise AuthError("token not valid")
    zones = pages_result_info(f"{b}/zones", h)
    records = []
    for z in zones[:50]:                   # DNS records of the first 50 zones
        try:
            for r in pages_result_info(f"{b}/zones/{z['id']}/dns_records", h, per_page=100):
                records.append({"zone": z.get("name"), "type": r.get("type"), "name": r.get("name"),
                                "content": r.get("content"), "proxied": r.get("proxied")})
        except Unreachable:
            pass
    return {"Accounts": pages_result_info(f"{b}/accounts", h), "Zones": zones, "DNS records": records}


def ibm(f):
    iam = base("ibm", "https://iam.cloud.ibm.com")
    try:
        body, _ = request(f"{iam}/identity/token", {"Content-Type": "application/x-www-form-urlencoded"},
                          urllib.parse.urlencode({"grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                                                  "apikey": f["api_key"]}).encode(), "POST")
    except Unreachable as e:
        # IAM answers a wrong API key with 400 (BXNIM0415E), not 401
        if "HTTP 400" in str(e):
            raise AuthError(str(e))
        raise
    tok = body.get("access_token")
    if not tok:
        raise AuthError("no access token returned")
    h = {"Authorization": f"Bearer {tok}"}
    ver = {"version": "2024-04-30", "generation": 2}

    def vpc(region):
        return base("ibm", f"https://{region}.iaas.cloud.ibm.com") + "/v1"
    regions = [r.strip() for r in (f.get("regions") or "").split(",") if r.strip()]
    if not regions:
        body, _ = request(add_query(f"{vpc('us-south')}/regions", **ver), h)
        regions = [r["name"] for r in body.get("regions", []) if r.get("status", "available") == "available"]
    out = {k: [] for k in ("VPCs", "Instances", "Security groups", "Load balancers", "Floating IPs")}
    for r in regions:
        for label, path, key in [("VPCs", "/vpcs", "vpcs"), ("Instances", "/instances", "instances"),
                                 ("Security groups", "/security_groups", "security_groups"),
                                 ("Load balancers", "/load_balancers", "load_balancers"),
                                 ("Floating IPs", "/floating_ips", "floating_ips")]:
            for item in pages_next_href(add_query(f"{vpc(r)}{path}", **ver), h, key):
                item.setdefault("_region", r)
                out[label].append(item)
    return out


def ovh(f):
    """OVHcloud: application key + secret + consumer key, $1$ SHA1 signature."""
    ends = {"eu": "https://eu.api.ovh.com/1.0", "ca": "https://ca.api.ovh.com/1.0", "us": "https://api.us.ovhcloud.com/1.0"}
    b = base("ovh", ends.get(f.get("endpoint") or "eu", ends["eu"]))
    t_body, _ = request(f"{b}/auth/time")
    delta = int(t_body if isinstance(t_body, int) else t_body.get("time", 0)) - int(dt.datetime.now().timestamp()) \
        if t_body else 0

    def get(path):
        url = f"{b}{path}"
        ts = str(int(dt.datetime.now().timestamp()) + delta)
        sig = "$1$" + hashlib.sha1("+".join([f["app_secret"], f["consumer_key"], "GET", url, "", ts]).encode()).hexdigest()
        body, _ = request(url, {"X-Ovh-Application": f["app_key"], "X-Ovh-Consumer": f["consumer_key"],
                                "X-Ovh-Timestamp": ts, "X-Ovh-Signature": sig})
        return body
    out = {k: [] for k in ("Projects", "Instances", "Private networks", "DNS zones")}
    for p in get("/cloud/project") or []:
        out["Projects"].append({"id": p})
        for i in get(f"/cloud/project/{urllib.parse.quote(str(p))}/instance") or []:
            i["_project"] = p; out["Instances"].append(i)
        for n in get(f"/cloud/project/{urllib.parse.quote(str(p))}/network/private") or []:
            n["_project"] = p; out["Private networks"].append(n)
    out["DNS zones"] = [{"name": z} for z in (get("/domain/zone") or [])]
    return out


def _pct(s: str) -> str:
    return urllib.parse.quote(str(s), safe="-_.~")


def alibaba(f):
    """Alibaba Cloud RPC API, signature version 1.0 (HMAC-SHA1)."""
    def call(host, version, action, **params):
        p = {"Format": "JSON", "Version": version, "AccessKeyId": f["access_key_id"],
             "SignatureMethod": "HMAC-SHA1", "SignatureVersion": "1.0",
             "SignatureNonce": uuid.uuid4().hex, "Action": action,
             "Timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             **{k: str(v) for k, v in params.items()}}
        canon = "&".join(f"{_pct(k)}={_pct(p[k])}" for k in sorted(p))
        to_sign = "GET&%2F&" + _pct(canon)
        p["Signature"] = base64.b64encode(hmac.new((f["access_key_secret"] + "&").encode(),
                                                   to_sign.encode(), hashlib.sha1).digest()).decode()
        url = base("alibaba", f"https://{host}") + "/?" + "&".join(f"{_pct(k)}={_pct(v)}" for k, v in p.items())
        try:
            return request(url)[0]
        except Unreachable as e:
            if "InvalidAccessKeyId" in str(e) or "SignatureDoesNotMatch" in str(e) or "Forbidden" in str(e):
                raise AuthError(str(e))
            raise

    def paged(host, version, action, path, region):
        out = []
        for page in range(1, MAX_PAGES + 1):
            body = call(host, version, action, RegionId=region, PageNumber=page, PageSize=50)
            cur = body
            for k in path:
                cur = (cur or {}).get(k) or {}
            items = cur if isinstance(cur, list) else []
            out += items
            if not items or len(out) >= int(body.get("TotalCount") or 0):
                break
        return out
    regions = [r.strip() for r in (f.get("regions") or "").split(",") if r.strip()]
    if not regions:
        body = call("ecs.aliyuncs.com", "2014-05-26", "DescribeRegions")
        regions = [r["RegionId"] for r in body.get("Regions", {}).get("Region", [])]
    out = {k: [] for k in ("VPCs", "ECS instances", "Security groups", "Elastic IPs", "Load balancers")}
    for r in regions:
        for label, host, ver, action, path in [
                ("VPCs", "vpc.aliyuncs.com", "2016-04-28", "DescribeVpcs", ["Vpcs", "Vpc"]),
                ("ECS instances", f"ecs.{r}.aliyuncs.com", "2014-05-26", "DescribeInstances", ["Instances", "Instance"]),
                ("Security groups", f"ecs.{r}.aliyuncs.com", "2014-05-26", "DescribeSecurityGroups", ["SecurityGroups", "SecurityGroup"]),
                ("Elastic IPs", "vpc.aliyuncs.com", "2016-04-28", "DescribeEipAddresses", ["EipAddresses", "EipAddress"]),
                ("Load balancers", "slb.aliyuncs.com", "2014-05-15", "DescribeLoadBalancers", ["LoadBalancers", "LoadBalancer"])]:
            for item in paged(host, ver, action, path, r):
                item.setdefault("_region", r)
                out[label].append(item)
    return out


def oci(f):
    """Oracle Cloud: HTTP signatures (draft-cavage), RSA-SHA256."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:
        raise Unreachable("Oracle Cloud needs python3-cryptography (sudo apt install python3-cryptography)")
    try:
        key = serialization.load_pem_private_key(f["private_key"].encode(), password=None)
    except ValueError:
        raise AuthError("the private key could not be read (passphrase-protected keys are not supported)")
    key_id = f"{f['tenancy']}/{f['user']}/{f['fingerprint']}"
    region = f.get("region") or "us-ashburn-1"

    def get(host, path, **q):
        url = base("oci", f"https://{host}") + path + ("?" + urllib.parse.urlencode(q) if q else "")
        u = urllib.parse.urlsplit(url)
        date = dt.datetime.now(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        target = u.path + ("?" + u.query if u.query else "")
        signing = f"date: {date}\n(request-target): get {target}\nhost: {u.netloc}"
        sig = base64.b64encode(key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())).decode()
        auth = (f'Signature version="1",keyId="{key_id}",algorithm="rsa-sha256",'
                f'headers="date (request-target) host",signature="{sig}"')
        return request(url, {"date": date, "host": u.netloc, "Authorization": auth})

    def all_pages(host, path, **q):
        out, page = [], None
        for _ in range(MAX_PAGES):
            body, hdr = get(host, path, **({**q, "page": page} if page else q))
            out += body if isinstance(body, list) else body.get("items", [])
            page = hdr.get("opc-next-page")
            if not page:
                break
        return out
    ident = f"identity.{region}.oraclecloud.com"
    comps = [{"id": f["tenancy"], "name": "(root)"}] + all_pages(
        ident, "/20160918/compartments", compartmentId=f["tenancy"], compartmentIdInSubtree="true")
    core = f"iaas.{region}.oraclecloud.com"
    out = {k: [] for k in ("Compartments", "VCNs", "Instances", "Security lists", "Load balancers")}
    out["Compartments"] = comps
    for c in comps:
        if c.get("lifecycleState", "ACTIVE") != "ACTIVE":
            continue
        for label, host, path in [("VCNs", core, "/20160918/vcns"), ("Instances", core, "/20160918/instances"),
                                  ("Security lists", core, "/20160918/securityLists"),
                                  ("Load balancers", core, "/20170115/loadBalancers")]:
            out[label] += all_pages(host, path, compartmentId=c["id"])
    return out


PROVIDERS = {
    "digitalocean": ("DigitalOcean", digitalocean), "linode": ("Akamai / Linode", linode),
    "hetzner": ("Hetzner Cloud", hetzner), "vultr": ("Vultr", vultr), "scaleway": ("Scaleway", scaleway),
    "cloudflare": ("Cloudflare", cloudflare), "ibm": ("IBM Cloud", ibm), "ovh": ("OVHcloud", ovh),
    "alibaba": ("Alibaba Cloud", alibaba), "oci": ("Oracle Cloud", oci),
}


def main(argv):
    if len(argv) != 4 or argv[1] not in PROVIDERS:
        sys.exit(__doc__)
    prov, d, out_dir = argv[1:]
    label, fn = PROVIDERS[prov]
    card = next((s for s in creds.load(d)["sets"] if s["type"] == prov), None)
    if not card:
        print("error\tno credential card for " + prov)
        return 1
    doc = {"provider": prov, "label": label, "counts": {}, "resources": {}, "errors": []}
    result = "ok"
    try:
        res = fn(card["fields"])
        doc["resources"] = res
        doc["counts"] = {k: len(v) for k, v in res.items()}
    except AuthError as e:
        result = "auth_failed"; doc["errors"].append(str(e)[:300])
    except Unreachable as e:
        result = "unreachable"; doc["errors"].append(str(e)[:300])
    except (KeyError, ValueError, TypeError) as e:
        result = "error"; doc["errors"].append(f"unexpected answer: {e}"[:300])
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    (Path(out_dir) / f"api-{prov}.json").write_text(json.dumps(doc, indent=1, default=str))
    print(f"{result}\t{'; '.join(doc['errors'])[:200]}")
    return 0 if result == "ok" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
