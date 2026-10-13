#!/usr/bin/env python3
"""Local stand-in for the cloud REST APIs used by lib/cloud_api.py.

  python3 tests/cloud_sim.py [PORT]      # default 9900, http://127.0.0.1 only

Every provider lives under its own prefix (/do, /linode, /hetzner, /vultr,
/scw, /cf, /ibm, /ovh, /ali, /oci); point the collector at it with
CLOUD_API_BASE_<PROVIDER>=http://127.0.0.1:9900/<prefix> (tests/test_cloud_api.sh
does this). It checks credentials the way each provider does (bearer token,
OVH / Alibaba / OCI signatures recomputed here) and always pages in twos so
the collector's pagination is exercised. It is a test double built from the
documented API shapes, not a copy of any provider.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "sim-token-ok"
OVH = {"app_key": "ovh-ak", "app_secret": "ovh-as-ok", "consumer_key": "ovh-ck-ok"}
ALI = {"access_key_id": "ali-id", "access_key_secret": "ali-secret-ok"}
OCI_PUBLIC_PEM = None          # set by the test from the generated key pair
PAGE = 2
FIVE = lambda kind: [{"id": f"{kind}-{i}", "name": f"{kind} {i}"} for i in range(1, 6)]


def page_of(items, page):
    return items[(page - 1) * PAGE: page * PAGE]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, obj, headers=None):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def bearer(self):
        return self.headers.get("Authorization") == f"Bearer {TOKEN}"

    def do_POST(self):
        u = urllib.parse.urlsplit(self.path)
        if u.path == "/ibm/identity/token":
            body = urllib.parse.parse_qs(self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode())
            if body.get("apikey") == [TOKEN] and body.get("grant_type") == ["urn:ibm:params:oauth:grant-type:apikey"]:
                return self.send(200, {"access_token": "ibm-access", "expires_in": 3600})
            return self.send(400, {"errorCode": "BXNIM0415E", "errorMessage": "Provided API key could not be found"})
        self.send(405, {"error": "only GET is supported here"})

    def do_PUT(self): self.send(405, {})
    def do_DELETE(self): self.send(405, {})
    def do_PATCH(self): self.send(405, {})

    def do_GET(self):  # noqa: C901 - one branch per provider, on purpose
        u = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        p = u.path
        page = int(q.get("page") or 1)

        if p.startswith("/do/"):
            if not self.bearer():
                return self.send(401, {"id": "unauthorized", "message": "Unable to authenticate you"})
            key = p[4:]
            items = page_of(FIVE(key), page)
            nxt = f"http://{self.headers['Host']}{p}?page={page + 1}&per_page={q.get('per_page')}" if page * PAGE < 5 else None
            return self.send(200, {key: items, "links": {"pages": {"next": nxt} if nxt else {}}, "meta": {"total": 5}})

        if p.startswith("/linode/"):
            if not self.bearer():
                return self.send(401, {"errors": [{"reason": "Invalid Token"}]})
            return self.send(200, {"data": page_of(FIVE(p), page), "page": page, "pages": 3, "results": 5})

        if p.startswith("/hetzner/"):
            if not self.bearer():
                return self.send(401, {"error": {"code": "unauthorized", "message": "unable to authenticate"}})
            key = p.split("/")[-1]
            return self.send(200, {key: page_of(FIVE(key), page),
                                   "meta": {"pagination": {"page": page, "next_page": page + 1 if page * PAGE < 5 else None}}})

        if p.startswith("/vultr/"):
            if not self.bearer():
                return self.send(401, {"error": "Invalid API token."})
            keys = {"vpcs": "vpcs", "instances": "instances", "firewalls": "firewall_groups",
                    "load-balancers": "load_balancers", "reserved-ips": "reserved_ips", "domains": "domains"}
            key = keys[p.split("/")[-1]]
            cur = int(base64.b64decode(q["cursor"]).decode()) if q.get("cursor") else 1
            nxt = base64.b64encode(str(cur + 1).encode()).decode() if cur * PAGE < 5 else ""
            return self.send(200, {key: page_of(FIVE(key), cur), "meta": {"total": 5, "links": {"next": nxt, "prev": ""}}})

        if p.startswith("/scw/"):
            if self.headers.get("X-Auth-Token") != TOKEN:
                return self.send(401, {"message": "authentication is denied", "type": "denied_authentication"})
            m = re.search(r"/(?:zones|regions)/([a-z0-9-]+)/", p)
            if m and m.group(1) not in ("fr-par-1", "fr-par"):      # resources only in Paris
                return self.send(200, {p.split("/")[-1].replace("-", "_"): [], "total_count": 0})
            key = p.split("/")[-1].replace("-", "_")
            return self.send(200, {key: page_of(FIVE(key), page), "total_count": 5})

        if p.startswith("/cf/"):
            if not self.bearer():
                return self.send(403, {"success": False, "errors": [{"code": 9109, "message": "Invalid access token"}]})
            if p == "/cf/user/tokens/verify":
                return self.send(200, {"success": True, "result": {"status": "active"}})
            items = FIVE("zone") if p == "/cf/zones" else FIVE("acct") if p == "/cf/accounts" else \
                [{"type": "A", "name": f"r{i}", "content": "192.0.2.1"} for i in range(3)]
            return self.send(200, {"success": True, "result": page_of(items, page),
                                   "result_info": {"page": page, "total_pages": -(-len(items) // PAGE)}})

        if p.startswith("/ibm/v1/"):
            if self.headers.get("Authorization") != "Bearer ibm-access":
                return self.send(401, {"errors": [{"code": "not_authorized"}]})
            if not q.get("version") or q.get("generation") != "2":
                return self.send(400, {"errors": [{"code": "bad_request", "message": "version and generation required"}]})
            key = p.split("/")[-1]
            if key == "regions":
                return self.send(200, {"regions": [{"name": "us-south", "status": "available"},
                                                   {"name": "eu-de", "status": "available"}]})
            start = int(q.get("start") or 0)
            items = FIVE(key)[start:start + PAGE]
            nxt = {"href": f"http://{self.headers['Host']}{p}?version={q['version']}&generation=2&limit=2&start={start + PAGE}"} \
                if start + PAGE < 5 else None
            return self.send(200, {key: items, **({"next": nxt} if nxt else {})})

        if p.startswith("/ovh/"):
            if p == "/ovh/auth/time":
                import time
                return self.send(200, int(time.time()))
            url = f"http://{self.headers['Host']}{self.path}"
            ts = self.headers.get("X-Ovh-Timestamp", "")
            want = "$1$" + hashlib.sha1("+".join([OVH["app_secret"], OVH["consumer_key"], "GET", url, "", ts]).encode()).hexdigest()
            if self.headers.get("X-Ovh-Application") != OVH["app_key"] or self.headers.get("X-Ovh-Signature") != want:
                return self.send(403, {"message": "Invalid signature", "errorCode": "INVALID_SIGNATURE"})
            if p == "/ovh/cloud/project":
                return self.send(200, ["proj1"])
            if p.endswith("/instance"):
                return self.send(200, FIVE("instance"))
            if p.endswith("/network/private"):
                return self.send(200, FIVE("net")[:2])
            if p == "/ovh/domain/zone":
                return self.send(200, ["example.org"])
            return self.send(404, {"message": "not found"})

        if p == "/ali/":
            params = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
            sig = params.pop("Signature", "")
            pct = lambda s: urllib.parse.quote(str(s), safe="-_.~")
            canon = "&".join(f"{pct(k)}={pct(params[k])}" for k in sorted(params))
            want = base64.b64encode(hmac.new((ALI["access_key_secret"] + "&").encode(),
                                             ("GET&%2F&" + pct(canon)).encode(), hashlib.sha1).digest()).decode()
            if params.get("AccessKeyId") != ALI["access_key_id"] or sig != want:
                return self.send(400, {"Code": "SignatureDoesNotMatch", "Message": "signature mismatch"})
            a = params.get("Action")
            if a == "DescribeRegions":
                return self.send(200, {"Regions": {"Region": [{"RegionId": "eu-central-1"}]}})
            wrap = {"DescribeVpcs": ("Vpcs", "Vpc"), "DescribeInstances": ("Instances", "Instance"),
                    "DescribeSecurityGroups": ("SecurityGroups", "SecurityGroup"),
                    "DescribeEipAddresses": ("EipAddresses", "EipAddress"),
                    "DescribeLoadBalancers": ("LoadBalancers", "LoadBalancer")}[a]
            pg = int(params.get("PageNumber") or 1)
            return self.send(200, {wrap[0]: {wrap[1]: page_of(FIVE(a), pg)}, "TotalCount": 5, "PageNumber": pg})

        if p.startswith("/oci/"):
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.exceptions import InvalidSignature
            auth = self.headers.get("Authorization", "")
            m = re.search(r'signature="([^"]+)"', auth)
            target = u.path + ("?" + u.query if u.query else "")
            signing = f"date: {self.headers.get('date')}\n(request-target): get {target}\nhost: {self.headers.get('Host')}"
            try:
                pub = serialization.load_pem_public_key(OCI_PUBLIC_PEM)
                pub.verify(base64.b64decode(m.group(1)), signing.encode(), padding.PKCS1v15(), hashes.SHA256())
            except (InvalidSignature, AttributeError, ValueError, TypeError):
                return self.send(401, {"code": "NotAuthenticated", "message": "The required information to complete authentication was not provided or was incorrect."})
            if 'keyId="ocid1.tenancy.sim/ocid1.user.sim/aa:bb"' not in auth:
                return self.send(401, {"code": "NotAuthenticated", "message": "bad keyId"})
            if p.endswith("/compartments"):
                return self.send(200, [{"id": "ocid1.compartment.sim.1", "name": "prod", "lifecycleState": "ACTIVE"}])
            items = FIVE(p.split("/")[-1])
            pg = int(q.get("page") or 1)
            return self.send(200, page_of(items, pg), {"opc-next-page": str(pg + 1)} if pg * PAGE < 5 else None)

        self.send(404, {"error": f"simulator has no {p}"})


def serve(port: int = 9900, oci_pub: bytes | None = None):
    global OCI_PUBLIC_PEM
    OCI_PUBLIC_PEM = oci_pub
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    return srv


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9900
    pub = open(sys.argv[2], "rb").read() if len(sys.argv) > 2 else None
    print(f"cloud simulator on http://127.0.0.1:{port}")
    serve(port, pub).serve_forever()
