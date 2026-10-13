#!/usr/bin/env python3
"""Run lib/cloud_api.py for every REST provider against tests/cloud_sim.py,
once with valid and once with wrong credentials.

  python3 discovery/tests/test_cloud_api.py

Needs python3-cryptography (for the Oracle Cloud signing test).
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB)); sys.path.insert(0, str(HERE))
import cloud_sim  # noqa: E402
import creds  # noqa: E402

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

PORT = 9917
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIV = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                         serialization.NoEncryption()).decode()
PUB = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
srv = cloud_sim.serve(PORT, PUB)
threading.Thread(target=srv.serve_forever, daemon=True).start()

T = cloud_sim.TOKEN
CASES = {  # provider: (sim prefix, good fields, bad fields, expected counts)
    "digitalocean": ("do", {"token": T}, {"token": "nope"}, {"Droplets": 5, "VPCs": 5, "Domains": 5}),
    "linode": ("linode", {"token": T}, {"token": "nope"}, {"Linodes": 5, "Firewalls": 5}),
    "hetzner": ("hetzner", {"token": T}, {"token": "nope"}, {"Servers": 5, "Networks": 5, "DNS zones": 5}),
    "vultr": ("vultr", {"token": T}, {"token": "nope"}, {"Instances": 5, "Firewall groups": 5}),
    "scaleway": ("scw", {"secret_key": T}, {"secret_key": "nope"}, {"Servers": 5, "VPCs": 5, "DNS zones": 5}),
    "cloudflare": ("cf", {"token": T}, {"token": "nope"}, {"Zones": 5, "Accounts": 5, "DNS records": 15}),
    "ibm": ("ibm", {"api_key": T}, {"api_key": "nope"}, {"Instances": 10, "VPCs": 10}),     # 2 regions x 5
    "ovh": ("ovh", dict(cloud_sim.OVH), {**cloud_sim.OVH, "app_secret": "wrong"}, {"Instances": 5, "Projects": 1, "DNS zones": 1}),
    "alibaba": ("ali", dict(cloud_sim.ALI), {**cloud_sim.ALI, "access_key_secret": "wrong"}, {"ECS instances": 5, "VPCs": 5}),
    "oci": ("oci", {"tenancy": "ocid1.tenancy.sim", "user": "ocid1.user.sim", "fingerprint": "aa:bb", "private_key": PRIV},
            {"tenancy": "ocid1.tenancy.sim", "user": "ocid1.user.sim", "fingerprint": "aa:bb",
             "private_key": rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
                 serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                 serialization.NoEncryption()).decode()},
            {"VCNs": 10, "Instances": 10, "Compartments": 2}),                            # root + 1 compartment
}

fails = 0


def run(prov, prefix, fields):
    d = tempfile.mkdtemp(prefix="ctest")
    creds.store(d, {"sets": [creds.validate({"type": prov, "name": f"{prov} test", "fields": fields}, 1)], "vault": {}})
    env = dict(os.environ, **{f"CLOUD_API_BASE_{prov.upper()}": f"http://127.0.0.1:{PORT}/{prefix}"})
    p = subprocess.run([sys.executable, str(LIB / "cloud_api.py"), prov, d, d], env=env,
                       capture_output=True, text=True, timeout=60)
    out = json.loads((Path(d) / f"api-{prov}.json").read_text())
    return p.stdout.strip().split("\t")[0], out


for prov, (prefix, good, bad, expect) in CASES.items():
    r, out = run(prov, prefix, good)
    wrong = {k: (out["counts"].get(k), v) for k, v in expect.items() if out["counts"].get(k) != v}
    ok_good = r == "ok" and not wrong
    r2, out2 = run(prov, prefix, bad)
    ok_bad = r2 == "auth_failed"
    fails += (not ok_good) + (not ok_bad)
    print(f"{'PASS' if ok_good and ok_bad else 'FAIL'}  {prov:<13} good={r} counts={out['counts']}"
          + (f" WRONG={wrong}" if wrong else "") + (f" errors={out['errors']}" if out["errors"] else "")
          + f" | bad creds={r2}")

srv.shutdown()
print(f"\n{len(CASES) * 2 - fails}/{len(CASES) * 2} checks passed")
sys.exit(1 if fails else 0)
