#!/usr/bin/env python3
"""Credentials for one scan, kept in $SECURE_TMP (tmpfs, 0700) only.

The panel sends a JSON document through an inherited pipe; discover.sh feeds
it to `ingest`. Secrets are only ever written to stdout of these commands
(captured by bash into variables) or to 0600 files inside the secure dir -
never to argv, the environment of other tools, or the run folder.

  creds.py ingest DIR                 stdin JSON -> DIR/creds.json; prints "type<TAB>name" per set
  creds.py from-vault DIR             stdin KEY=value vault lines; adds the CRED_* sets named in
                                      creds.json vault.use (or all of them if use == ["*"])
  creds.py count DIR TYPE             number of sets of TYPE
  creds.py pick DIR TYPE IP           id of the first TYPE set whose hosts match IP (blank = any)
  creds.py hosts DIR TYPE             explicit IPs / ranges of all TYPE sets, one per line
  creds.py get DIR ID FIELD           field value on stdout (no newline)
  creds.py name DIR ID                the set's display name
  creds.py tofile DIR ID FIELD PATH   write a field to PATH with mode 0600
  creds.py vaultpass DIR              the vault passphrase, if one was sent
  creds.py to-vault DIR               "CRED_<slug>=<base64 json>" for every set marked save
  creds.py secrets DIR                every secret value, one per line, for scrub()

JSON from the panel:
  {"sets": [{"type": "ssh", "name": "pve root", "hosts": ["172.16.0.30"],
             "fields": {"user": "root", "password": "..."}, "save": false}, ...],
   "vault": {"passphrase": "...", "use": ["CRED_pve-root"]}}
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import sys
from pathlib import Path

# type -> (required fields, optional fields, secret fields)
TYPES = {
    "ssh":        ({"user"}, {"password", "key", "key_path", "port"}, {"password", "key"}),
    "snmp":       ({"version"}, {"port", "community", "user", "level", "auth_proto", "auth_pass",
                                 "priv_proto", "priv_pass"}, {"community", "auth_pass", "priv_pass"}),
    "aws":        ({"access_key_id", "secret_access_key"}, {"session_token", "region"},
                   {"secret_access_key", "session_token"}),
    "azure":      ({"tenant_id", "client_id", "client_secret"}, {"subscription"}, {"client_secret"}),
    "gcp":        ({"key_json"}, {"project"}, {"key_json"}),
    "k8s":        ({"kubeconfig"}, {"context"}, {"kubeconfig"}),
    # token-based cloud APIs
    "digitalocean": ({"token"}, set(), {"token"}),
    "linode":       ({"token"}, set(), {"token"}),
    "hetzner":      ({"token"}, set(), {"token"}),
    "vultr":        ({"token"}, set(), {"token"}),
    "scaleway":     ({"secret_key"}, {"access_key", "project_id"}, {"secret_key"}),
    "cloudflare":   ({"token"}, set(), {"token"}),
    "ibm":          ({"api_key"}, {"regions"}, {"api_key"}),
    "ovh":          ({"app_key", "app_secret", "consumer_key"}, {"endpoint"}, {"app_secret", "consumer_key"}),
    "alibaba":      ({"access_key_id", "access_key_secret"}, {"regions"}, {"access_key_secret"}),
    "oci":          ({"tenancy", "user", "fingerprint", "private_key"}, {"region"}, {"private_key"}),
}
API_TYPES = {"digitalocean", "linode", "hetzner", "vultr", "scaleway", "cloudflare", "ibm", "ovh", "alibaba", "oci"}
HOST_TYPES = {"ssh", "snmp"}            # credentials that apply per host
SNMP_AUTH = {"MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"}
SNMP_PRIV = {"DES", "AES", "AES-192", "AES-256"}
SNMP_LEVEL = {"noAuthNoPriv", "authNoPriv", "authPriv"}
MAX_FIELD = 64 * 1024                   # kubeconfig / key JSON can be a few KB


class Bad(ValueError):
    pass


def _clean_hosts(hosts) -> list[str]:
    out = []
    for h in hosts or []:
        h = str(h).strip()
        if not h:
            continue
        try:
            net = ipaddress.ip_network(h, strict=False)
        except ValueError:
            raise Bad(f"host list entry {h!r} is not an IP address or range")
        if net.version != 4:
            raise Bad(f"{h!r}: only IPv4 is supported")
        out.append(str(net.network_address) if net.prefixlen == 32 else str(net))
    return out


def validate(s: dict, n: int) -> dict:
    t = s.get("type")
    if t not in TYPES:
        raise Bad(f"credential {n}: unknown type {t!r}")
    req, opt, _ = TYPES[t]
    f = s.get("fields") if isinstance(s.get("fields"), dict) else {}
    fields = {}
    for k, v in f.items():
        if k not in req | opt:
            continue
        v = "" if v is None else str(v)
        if len(v) > MAX_FIELD:
            raise Bad(f"credential {n}: field {k} is too long")
        if "\0" in v:
            raise Bad(f"credential {n}: field {k} contains a NUL byte")
        if k not in ("key", "key_json", "kubeconfig", "private_key"):
            v = v.strip()
            if "\n" in v or "\r" in v:
                raise Bad(f"credential {n}: field {k} must be one line")
        if v:
            fields[k] = v
    missing = [k for k in req if k not in fields]
    if missing:
        raise Bad(f"credential {n} ({t}): missing {', '.join(sorted(missing))}")
    name = re.sub(r"[\x00-\x1f]", "", str(s.get("name") or "")).strip()[:60] or f"{t} {n}"

    if "port" in fields:
        if not fields["port"].isdigit() or not 1 <= int(fields["port"]) <= 65535:
            raise Bad(f"credential {n} ({t}): port must be 1-65535")
    if t == "ssh":
        if not (fields.get("password") or fields.get("key") or fields.get("key_path")):
            raise Bad(f"credential {n} (ssh): give a password, a private key or a key file path")
        if not re.match(r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$", fields["user"]):
            raise Bad(f"credential {n} (ssh): user name has characters SSH would not accept")
        if fields.get("key") and "PRIVATE KEY" not in fields["key"]:
            raise Bad(f"credential {n} (ssh): the pasted key does not look like a private key")
        if fields.get("key") and not fields["key"].endswith("\n"):
            fields["key"] += "\n"
        if fields.get("key_path") and not Path(os.path.expanduser(fields["key_path"])).is_file():
            raise Bad(f"credential {n} (ssh): key file {fields['key_path']} not found on this machine")
    if t == "snmp":
        if fields["version"] not in ("2c", "3"):
            raise Bad(f"credential {n} (snmp): version must be 2c or 3")
        if fields["version"] == "2c" and not fields.get("community"):
            raise Bad(f"credential {n} (snmp v2c): missing community")
        if fields["version"] == "3":
            if not fields.get("user"):
                raise Bad(f"credential {n} (snmp v3): missing user")
            lvl = fields.setdefault("level", "authPriv")
            if lvl not in SNMP_LEVEL:
                raise Bad(f"credential {n} (snmp v3): level must be one of {', '.join(sorted(SNMP_LEVEL))}")
            if lvl != "noAuthNoPriv":
                if fields.setdefault("auth_proto", "SHA") not in SNMP_AUTH or len(fields.get("auth_pass", "")) < 8:
                    raise Bad(f"credential {n} (snmp v3): auth protocol {sorted(SNMP_AUTH)} and an auth password of 8+ characters")
            if lvl == "authPriv":
                if fields.setdefault("priv_proto", "AES") not in SNMP_PRIV or len(fields.get("priv_pass", "")) < 8:
                    raise Bad(f"credential {n} (snmp v3): privacy protocol {sorted(SNMP_PRIV)} and a privacy password of 8+ characters")
    if t == "gcp":
        try:
            j = json.loads(fields["key_json"])
            if j.get("type") != "service_account":
                raise ValueError
        except ValueError:
            raise Bad(f"credential {n} (gcp): key_json must be a service account key file (JSON)")
    if t == "aws" and fields.get("region") and not re.match(r"^[a-z]{2}(-[a-z]+)+-\d$", fields["region"]):
        raise Bad(f"credential {n} (aws): region {fields['region']!r} does not look like an AWS region")

    if t == "ovh" and fields.get("endpoint", "eu") not in ("eu", "ca", "us"):
        raise Bad(f"credential {n} (ovh): endpoint must be eu, ca or us")
    if t == "oci" and "PRIVATE KEY" not in fields["private_key"]:
        raise Bad(f"credential {n} (oci): the private key does not look like a PEM private key")
    for k in ("regions", "region"):
        if k in fields and not re.match(r"^[a-z0-9-]+(\s*,\s*[a-z0-9-]+)*$", fields[k]):
            raise Bad(f"credential {n} ({t}): {k} must be region names separated by commas")

    hosts = _clean_hosts(s.get("hosts")) if t in HOST_TYPES else []
    return {"id": f"c{n}", "type": t, "name": name, "hosts": hosts, "fields": fields,
            "save": bool(s.get("save"))}


def _path(d) -> Path:
    return Path(d) / "creds.json"


def load(d) -> dict:
    p = _path(d)
    return json.loads(p.read_text()) if p.exists() else {"sets": [], "vault": {}}


def store(d, doc) -> None:
    p = _path(d)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(doc, fh)


def ingest(d):
    raw = sys.stdin.read()
    if not raw.strip():
        store(d, {"sets": [], "vault": {}})
        return 0
    try:
        doc = json.loads(raw)
        sets = [validate(s, i + 1) for i, s in enumerate(doc.get("sets") or [])]
    except (ValueError, AttributeError) as e:
        print(f"credentials rejected: {e}", file=sys.stderr)
        return 2
    v = doc.get("vault") if isinstance(doc.get("vault"), dict) else {}
    vault = {"passphrase": str(v.get("passphrase") or ""),
             "use": [str(x) for x in (v.get("use") or []) if re.match(r"^(CRED_[A-Za-z0-9_-]{1,64}|\*)$", str(x))]}
    store(d, {"sets": sets, "vault": vault})
    for s in sets:
        print(f"{s['type']}\t{s['name']}")
    return 0


def slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-")[:64] or "cred"


def from_vault(d):
    doc = load(d)
    use = set(doc.get("vault", {}).get("use") or [])
    if not use:
        return 0
    have = {("CRED_" + slug(s["name"])) for s in doc["sets"]}
    n = len(doc["sets"])
    for line in sys.stdin.read().splitlines():
        k, _, v = line.partition("=")
        if not k.startswith("CRED_") or not ("*" in use or k in use) or k in have:
            continue
        try:
            s = json.loads(base64.b64decode(v))
            s["save"] = False
            n += 1
            vs = validate(s, n)
            vs["from_vault"] = k
            doc["sets"].append(vs)
            print(f"{vs['type']}\t{vs['name']}")
        except (ValueError, Bad) as e:
            print(f"vault entry {k} skipped: {e}", file=sys.stderr)
    store(d, doc)
    return 0


def _ip_in(ip, hosts) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(h) for h in hosts)


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)
    cmd, d = argv[1], argv[2]
    if cmd == "ingest":
        return ingest(d)
    if cmd == "from-vault":
        return from_vault(d)
    doc = load(d)
    sets = {s["id"]: s for s in doc["sets"]}
    if cmd == "count":
        print(sum(1 for s in doc["sets"] if s["type"] == argv[3]))
    elif cmd == "pick":
        t, ip = argv[3], argv[4]
        for s in doc["sets"]:
            if s["type"] == t and (not s["hosts"] or _ip_in(ip, s["hosts"])):
                print(s["id"])
                break
    elif cmd == "hosts":
        for s in doc["sets"]:
            if s["type"] == argv[3]:
                for h in s["hosts"]:
                    print(h)
    elif cmd == "get":
        sys.stdout.write(sets.get(argv[3], {}).get("fields", {}).get(argv[4], ""))
    elif cmd == "name":
        sys.stdout.write(sets.get(argv[3], {}).get("name", ""))
    elif cmd == "tofile":
        val = sets.get(argv[3], {}).get("fields", {}).get(argv[4], "")
        fd = os.open(argv[5], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(val)
    elif cmd == "vaultpass":
        sys.stdout.write(doc.get("vault", {}).get("passphrase", ""))
    elif cmd == "to-vault":
        for s in doc["sets"]:
            if s.get("save"):
                body = {k: s[k] for k in ("type", "name", "hosts", "fields")}
                print(f"CRED_{slug(s['name'])}=" + base64.b64encode(json.dumps(body).encode()).decode())
    elif cmd == "secrets":
        for s in doc["sets"]:
            for k in TYPES[s["type"]][2]:
                v = s["fields"].get(k)
                if v:
                    for line in v.splitlines():       # multi-line values: each line
                        if len(line.strip()) >= 4:
                            print(line.strip())
        pp = doc.get("vault", {}).get("passphrase")
        if pp:
            print(pp)
    else:
        sys.exit(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
