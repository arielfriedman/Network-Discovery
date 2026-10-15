#!/usr/bin/env python3
"""Read the title and server name of web pages on open ports.

  http_probe.py HOSTS_DIR OUT_JSON

nmap only runs its http-title script on ports it recognised as HTTP; apps on
unusual ports (an Express app on 3001 that nmap calls "nessus?") were left
unnamed. For every open TCP port in HOSTS_DIR/*.xml whose service is HTTP
(or that nmap could not name, or that speaks TLS),
or whose fingerprint shows an HTTP reply, this sends one plain GET / (and
follows up to two redirects on the same host and port), reads at most 64 KB
and records: final path, status, <title>, Server header. No credentials, no
other requests. TLS is tried when the service says ssl/https or plain HTTP
fails; certificates are not verified (this only reads a public page title).
"""
from __future__ import annotations

import concurrent.futures as cf
import glob
import html
import http.client
import json
import os
import re
import ssl
import sys
import xml.etree.ElementTree as ET

TIMEOUT = 4
MAX_BYTES = 64 * 1024
RAW_PRINT = {9100, 9101, 9102, 515}


def candidates(hosts_dir: str):
    for path in glob.glob(os.path.join(hosts_dir, "*.xml")):
        try:
            host = ET.parse(path).getroot().find("host")
        except (ET.ParseError, OSError):
            continue
        if host is None:
            continue
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            continue
        ip = addr.get("addr")
        for p in host.findall("ports/port"):
            st, s = p.find("state"), p.find("service")
            if st is None or st.get("state") != "open" or p.get("protocol") != "tcp":
                continue
            name = (s.get("name", "") if s is not None else "")
            tunnel = (s.get("tunnel", "") if s is not None else "")
            fp = " ".join(sc.get("output") or "" for sc in p.findall("script[@id='fingerprint-strings']"))
            # also ports nmap could not name ("wpl-analytics?" for Proxmox on 8006) and TLS ports
            unknown = name.endswith("?") or name in ("", "unknown") or tunnel == "ssl"
            if int(p.get("portid")) in RAW_PRINT:
                continue                            # anything sent to a raw print port gets printed
            if "http" in name or "HTTP/1." in fp or (unknown and "ssh" not in name):
                tls = tunnel == "ssl" or name in ("https", "ssl/http", "https-alt")
                yield ip, int(p.get("portid")), tls


def get(ip: str, port: int, tls: bool, path: str = "/"):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = (http.client.HTTPSConnection(ip, port, timeout=TIMEOUT, context=ctx) if tls
            else http.client.HTTPConnection(ip, port, timeout=TIMEOUT))
    try:
        conn.request("GET", path, headers={"User-Agent": "SentinelScan (identification)", "Accept": "text/html"})
        r = conn.getresponse()
        body = r.read(MAX_BYTES)
        return r.status, dict(r.getheaders()), body
    finally:
        conn.close()


def probe(ip: str, port: int, tls: bool) -> dict | None:
    for use_tls in ([tls, not tls]):
        path, out = "/", {"ip": ip, "port": port, "tls": use_tls}
        try:
            for _ in range(3):                     # first request + 2 redirects
                status, hdr, body = get(ip, port, use_tls, path)
                hdr = {k.lower(): v for k, v in hdr.items()}
                out.update(status=status, path=path, server=hdr.get("server", "")[:80])
                loc = hdr.get("location", "")
                if status in (301, 302, 303, 307, 308) and loc:
                    m = re.match(r"^(?:(https?)://([^/]+))?(/[^\s]*)$", loc)
                    same = m and (not m.group(2) or m.group(2).split(":")[0] == ip)
                    if same and m.group(1) == "https" and not use_tls:
                        use_tls = True                 # plain HTTP sends us to HTTPS on the same port
                        out["tls"] = True
                        path = m.group(3)[:200]
                        continue
                    if same:
                        path = m.group(3)[:200]
                        continue
                    out["redirect"] = loc[:200]
                break
            m = re.search(rb"<title[^>]*>(.*?)</title>", body or b"", re.I | re.S)
            if m:
                out["title"] = html.unescape(m.group(1).decode("utf-8", "replace")).strip()[:120]
            return out
        except (OSError, http.client.HTTPException, ssl.SSLError):
            continue
    return None


def main(argv):
    if len(argv) != 3:
        sys.exit(__doc__)
    jobs = list(candidates(argv[1]))
    results = []
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        for r in ex.map(lambda j: probe(*j), jobs):
            if r:
                results.append(r)
    with open(argv[2], "w") as fh:
        json.dump(results, fh, indent=1)
    print(f"{len(results)} web page(s) read on {len(jobs)} port(s)")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
