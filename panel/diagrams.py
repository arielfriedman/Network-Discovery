"""Network drawings of a finished scan (docs/DIAGRAMS.md).

From a network scan's findings.json this builds:

* a draw.io file (.drawio, the open mxGraph XML format) - edit it in the draw.io
  desktop app or on diagrams.net. Page 1 "Network": internet, gateway, the
  local network and every host, grouped by device type; hypervisors hold their
  VMs. Page 2 "Virtual machines" (when the scan listed any): each hypervisor
  with its VMs, CPU, memory and disks.
* an SVG of page 1 from the same layout, so the dashboard can show a preview
  with nothing extra installed.
* PNG / PDF through the draw.io desktop CLI when it is installed.
* a diagrams.net link that carries the drawing in the URL fragment (after
  '#'), which browsers never send to the server.

Host names, vendors and app names come from the network (mDNS, banners), so
labels are plain text (draw.io html=0) and everything is XML-escaped.
"""
from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
import zlib
from xml.sax.saxutils import escape, quoteattr

# device type -> (fill, stroke) - draw.io's standard palette
COLORS = {
    "Router / Wi-Fi": ("#ffe6cc", "#d79b00"),
    "Hypervisor": ("#e1d5e7", "#9673a6"),
    "NAS / storage": ("#d5e8d4", "#82b366"),
    "Linux server": ("#dae8fc", "#6c8ebf"),
    "Windows PC / server": ("#dae8fc", "#6c8ebf"),
    "Raspberry Pi": ("#f8cecc", "#b85450"),
    "Printer": ("#fff2cc", "#d6b656"),
    "IP camera": ("#fff2cc", "#d6b656"),
    "Smart home / IoT": ("#fff2cc", "#d6b656"),
    "TV / streamer": ("#f5f5f5", "#666666"),
    "Game console": ("#f5f5f5", "#666666"),
    "Apple device": ("#f5f5f5", "#666666"),
    "Phone / tablet": ("#f5f5f5", "#666666"),
}
UNKNOWN = "Other / unidentified"
GREY = ("#f5f5f5", "#666666")
ORDER = ["Hypervisor", "Linux server", "Windows PC / server", "NAS / storage", "Raspberry Pi", "Printer",
         "IP camera", "Smart home / IoT", "TV / streamer", "Game console", "Apple device", "Phone / tablet"]

BOX_W, BOX_H, GAP, PAD, HEAD = 220, 96, 20, 16, 30
PER_ROW = 3
BUS_H = 12


# ── data -> layout ───────────────────────────────────────────────────────────
def _short(s, n=34):
    s = str(s or "").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _name(h: dict | None) -> str | None:
    n = (h or {}).get("hostname")
    return None if not n or n in ("_gateway", "localhost") else n     # _gateway: systemd-resolved's alias


def _host_lines(h: dict, scanner_ip: str | None) -> list[str]:
    name = _name(h) or (h.get("vm") or {}).get("name")
    lines = [_short(name) if name else h["ip"]]
    if name:
        lines.append(h["ip"])
    if h["ip"] == scanner_ip:
        lines.append("this PC (scanner)")
    what = h.get("os") or (h.get("vendor") if h.get("vendor") and not str(h.get("vendor")).startswith("(") else "")
    if what:
        lines.append(_short(what))
    ports = [str(p.get("port", "")).split("/")[0] for p in h.get("ports") or []]
    if ports:
        lines.append("ports " + _short(" ".join(ports[:8]) + (" …" if len(ports) > 8 else ""), 30))
    return lines[:4]


def _tooltip(h: dict) -> str:
    out = [f"{h['ip']}" + (f"  {h['hostname']}" if h.get("hostname") else "")]
    for k, label in (("device_type", "type"), ("os", "OS"), ("vendor", "vendor"), ("mac", "MAC")):
        if h.get(k):
            out.append(f"{label}: {h[k]}")
    for p in (h.get("ports") or [])[:30]:
        out.append(f"{p.get('port')}  {p.get('service') or ''}  {p.get('version') or ''}".rstrip())
    apps = [a.get("name") for a in h.get("apps") or [] if a.get("name")]
    if apps:
        out.append("apps: " + ", ".join(apps[:10]))
    return "\n".join(out)


def _vm_lines(v: dict) -> list[str]:
    lines = [_short(v.get("name") or f"{v.get('kind')} {v.get('id')}")]
    meta = [f"{'CT' if v.get('kind') == 'lxc' else 'VM'} {v.get('id')}", v.get("status") or ""]
    lines.append(" · ".join(x for x in meta if x))
    res = []
    if v.get("vcpus"):
        res.append(f"{v['vcpus']} vCPU")
    if v.get("memory_mb"):
        res.append(f"{round(v['memory_mb'] / 1024, 1):g} GB RAM")
    if res:
        lines.append(", ".join(res))
    if v.get("host_ip"):
        lines.append(v["host_ip"])
    return lines[:4]


class Layout:
    """Boxes and lines with absolute coordinates; both writers draw from this."""

    def __init__(self):
        self.nodes: list[dict] = []     # id, x, y, w, h, lines, fill, stroke, kind, parent, tooltip
        self.edges: list[dict] = []     # id, source, target, points [(x, y), ...]
        self.width = self.height = 0

    def node(self, **kw) -> str:
        kw.setdefault("id", f"n{len(self.nodes) + 2}")
        kw.setdefault("parent", None)
        kw.setdefault("tooltip", "")
        self.nodes.append(kw)
        return kw["id"]

    def edge(self, source, target, points, label="", pins=""):
        # pins: draw.io exit/entry points, so draw.io routes the line where the SVG draws it
        self.edges.append({"id": f"e{len(self.edges) + 2}", "source": source, "target": target,
                           "points": points, "label": label, "pins": pins})


def _group_size(n: int) -> tuple[int, int]:
    cols = max(1, min(PER_ROW, n))
    rows = (n + cols - 1) // cols
    return PAD * 2 + cols * BOX_W + (cols - 1) * GAP, HEAD + PAD * 2 + rows * BOX_H + (rows - 1) * GAP


def network_layout(d: dict) -> Layout:
    meta = d.get("meta") or {}
    gw, me = meta.get("gateway"), meta.get("scanner_ip")
    hosts = list(d.get("hosts") or [])
    vms = list(d.get("vms") or [])
    by_ip = {h["ip"]: h for h in hosts}

    # hypervisors with an inventory hold their VMs; a VM seen on the network is drawn there only
    hv_vms: dict[str, list[dict]] = {}
    for v in vms:
        hv_vms.setdefault(v.get("hypervisor") or "?", []).append(v)
    in_vm = {v["host_ip"] for v in vms if v.get("host_ip")}

    groups: dict[str, list] = {}
    for h in hosts:
        if h["ip"] == gw or h["ip"] in in_vm or h["ip"] in hv_vms:
            continue
        groups.setdefault(h.get("device_type") or UNKNOWN, []).append(("host", h))
    names = [t for t in ORDER if t in groups] + sorted(t for t in groups if t not in ORDER and t != UNKNOWN)
    if UNKNOWN in groups:
        names.append(UNKNOWN)
    blocks = []                                  # (title, items, colors)
    for ip, lst in hv_vms.items():
        h = by_ip.get(ip, {"ip": ip})
        title = f"Hypervisor {h.get('hostname') or ip}" + (f" ({ip})" if h.get("hostname") else "")
        items = ([("host", h)] if ip in by_ip else []) + [("vm", v) for v in sorted(
            lst, key=lambda v: (v.get("status") != "running", str(v.get("id"))))]
        blocks.append((title, items, COLORS["Hypervisor"]))
    for t in names:
        blocks.append((f"{t} ({len(groups[t])})", sorted(groups[t], key=lambda x: _ipkey(x[1]["ip"])),
                       COLORS.get(t, GREY)))

    L = Layout()
    # alternate blocks above / below the network line, biggest first
    blocks.sort(key=lambda b: -len(b[1]))
    above, below = blocks[0::2], blocks[1::2]

    def row_width(bs):
        return sum(_group_size(len(b[1]))[0] for b in bs) + GAP * 2 * max(0, len(bs) - 1)

    left = 40 + 180 + 80                          # internet / gateway column
    bus_w = max(row_width(above), row_width(below), 400)
    top_h = max([_group_size(len(b[1]))[1] for b in above] or [0])
    bus_y = 40 + max(top_h, 200) + 60

    # internet -> gateway -> network line
    gw_h = by_ip.get(gw) if gw else None
    inet = L.node(x=40, y=bus_y - 230, w=180, h=90, lines=["Internet"], fill="#ffffff", stroke="#666666",
                  kind="cloud")
    gw_lines = (["Gateway", gw] + ([_short(_name(gw_h))] if _name(gw_h) else [])
                + ([_short(gw_h.get("vendor"))] if gw_h and gw_h.get("vendor") else [])) if gw else ["Gateway", "unknown"]
    gwid = L.node(x=40, y=bus_y - 110, w=180, h=80, lines=gw_lines[:4], fill=COLORS["Router / Wi-Fi"][0],
                  stroke=COLORS["Router / Wi-Fi"][1], kind="box", tooltip=_tooltip(gw_h) if gw_h else "")
    L.edge(inet, gwid, [(130, bus_y - 140), (130, bus_y - 110)],
           pins="exitX=0.5;exitY=1;exitDx=0;exitDy=0;entryX=0.5;entryY=0;entryDx=0;entryDy=0;")
    net = meta.get("local_net") or meta.get("target") or "local network"
    bus = L.node(x=left, y=bus_y, w=bus_w, h=BUS_H, lines=[f"LAN {net}"], fill="#666666", stroke="#666666",
                 kind="bus")
    L.edge(gwid, bus, [(220, bus_y - 70), (left - 40, bus_y - 70), (left - 40, bus_y + BUS_H / 2), (left, bus_y + BUS_H / 2)],
           pins="exitX=1;exitY=0.5;exitDx=0;exitDy=0;entryX=0;entryY=0.5;entryDx=0;entryDy=0;")

    def place(bs, is_above):
        x = left
        for title, items, (fill, stroke) in bs:
            w, h = _group_size(len(items))
            y = bus_y - 50 - h if is_above else bus_y + BUS_H + 50
            gid = L.node(x=x, y=y, w=w, h=h, lines=[title], fill=fill, stroke=stroke, kind="group")
            cols = max(1, min(PER_ROW, len(items)))
            for i, (kind, obj) in enumerate(items):
                bx = x + PAD + (i % cols) * (BOX_W + GAP)
                by = y + HEAD + PAD + (i // cols) * (BOX_H + GAP)
                if kind == "vm":
                    run = obj.get("status") == "running"
                    L.node(x=bx, y=by, w=BOX_W, h=BOX_H, lines=_vm_lines(obj), parent=gid, kind="box",
                           fill="#ffffff" if run else "#eeeeee", stroke=stroke, dashed=not run,
                           tooltip="\n".join(_vm_lines(obj)))
                else:
                    t = obj.get("device_type")
                    f2, s2 = COLORS.get(t, GREY) if t else GREY
                    L.node(x=bx, y=by, w=BOX_W, h=BOX_H, lines=_host_lines(obj, me), parent=gid, kind="box",
                           fill="#ffffff", stroke=s2, bold=obj["ip"] == me, tooltip=_tooltip(obj))
            cx = x + w / 2
            ex = round((cx - left) / bus_w, 4)               # where on the LAN line it joins
            if is_above:
                L.edge(gid, bus, [(cx, y + h), (cx, bus_y)],
                       pins=f"exitX=0.5;exitY=1;exitDx=0;exitDy=0;entryX={ex};entryY=0;entryDx=0;entryDy=0;")
            else:
                L.edge(gid, bus, [(cx, y), (cx, bus_y + BUS_H)],
                       pins=f"exitX=0.5;exitY=0;exitDx=0;exitDy=0;entryX={ex};entryY=1;entryDx=0;entryDy=0;")
            x += w + GAP * 2

    place(above, True)
    place(below, False)
    bottom = max([n["y"] + n["h"] for n in L.nodes] or [bus_y + 100])
    L.width = left + bus_w + 40
    L.height = bottom + 40
    title = f"SentinelScan · {net} · {meta.get('started', '')[:16].replace('T', ' ')} · {len(hosts)} hosts"
    L.node(x=40, y=10, w=900, h=24, lines=[title], fill="none", stroke="none", kind="title")
    return L


def vm_layout(d: dict) -> Layout | None:
    vms = list(d.get("vms") or [])
    if not vms:
        return None
    hv_by = {}
    for v in vms:
        hv_by.setdefault(v.get("hypervisor") or "?", []).append(v)
    hvinfo = {h.get("host"): h for h in d.get("hypervisors") or []}
    L = Layout()
    y = 50
    for ip, lst in hv_by.items():
        info = hvinfo.get(ip, {})
        title = f"{info.get('platform', 'hypervisor')} {info.get('version') or ''} on {ip} - {len(lst)} VM(s)/container(s)"
        cols = min(4, len(lst))
        rows = (len(lst) + cols - 1) // cols
        w = PAD * 2 + cols * 260 + (cols - 1) * GAP
        h = HEAD + PAD * 2 + rows * 130 + (rows - 1) * GAP
        gid = L.node(x=40, y=y, w=w, h=h, lines=[title], fill=COLORS["Hypervisor"][0],
                     stroke=COLORS["Hypervisor"][1], kind="group")
        for i, v in enumerate(sorted(lst, key=lambda v: str(v.get("id")))):
            disks = []
            for dk in v.get("disks") or []:
                media = "/".join(m for m in (dk.get("media") or []) if m and m != "unknown")
                size = f"{dk['size_gb']:g} GB" if dk.get("size_gb") else ""
                disks.append(" ".join(x for x in (dk.get("id"), size, media) if x))
            lines = _vm_lines(v) + ([_short("disks: " + ", ".join(disks), 40)] if disks else [])
            guest = v.get("guest") or {}
            if guest.get("os"):
                lines.append(_short(guest["os"], 40))
            run = v.get("status") == "running"
            L.node(x=40 + PAD + (i % cols) * (260 + GAP), y=y + HEAD + PAD + (i // cols) * (130 + GAP), w=260, h=130,
                   lines=lines[:6], parent=gid, kind="box", fill="#ffffff" if run else "#eeeeee",
                   stroke=COLORS["Hypervisor"][1], dashed=not run, tooltip="\n".join(lines))
        L.width = max(L.width, 40 + w + 40)
        y += h + 40
    L.height = y
    return L


def _ipkey(ip: str):
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999,)


# ── writers ──────────────────────────────────────────────────────────────────
def _style(n: dict) -> str:
    k = n["kind"]
    if k == "group":
        return (f"swimlane;startSize={HEAD};html=0;whiteSpace=wrap;rounded=1;fillColor={n['fill']};"
                f"strokeColor={n['stroke']};swimlaneFillColor=#ffffff;fontStyle=1;container=1;pointerEvents=0;")
    if k == "cloud":
        return f"ellipse;shape=cloud;whiteSpace=wrap;html=0;fillColor={n['fill']};strokeColor={n['stroke']};fontStyle=1;"
    if k == "bus":
        return (f"rounded=1;html=0;fillColor={n['fill']};strokeColor={n['stroke']};fontColor=#333333;"
                "labelPosition=center;verticalLabelPosition=top;align=left;verticalAlign=bottom;fontStyle=1;")
    if k == "title":
        return "text;html=0;align=left;verticalAlign=middle;fontSize=14;fontStyle=1;"
    return (f"rounded=1;whiteSpace=wrap;html=0;fillColor={n['fill']};strokeColor={n['stroke']};align=center;"
            f"verticalAlign=middle;fontSize=11;spacing=4;" + ("dashed=1;" if n.get("dashed") else "")
            + ("fontStyle=1;strokeWidth=2;" if n.get("bold") else ""))


def _mxcells(L: Layout) -> str:
    pos = {n["id"]: n for n in L.nodes}
    out = []
    for n in L.nodes:
        x, y = n["x"], n["y"]
        if n["parent"]:
            p = pos[n["parent"]]
            x, y = x - p["x"], y - p["y"]
        value = quoteattr("\n".join(n["lines"]))
        geo = f'<mxGeometry x="{x:g}" y="{y:g}" width="{n["w"]:g}" height="{n["h"]:g}" as="geometry"/>'
        cell = (f'<mxCell style={quoteattr(_style(n))} vertex="1" parent="{n["parent"] or 1}">{geo}</mxCell>')
        if n.get("tooltip"):
            out.append(f'<UserObject label={value} tooltip={quoteattr(n["tooltip"])} id="{n["id"]}">{cell}</UserObject>')
        else:
            out.append(cell.replace("<mxCell ", f'<mxCell id="{n["id"]}" value={value} ', 1))
    for e in L.edges:
        pts = "".join(f'<mxPoint x="{x:g}" y="{y:g}"/>' for x, y in e["points"][1:-1])
        out.append(f'<mxCell id="{e["id"]}" value={quoteattr(e["label"])} style="edgeStyle=orthogonalEdgeStyle;'
                   f'rounded=1;orthogonalLoop=1;jettySize=auto;html=0;endArrow=none;strokeWidth=2;strokeColor=#666666;{e["pins"]}" '
                   f'edge="1" parent="1" source="{e["source"]}" target="{e["target"]}">'
                   f'<mxGeometry relative="1" as="geometry">'
                   + (f'<Array as="points">{pts}</Array>' if pts else "") + '</mxGeometry></mxCell>')
    return "".join(out)


def drawio(d: dict) -> str:
    pages = [("Network", network_layout(d))]
    vl = vm_layout(d)
    if vl:
        pages.append(("Virtual machines", vl))
    body = []
    for i, (name, L) in enumerate(pages):
        body.append(f'<diagram id="p{i}" name={quoteattr(name)}><mxGraphModel dx="{L.width:g}" dy="{L.height:g}" '
                    f'grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="0" '
                    f'pageScale="1" math="0" shadow="0"><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
                    f'{_mxcells(L)}</root></mxGraphModel></diagram>')
    return f'<?xml version="1.0" encoding="UTF-8"?>\n<mxfile host="SentinelScan" version="24.0.0">{"".join(body)}</mxfile>\n'


def svg(d: dict) -> str:
    """Page 1 as SVG (the dashboard preview and the PNG download in the browser)."""
    L = network_layout(d)
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{L.width:g}" height="{L.height:g}" '
           f'viewBox="0 0 {L.width:g} {L.height:g}" font-family="Helvetica, Arial, sans-serif">'
           f'<rect width="100%" height="100%" fill="#ffffff"/>']
    for e in L.edges:
        pts = " ".join(f"{x:g},{y:g}" for x, y in e["points"])
        out.append(f'<polyline points="{pts}" fill="none" stroke="#666666" stroke-width="2"/>')
    for n in L.nodes:
        x, y, w, h, k = n["x"], n["y"], n["w"], n["h"], n["kind"]
        tip = f"<title>{escape(n['tooltip'])}</title>" if n.get("tooltip") else ""
        if k == "title":
            out.append(f'<text x="{x:g}" y="{y + 17:g}" font-size="14" font-weight="bold" fill="#333">{escape(n["lines"][0])}</text>')
            continue
        if k == "cloud":
            out.append(f'<g>{tip}<ellipse cx="{x + w / 2:g}" cy="{y + h / 2:g}" rx="{w / 2:g}" ry="{h / 2:g}" '
                       f'fill="{n["fill"]}" stroke="{n["stroke"]}" stroke-width="1.5"/>'
                       f'<text x="{x + w / 2:g}" y="{y + h / 2 + 5:g}" font-size="13" font-weight="bold" '
                       f'text-anchor="middle" fill="#333">{escape(n["lines"][0])}</text></g>')
            continue
        if k == "bus":
            out.append(f'<rect x="{x:g}" y="{y:g}" width="{w:g}" height="{h:g}" rx="5" fill="{n["fill"]}"/>'
                       f'<text x="{x + 4:g}" y="{y - 6:g}" font-size="12" font-weight="bold" fill="#333">{escape(n["lines"][0])}</text>')
            continue
        dash = ' stroke-dasharray="6 4"' if n.get("dashed") else ""
        sw = 2.5 if n.get("bold") else 1.2
        if k == "group":
            out.append(f'<g>{tip}<rect x="{x:g}" y="{y:g}" width="{w:g}" height="{h:g}" rx="8" fill="#ffffff" '
                       f'stroke="{n["stroke"]}" stroke-width="1.5"/><path d="M{x:g},{y + HEAD:g} v-{HEAD - 8:g} '
                       f'a8,8 0 0 1 8,-8 h{w - 16:g} a8,8 0 0 1 8,8 v{HEAD - 8:g} z" fill="{n["fill"]}" '
                       f'stroke="{n["stroke"]}" stroke-width="1.5"/><text x="{x + w / 2:g}" y="{y + 20:g}" '
                       f'font-size="12" font-weight="bold" text-anchor="middle" fill="#333">{escape(n["lines"][0])}</text></g>')
            continue
        lines = n["lines"]
        y0 = y + h / 2 - (len(lines) - 1) * 7 + 4
        text = "".join(f'<tspan x="{x + w / 2:g}" y="{y0 + i * 14:g}"'
                       + (' font-weight="bold"' if i == 0 else "") + f">{escape(t)}</tspan>"
                       for i, t in enumerate(lines))
        out.append(f'<g>{tip}<rect x="{x:g}" y="{y:g}" width="{w:g}" height="{h:g}" rx="8" fill="{n["fill"]}" '
                   f'stroke="{n["stroke"]}" stroke-width="{sw}"{dash}/>'
                   f'<text font-size="11" text-anchor="middle" fill="#222">{text}</text></g>')
    out.append("</svg>")
    return "".join(out)


def diagrams_net_url(xml: str) -> str:
    """Open the drawing on diagrams.net. The data sits in the #fragment, which the
    browser keeps to itself: nothing is uploaded."""
    data = urllib.parse.quote(xml, safe="~()*!.'")                  # = encodeURIComponent
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    raw = co.compress(data.encode()) + co.flush()
    return "https://app.diagrams.net/#R" + base64.b64encode(raw).decode()


# ── draw.io desktop CLI (PNG / PDF) ──────────────────────────────────────────
def cli() -> str | None:
    for name in ("drawio", "draw.io"):
        p = shutil.which(name)
        if p:
            return p
    for p in ("/opt/drawio/drawio", "/opt/draw.io/drawio"):
        if os.path.exists(p):
            return p
    return None


def export(d: dict, fmt: str) -> bytes:
    """PNG or PDF of the drawing through the draw.io desktop app (it bundles the renderer)."""
    exe = cli()
    if not exe:
        raise RuntimeError("the draw.io desktop app is not installed")
    if fmt not in ("png", "pdf"):
        raise ValueError("png or pdf")
    with tempfile.TemporaryDirectory(prefix="sentinel-diagram-") as tmp:
        src, dst = os.path.join(tmp, "scan.drawio"), os.path.join(tmp, f"scan.{fmt}")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write(drawio(d))
        # png: page 1 at 2x; pdf: all pages (-a), each cropped to its drawing (--crop)
        cmd = [exe, "-x", "-f", fmt, "-b", "10"] + (["-s", "2"] if fmt == "png" else ["-a", "--crop"]) + ["-o", dst, src]
        if os.geteuid() == 0:
            cmd.append("--no-sandbox")                            # Electron refuses root without it
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            if not shutil.which("xvfb-run"):
                raise RuntimeError("no display for the draw.io app (running as a service?) - install xvfb "
                                   "(sudo apt install xvfb) or use the .drawio / SVG download")
            cmd = ["xvfb-run", "-a"] + cmd + ["--disable-gpu"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                           env=dict(os.environ, HOME=os.environ.get("HOME") or tmp))
        if not os.path.exists(dst):
            raise RuntimeError("draw.io export failed: " + (r.stderr or r.stdout or "no output").strip()[-300:])
        data = open(dst, "rb").read()
    if fmt == "png" and data.endswith(b"\x00\x00\x00\x00") and not data.endswith(b"IEND\xaeB`\x82"):
        data += b"IEND\xaeB`\x82"                                  # draw.io CLI can truncate the end chunk
    return data


SAFE_REF = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
