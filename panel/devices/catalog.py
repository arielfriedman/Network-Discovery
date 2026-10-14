"""
Supported models (Oct 2026). Sources and caveats: docs/DEVICE_MODELS.md.

A *family* groups models that are managed the same way, so wizards target
families, not individual models. Port names are what the Add-device form
suggests; the live interface list from the device always wins.
"""

CATALOG = {
    "fortinet": {
        "label": "Fortinet FortiGate",
        "families": {
            "fortios": {
                "label": "FortiGate (FortiOS 7.4 / 7.6 / 8.0)",
                "api": "FortiOS REST API over HTTPS, API token",
                "models": {
                    "FG-100F": {"ports": "mgmt, dmz, wan1, wan2, ha1, ha2, port1-port20, x1, x2"},
                    "FG-200E": {"ports": "mgmt, ha, wan1, wan2, port1-port18",
                                "note": "Still supported in FortiOS 8.0.1 (release notes, checked Oct 2026). "
                                        "Newer model in the range: FG-200G."},
                },
            },
        },
    },
    "cisco": {
        "label": "Cisco",
        "families": {
            "iosxe": {
                "label": "IOS-XE switches and routers",
                "api": "SSH CLI (auto-revert with 'configure terminal revert timer')",
                "models": {
                    "Catalyst 9200 / 9200L": {"ports": "GigabitEthernet1/0/1-48, uplinks Gi/Te1/1/1-4"},
                    "Catalyst 9300 / 9300L": {"ports": "GigabitEthernet1/0/1-48, uplinks Te1/1/1-8, Gi0/0 (Mgmt-vrf)"},
                    "Catalyst 8200 / 8300 Edge": {"ports": "GigabitEthernet0/0/0-n, TenGigabitEthernet0/0/x",
                                                  "note": "Must be in autonomous mode, not SD-WAN controller mode."},
                    "ISR 1100 (C1121 / C1131 / C1161)": {"ports": "WAN Gi0/0/0, LAN switch ports Gi0/1/0-7 (Vlan1)",
                                                        "note": "Must be in autonomous mode, not SD-WAN controller mode."},
                },
            },
            "cbs": {
                "label": "Catalyst 1200 / 1300, CBS 250 / 350 (Cisco Business)",
                "api": "SSH CLI (no auto-revert; backup before every change)",
                "models": {
                    "Catalyst 1300": {"ports": "gi1/0/1-48, te1/0/1-4"},
                    "Catalyst 1200": {"ports": "gi1/0/1-48, te1/0/1-4"},
                    "CBS350 (end of sale)": {"ports": "gi1/0/1-48, te1/0/1-4"},
                },
            },
        },
    },
    "paloalto": {
        "label": "Palo Alto Networks",
        "families": {
            "panos": {
                "label": "PAN-OS next-generation firewalls (PAN-OS 11.1 / 11.2 / 12.1)",
                "api": "PAN-OS XML API over HTTPS (changes go to the candidate config, then commit)",
                "models": {
                    "PA-440 / PA-450 / PA-460": {"ports": "ethernet1/1-1/8, MGT"},
                    "PA-1410 / PA-1420": {"ports": "ethernet1/1-1/22, MGT, HA1-A/HA1-B"},
                    "PA-3410 / PA-3420": {"ports": "ethernet1/1-1/n, MGT"},
                    "VM-Series (lab)": {"ports": "ethernet1/1-1/n, MGT"},
                },
            },
        },
    },
    "checkpoint": {
        "label": "Check Point",
        "families": {
            "spark": {
                "label": "Quantum Spark 1600 / 1800 / 1900 / 2000 (locally managed)",
                "api": "Spark REST API on port 4434 (run-clish-command)",
                "models": {
                    "Quantum Spark 1600 / 1800": {"ports": "WAN, DMZ, LAN1-LANn"},
                    "Quantum Spark 1900 / 2000": {"ports": "WAN, DMZ, LAN1-LANn"},
                },
                "setup": "On the appliance, enable the API once in clish: set rest-api mode on",
            },
            "mgmt": {
                "label": "Quantum Force 9100 / 9200 and other gateways, via the Management Server",
                "api": "Management API (web_api): changes in a session, then publish and install policy",
                "models": {
                    "Quantum Force 9100": {"ports": "Mgmt, Sync, ethX"},
                    "Quantum Force 9200": {"ports": "Mgmt, Sync, ethX"},
                    "Management Server (R81.20 / R82)": {"ports": ""},
                },
                "setup": "Connect to the Management Server's address, not the gateway's.",
            },
        },
    },
}


def families(vendor: str) -> dict:
    return CATALOG.get(vendor, {}).get("families", {})


def find_family(vendor: str, model: str) -> str:
    for key, fam in families(vendor).items():
        if model in fam["models"]:
            return key
    fams = list(families(vendor))
    return fams[0] if fams else ""
