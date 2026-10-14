# Device wizard: supported models and how each is managed

Researched October 2026 from vendor documentation. Items marked **[verify]** were not
confirmed from a primary source; check them on real hardware.

## Models

| Vendor | Models | Status |
|---|---|---|
| Fortinet | **FG-100F**, **FG-200E** | Both supported in FortiOS 7.4, 7.6 and **8.0** ([8.0.1 build 0245 supported models](https://docs.fortinet.com/document/fortigate/8.0.1/fortios-release-notes/760203/introduction-and-supported-models), [7.6.7](https://docs.fortinet.com/document/fortigate/7.6.7/fortios-release-notes/760203/introduction-and-supported-models)). **Correction 2026-10-14:** an earlier version of this file said the 200E reached end of sale in Oct 2025; no end-of-order notice could be found ([Fortinet Community](https://community.fortinet.com/support-forum-92/fortigate-200e-eol-190120)) - check the support portal's product life cycle page. Newer model in the range: 200G. |
| Cisco switches | **Catalyst 9200/9200L, 9300/9300L** (IOS-XE); **Catalyst 1200/1300** (Cisco Business) | Catalyst 1000 end of sale Apr 2025; CBS250/350 end of sale Oct 2024, replaced by Catalyst 1200/1300. |
| Cisco routers | **Catalyst 8200/8300 Edge**, **ISR 1100 (C1121/C1131/C1161)** | ISR 4000 last order Nov 2023 ([EOL14896](https://www.cisco.com/c/en/us/products/collateral/routers/4000-series-integrated-services-routers-isr/select-isr4k-series-platform-eol.html)). C8000/ISR1100 can run in autonomous or SD-WAN controller mode; the wizard needs autonomous. |
| Palo Alto | **PA-440/450/460**, **PA-1410/1420**, **PA-3410/3420**, VM-Series | PA-220 end of sale 2023; PA-820/850 end of sale Aug 2024 → PA-1400 ([HW EoL](https://paloaltonetworks.com/services/support/end-of-life-announcements/hardware-end-of-life-dates)). PA-500 series (2025, PAN-OS 12.1.2+) succeeds PA-400. |
| Check Point | **Quantum Spark 1600/1800/1900/2000** (Embedded Gaia), **Quantum Force 9100/9200** (Gaia, via Management Server) | Spark R82.00.10 adds R82 to 1600-2000; older 15xx are blocked from R82 ([sk184357](https://support.checkpoint.com/results/sk/sk184357)). |

## OS versions

| Platform | Versions |
|---|---|
| FortiGate | FortiOS 7.4 (EoS Nov 2028), 7.6 (EoS Jan 2030), 8.0 (current; 8.0.1 build 0245) |
| Cat 9200/9300, C8200/8300, ISR1100 | IOS-XE 17.x (17.9 / 17.12 extended; 17.15 / 17.18 current) |
| Catalyst 1200/1300 | Cisco Business firmware 4.x, not IOS **[verify]** |
| PA-400/1400/3400 | PAN-OS 11.1, 11.2, 12.1 ([matrix](https://docs.paloaltonetworks.com/compatibility-matrix/supported-os-releases-by-model/palo-alto-networks-next-gen-firewalls)) |
| Spark 1600-2000 | Embedded Gaia R81.10.x, R82.00.x |
| Quantum Force / Management | Gaia R81.20, R82, R82.10 |

## How the wizard talks to each

| Vendor | Interface | Notes |
|---|---|---|
| FortiGate | REST API `/api/v2/cmdb`, `/api/v2/monitor`, header `Authorization: Bearer <token>` | Token goes in the header (required from 7.4.5; 8.0 is token-only). Config backup `/api/v2/monitor/system/config/backup?scope=global` is GET on ≤7.4 and **POST on 7.6+** (8.0: not confirmed **[verify]**), needs super_admin. **8.0:** a REST API admin's trusted hosts may not be 0.0.0.0/0 ([8.0 REST API administrator](https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/399023/rest-api-administrator)). Changes apply immediately. |
| Cisco IOS-XE | SSH CLI | RESTCONF/NETCONF exist (Cat9300 16.8.1a+, Cat9200 16.9.2+, C8000 17.3.1+) but SSH works everywhere. Safe changes: `configure terminal revert timer <min>` + `configure confirm` (needs `archive`). |
| Cisco Catalyst 1200/1300 | SSH CLI | No RESTCONF/NETCONF ([C1300 datasheet](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-1300-series-switches/nb-06-cat1300-ser-data-sheet-cte-en.html)); no auto-revert. |
| Palo Alto | XML API `/api/` | `type=keygen` (POST user/password) → header `X-PAN-KEY`. `type=config&action=set|edit|delete|get|show&xpath=…&element=…` edits the candidate config; `type=commit` + poll `show jobs id`. `type=export&category=configuration` for backup. |
| Check Point Spark | `https://<gw>:4434/web-api/` | Enable with clish `set rest-api mode on`. Only 4 commands: `login`, `logout`, `generate-report`, `run-clish-command` (base64 clish script). ([R81.10.X Locally Managed Admin Guide](https://sc1.checkpoint.com/documents/SMB_R81.10.X/AdminGuides_Locally_Managed/EN/CP_R81.10.X_Quantum_Spark_1500_1600_1800_1900_2000_Appliances_Locally_Managed_AdminGuide.pdf)) |
| Check Point Management | `https://<mgmt>/web_api/` | `login` → header `X-chkp-sid`; changes held in a session until `publish` (or `discard`), then `install-policy`, poll `show-task`. |

## Interface names

| Model | Names |
|---|---|
| FG-100F | mgmt, dmz, wan1, wan2, ha1, ha2, port1-port20, x1, x2 ([HW accel 7.6](https://docs.fortinet.com/document/fortigate/7.6.7/hardware-acceleration/47902)) |
| FG-200E | mgmt, ha, wan1, wan2, port1-port14 (copper), port15-18 (SFP) |
| Cat9200/9300 | GigabitEthernet1/0/1-48, uplinks Gi/Te1/1/x; 9300 has Gi0/0 in Mgmt-vrf |
| ISR C1121-8P | WAN Gi0/0/0, LAN switch ports Gi0/1/0-7 **[verify]** |
| PA-1410 | ethernet1/1-1/12 copper, 1/13-18 SFP, 1/19-22 SFP+, MGT, HA1-A/B ([front panel](https://docs.paloaltonetworks.com/hardware/pa-1400-hardware-reference/pa-1400-series-overview/front-panel-1400-series)) |
| Spark 1600-2000 | WAN, DMZ, LAN1…LANn, VLANs as LAN1:2 |
| Quantum Force | Mgmt, Sync, ethX **[verify]** |

## Factory defaults (for lab setup)

| Device | Default |
|---|---|
| FortiGate | `https://192.168.1.99`, admin / blank password, forced change |
| PAN-OS | MGT `192.168.1.1`, admin / admin, forced change |
| Check Point Spark | `https://192.168.1.1:4434`, First Time Configuration Wizard |
| Check Point Gaia | `https://192.168.1.1`, admin / admin, First Time Wizard |
| Cisco IOS-XE | no default IP; console setup dialog or PnP |
