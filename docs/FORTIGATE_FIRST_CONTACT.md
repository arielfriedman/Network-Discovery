# FortiGate 100F / 200E: first contact with a production unit

There is no lab or spare FortiGate, so the first real connection is to a
production firewall. This procedure keeps that first contact **read-only on
both sides**: the FortiGate only accepts reads from the token, and the panel
refuses to apply anything while the device is in read-only mode (the
default). Written 2026-10-14; FortiOS 7.4 / 7.6 / 8.0.

## 1. On the FortiGate: a read-only REST API token

GUI (works the same on 7.4 / 7.6 / 8.0):

1. **System > Admin Profiles > Create New** - name `sentinel-readonly`,
   set every permission group to **Read** (none to Read/Write).
2. **System > Administrators > Create New > REST API Admin** - user name
   `sentinel`, administrator profile `sentinel-readonly`, **Trusted Hosts**:
   the panel machine's address only (e.g. `172.16.0.5/32`; FortiOS 8.0 does
   not allow 0.0.0.0/0 for API admins anyway). Leave PKI off.
3. Copy the API key shown once at the end. Treat it like a password.

CLI equivalent - compare the field names with `config system accprofile` /
`edit x` / `get` on your version before using it **[verify]**:

```
config system accprofile
    edit "sentinel-readonly"
        set secfabgrp read
        set ftviewgrp read
        set authgrp read
        set sysgrp read
        set netgrp read
        set loggrp read
        set fwgrp read
        set vpngrp read
        set utmgrp read
        set wanoptgrp read
        set wifi read
    next
end
config system api-user
    edit "sentinel"
        set accprofile "sentinel-readonly"
        config trusthost
            edit 1
                set ipv4-trusthost 172.16.0.5 255.255.255.255
            next
        end
    next
end
execute api-user generate-key sentinel
```

## 2. In the panel (Devices page)

1. **Add device**: Fortinet, FortiGate, model FG-100F or FG-200E, name,
   management IP, HTTPS admin port (443, or what `config system global` /
   `admin-sport` says).
2. The device opens **read-only** (green banner). Leave it that way.
3. **Connect**: the panel shows the FortiGate's certificate fingerprint
   before sending the token. Compare it with the certificate in the
   FortiGate GUI (browser padlock on the admin page, or System >
   Certificates) and trust it only if it matches.
4. Paste the token, VDOM `root` (unless you use VDOMs), connect.
5. Check the **Overview**: hostname, model, FortiOS version and build,
   serial, interfaces. Report anything wrong or missing - that is the
   first real-hardware result.
6. **Backups** will most likely fail with a read-only token: FortiOS needs a
   super_admin profile for configuration backups. That is expected; note
   the exact message.
7. Open any wizard and press **Preview**: it shows exactly what would be
   sent. With read-only on, *Apply* stays disabled.

Please send back: FortiOS version + build (from the overview), which
overview fields were wrong or empty, and any error text. Nothing on the
firewall changes in this step.

## 3. Later, for changes (separate decision, maintenance window)

- A second token with a profile that can write (and super_admin for
  backups), trusted host = the panel machine only.
- In the panel: **Allow changes…** (type the device name).
- Start with the smallest, easiest-to-undo change: one address object.
  Check it in the FortiGate GUI, then use *Roll back* in the Changes tab
  and check it is gone.
- Switch the device back to read-only when done.
- Delete or disable the write token when it is not needed.
