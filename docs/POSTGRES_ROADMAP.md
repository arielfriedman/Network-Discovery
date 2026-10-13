# PostgreSQL Roadmap — storing dashboard results, users and activity

Plan for moving the SentinelScan control panel (and later network-discovery and the
device wizard) from JSON files to a PostgreSQL database.

## Source

**"The 6 Tables Every Login System Needs"**, Database Star (Ben Brumm), 6 min, 2026-09-28
<https://www.youtube.com/watch?v=YzBRLQbOl_I>

The video has three sections: **Users** (0:00), **Roles** (2:11) and **Activity** (4:28).
Part 1 follows the schema diagram shown in the video (screenshot: `~/Documents/Screenshot_1.png`).

---

## Part 1 — The login system (6 tables, as in the video)

| # | Table | Columns (from the video) | Purpose |
|---|---|---|---|
| 1 | `users` | `id`, `name` varchar(100), `email` varchar(255) **unique**, `password_hash` varchar(255), `created_at` timestamp — all NOT NULL | One row per person who can log in |
| 2 | `roles` | `id`, `name` varchar(50) **unique** | Named sets of rights: admin, operator, viewer |
| 3 | `permissions` | `id`, `name` varchar(50) **unique** | Individual actions: `scan.run`, `device.configure`, … |
| 4 | `user_roles` | `user_id` → users, `role_id` → roles | Which users have which roles (many-to-many join table) |
| 5 | `role_permissions` | `role_id` → roles, `permission_id` → permissions | Which roles grant which permissions (many-to-many join table) |
| 6 | `user_activity` | `id`, `user_id` → users, `action` varchar(50), `created_at` timestamp — all NOT NULL | What each user did and when |

Relationships: a user has many roles and a role has many users (through `user_roles`); a role
has many permissions and a permission belongs to many roles (through `role_permissions`); a
user has many activity rows.

Why roles *and* permissions: code checks permissions (`can this user run a scan?`),
while people manage roles (`make Anna an operator`). Changing what "operator" may do
then means changing rows, not code.

### Schema (PostgreSQL, matching the video)

```sql
CREATE TABLE users (
    id            int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name          varchar(100) NOT NULL,
    email         varchar(255) NOT NULL UNIQUE,
    password_hash varchar(255) NOT NULL,     -- argon2id/bcrypt hash, never the password
    created_at    timestamptz  NOT NULL DEFAULT now()
);

CREATE TABLE roles (
    id   int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name varchar(50) NOT NULL UNIQUE          -- admin, operator, viewer
);

CREATE TABLE permissions (
    id   int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name varchar(50) NOT NULL UNIQUE          -- e.g. scan.run
);

CREATE TABLE user_roles (
    user_id int NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id int NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE role_permissions (
    role_id       int NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id int NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_activity (
    id         int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    int         NOT NULL REFERENCES users(id),
    action     varchar(50) NOT NULL,          -- login, scan.start, device.config.apply, …
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON user_activity (user_id, created_at DESC);
```

The video's diagram shows `timestamp`; `timestamptz` is the recommended PostgreSQL choice
(stores an absolute moment, safe across time zones).

### Optional additions for our dashboard (not in the video)

```sql
ALTER TABLE users ADD COLUMN is_active     boolean NOT NULL DEFAULT true;  -- deactivate instead of delete
ALTER TABLE users ADD COLUMN last_login_at timestamptz;
ALTER TABLE user_activity ADD COLUMN target    text;   -- scan id, device IP, …
ALTER TABLE user_activity ADD COLUMN source_ip inet;
ALTER TABLE user_activity ADD COLUMN details   jsonb;
```

Because `user_activity.user_id` is NOT NULL, failed logins for usernames that don't exist
can't go there. If we want to track brute-force attempts, add a small separate
`login_attempts` table (email tried, source IP, success, time).

### Rules to follow
- **Passwords:** store only a slow, salted hash (argon2id or bcrypt), made in the app.
- **Don't hard-delete users** who have activity history; deactivate them instead (optional `is_active` above).
- **Activity is append-only.** The app's database user gets `INSERT` and `SELECT` on `user_activity`, not `UPDATE` or `DELETE`.
- **Unique constraints** on `users.email`, `roles.name` and `permissions.name`, as in the video.

### Suggested starting data

| Role | Permissions |
|---|---|
| admin | everything, including `user.manage` |
| operator | `results.view`, `scan.run`, `scan.stop`, `device.view`, `device.configure`, `config.backup` |
| viewer | `results.view`, `device.view` |

Actions to record: `login`, `logout`, `scan.start`, `scan.stop`, `scan.complete`,
`results.export`, `device.connect`, `device.config.preview`, `device.config.apply`,
`device.config.rollback`, `user.create`, `user.role.change`.

---

## Part 2 — Tables for scan results (our addition)

Based on the shared findings schema SentinelScan already produces (`ScanSession.to_dict()`).

| Table | Holds |
|---|---|
| `scans` | One row per scan: kind (host/network/cloud), target, mode, depth, status, risk score, started/finished, `started_by → users` |
| `scan_modules` | Each module's result per scan: name, status (done/skipped/error/cancelled), finding count, seconds |
| `findings` | scan_id, severity, category, title, affected component, remediation, CVSS, `cve_ids text[]`, raw `jsonb` |
| `hosts` | Network scans: scan_id, IP (`inet`), MAC (`macaddr`), hostname, vendor, OS guess |
| `services` | host_id, port, protocol, service, version |

Later, for the device wizard: `devices` (vendor, model, IP, version), `config_backups`
(device, taken_at, config text) and `config_changes` (who, when, commands, result).
**Device passwords and API keys stay in the encrypted vault, not in the database.**

Useful queries this enables: risk score over time per host, "which findings are new
since the last scan", "which hosts appeared this week", "who changed this device".

---

## Part 3 — Steps

1. **Run PostgreSQL** in an LXC container on Proxmox (pve), or in Docker. Create a
   database `sentinel` and a separate app user with only the rights it needs.
2. **Lock it down:** listen on the LAN only, `scram-sha-256` in `pg_hba.conf`,
   firewall the port to the panel's host, TLS if it crosses machines.
3. **Keep the schema in numbered migration files** (`sql/001_init.sql`, `002_…`) in the repo.
4. **Write results to Postgres** from `serve.py` when a scan finishes (keep the JSON export too).
   This adds the first dependency, `psycopg`. Until now the panel uses only the standard library.
5. **Import existing results** from `~/sentinelscan/reports/*.json` and network-discovery's `findings.json`.
6. **Add login and roles** to the panel, using Part 1, and record every action in `user_activity`.
7. **Add a history page:** past scans, trends, new or resolved findings.
8. **Back up:** nightly `pg_dump` with retention, and test a restore. **Done 2026-10-13:**
   `panel/db_backup.py`, scheduled with the user's crontab rather than a systemd timer
   (no root or lingering needed; `install.sh` turns it on, History page switches it),
   restore tested into a fresh database.
