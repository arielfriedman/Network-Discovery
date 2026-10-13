-- 007: credential metadata and login results (docs/SCAN_BUILDER.md, step 2).
-- Secrets are NEVER stored here: they live only in the GPG vault
-- (discovery/config/vault.gpg) or in memory for one scan.

CREATE TABLE credentials (
    id          int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    vault_key   text        NOT NULL UNIQUE,         -- CRED_<slug> entry in the vault
    name        text        NOT NULL,
    type        varchar(20) NOT NULL,                -- ssh, snmp, aws, azure, gcp, k8s, ...
    hosts       text[]      NOT NULL DEFAULT '{}',   -- IPs / ranges it is for; empty = any
    created_by  int REFERENCES users(id),
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_used   timestamptz,
    last_result varchar(12)
);

-- One row per login attempt during a scan.
CREATE TABLE scan_credential_use (
    id        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_id   int         NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cred_type varchar(20) NOT NULL,
    cred_name text        NOT NULL,
    host      text        NOT NULL,                 -- IP, or the provider name for cloud logins
    result    varchar(12) NOT NULL CHECK (result IN ('ok', 'auth_failed', 'unreachable', 'error')),
    detail    text
);
CREATE INDEX scan_credential_use_scan ON scan_credential_use (scan_id);
