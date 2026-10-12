-- 003: network devices for the configuration wizard.
-- Passwords and API keys are NOT stored here - they stay in the encrypted
-- vault (discovery/vault.sh) or in panel memory for the session only.

CREATE TABLE devices (
    id          int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        text        NOT NULL,
    vendor      varchar(20) NOT NULL CHECK (vendor IN ('fortinet', 'cisco', 'paloalto', 'checkpoint')),
    model       text,
    os_version  text,
    serial      text,
    address     text        NOT NULL,               -- IP or hostname
    port        int,
    vault_key   text,                               -- name of the credential entry in the vault
    last_seen   timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (vendor, address)
);

CREATE TABLE config_backups (
    id          int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id   int NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    taken_at    timestamptz NOT NULL DEFAULT now(),
    reason      text,                               -- manual / before change #n
    config      text NOT NULL,
    sha256      char(64) NOT NULL
);
CREATE INDEX ON config_backups (device_id, taken_at DESC);

CREATE TABLE config_changes (
    id          int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id   int NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    user_id     int NOT NULL REFERENCES users(id),
    wizard      text NOT NULL,                      -- e.g. fortinet.address_object
    params      jsonb,
    commands    text NOT NULL,                      -- exactly what was sent
    backup_id   int REFERENCES config_backups(id),
    status      varchar(12) NOT NULL CHECK (status IN ('previewed', 'applied', 'failed', 'rolled_back')),
    result      text,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON config_changes (device_id, created_at DESC);
