-- 011: Actions page - machines reached over SSH (panel/action_targets.py).
-- No secrets: passwords and keys stay in the panel's memory for the open
-- connection only. fingerprint is the SSH host key the user confirmed.

CREATE TABLE action_targets (
    id          int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host        text        NOT NULL,
    port        int         NOT NULL DEFAULT 22 CHECK (port BETWEEN 1 AND 65535),
    username    text        NOT NULL,
    fingerprint text,
    distro      text,
    last_used   timestamptz,
    UNIQUE (host, port, username)
);
