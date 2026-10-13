-- 005: scan checklist and target lists (docs/SCAN_BUILDER.md, step 1).

ALTER TABLE scans ADD COLUMN options     jsonb;   -- checklist: {"names": true, "ports": "top", ...}
ALTER TABLE scans ADD COLUMN target_spec jsonb;   -- {"mode": "targets", "counts": {...}, "files": [...]}

-- One row per line the user listed (typed or from an uploaded file) and what
-- became of it.
CREATE TABLE scan_targets (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_id     int         NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind        varchar(4)  NOT NULL CHECK (kind IN ('ip', 'cidr', 'mac', 'host')),
    value       text        NOT NULL,             -- as normalized: 172.16.0.30, bc:24:11:aa:bb:cc, pve.lan
    source      text        NOT NULL DEFAULT 'typed',   -- 'typed' or the uploaded file name
    resolved_ip inet[]      NOT NULL DEFAULT '{}',
    status      varchar(12) NOT NULL CHECK (status IN ('up', 'assumed_up', 'no_response', 'unresolved', 'not_seen')),
    detail      text
);
CREATE INDEX scan_targets_scan ON scan_targets (scan_id);
