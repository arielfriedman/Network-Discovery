-- 002: scan results (roadmap Part 2). Every scan the panel runs lands here;
-- the JSON/HTML files in panel/reports stay as exports.

CREATE TABLE scans (
    id            int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_ref      varchar(40)  NOT NULL UNIQUE,      -- panel scan id or discovery run id
    kind          varchar(10)  NOT NULL CHECK (kind IN ('host', 'network', 'cloud')),
    target        text,
    mode          varchar(20),                       -- workstation / server
    scan_type     varchar(20),                       -- quick / full
    status        varchar(12)  NOT NULL DEFAULT 'running'
                  CHECK (status IN ('running', 'complete', 'cancelled', 'error')),
    risk_score    int,
    severity_counts jsonb,
    summary       jsonb,                             -- network stats etc.
    started_at    timestamptz  NOT NULL DEFAULT now(),
    finished_at   timestamptz,
    elapsed_s     numeric(10,1),
    started_by    int REFERENCES users(id),
    report_path   text                               -- where the HTML/JSON export lives
);
CREATE INDEX ON scans (kind, started_at DESC);

CREATE TABLE scan_modules (
    scan_id       int NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name          varchar(60) NOT NULL,
    display_name  text,
    status        varchar(12) NOT NULL,              -- done / skipped / error / cancelled
    finding_count int NOT NULL DEFAULT 0,
    elapsed_s     numeric(10,1),
    detail        text,
    PRIMARY KEY (scan_id, name)
);

CREATE TABLE findings (
    id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_id            int  NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    severity           varchar(10) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    category           text,
    title              text NOT NULL,
    description        text,
    affected_component text,
    remediation        text,
    cvss_score         numeric(3,1),
    cve_ids            text[] NOT NULL DEFAULT '{}',
    fingerprint        text NOT NULL,                -- category|title, to compare scans
    raw                jsonb
);
CREATE INDEX ON findings (scan_id);
CREATE INDEX ON findings (fingerprint);

CREATE TABLE hosts (
    id        int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_id   int  NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip        inet NOT NULL,
    mac       macaddr,
    hostname  text,
    vendor    text,
    os_guess  text,
    extra     jsonb,                                 -- mdns / netbios / ssdp
    UNIQUE (scan_id, ip)
);
CREATE INDEX ON hosts (ip);
CREATE INDEX ON hosts (mac);

CREATE TABLE services (
    host_id   int  NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port      int  NOT NULL CHECK (port BETWEEN 0 AND 65535),
    protocol  varchar(4) NOT NULL DEFAULT 'tcp',
    service   text,
    version   text,
    PRIMARY KEY (host_id, port, protocol)
);
