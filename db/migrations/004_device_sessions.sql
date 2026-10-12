-- 004: what the device wizard needs on top of 003.

ALTER TABLE devices ADD COLUMN family text;            -- catalog family: fortios, iosxe, panos, spark, mgmt, ...
ALTER TABLE devices ADD COLUMN pin    text;            -- confirmed TLS cert / SSH host key fingerprint
ALTER TABLE devices ADD COLUMN facts  jsonb;           -- last seen hostname / model / version / serial
ALTER TABLE devices ADD COLUMN notes  text;

-- What it takes to undo an applied change: the undo steps and the values
-- captured while applying (e.g. the id the firewall gave a new policy).
ALTER TABLE config_changes ADD COLUMN summary text;
ALTER TABLE config_changes ADD COLUMN undo    jsonb;
ALTER TABLE config_changes ADD COLUMN applied_at timestamptz;
