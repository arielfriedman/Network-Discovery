-- 008: device type identification (discovery/lib/device_types.py).
ALTER TABLE hosts ADD COLUMN device_type       text;          -- e.g. 'Raspberry Pi'
ALTER TABLE hosts ADD COLUMN device_model      text;          -- e.g. 'Raspberry Pi 4 Model B Rev 1.4' (read over SSH)
ALTER TABLE hosts ADD COLUMN device_confidence varchar(6)
    CHECK (device_confidence IN ('high', 'medium', 'low'));
ALTER TABLE hosts ADD COLUMN device_evidence   text[];        -- why: one line per piece of evidence
