-- 009: read-only mode for devices. On by default (also for devices already
-- added): the panel can connect, show the overview and take backups, but
-- will not apply or roll back changes until the user switches it off for
-- that device, typing its name to confirm.
ALTER TABLE devices ADD COLUMN read_only boolean NOT NULL DEFAULT true;
