-- 006: a scan whose panel stopped mid-run (killed, machine rebooted) is marked
-- 'interrupted' when the panel next starts, instead of staying 'running'.
ALTER TABLE scans DROP CONSTRAINT scans_status_check;
ALTER TABLE scans ADD CONSTRAINT scans_status_check
    CHECK (status IN ('running', 'complete', 'cancelled', 'error', 'interrupted'));
