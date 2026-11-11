-- One exact hostname only. Owner requested a Microsoft canary.
-- Never downgrade ACTIVE/COVERED/other states, never reset others.
-- Defer entirely when any existing owner DNS transition/canary is outstanding.
WITH gate AS (
  SELECT NOT EXISTS (
    SELECT 1 FROM dns_admin_domains
    WHERE status IN ('APPLY_REQUESTED','PROBING','CANARY','CONFIRM_REQUESTED',
      'CONFIRMING','ROLLBACK_REQUESTED','REMOVAL_PENDING','REMOVING')
  ) AS available
)
UPDATE dns_admin_domains SET
  status='APPLY_REQUESTED',revision=revision+1,
  updated_at=now(),last_error_code=NULL
WHERE domain='copilot.microsoft.com'
  AND product='Microsoft'
  AND status='PENDING'
  AND (SELECT available FROM gate)
RETURNING domain || '|' || status || '|' || revision;
