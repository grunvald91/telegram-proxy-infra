-- Exact six Microsoft-related names explicitly stated in the user's 523-host study.
-- Queue and product ownership metadata only. NO deployment, no per-host canary,
-- no rewrite and no route status transitions. Existing ACTIVE, COVERED, CANARY,
-- APPLY_REQUESTED, FAILED etc are never replaced or downgraded.
BEGIN;
WITH research(domain) AS (
  VALUES ('bing.com'),
         ('copilot.microsoft.com'),
         ('microsoft.com'),
         ('software-static.download.prss.microsoft.com'),
         ('xbox.com'),
         ('xboxdesignlab.xbox.com')
)
INSERT INTO dns_admin_domains(domain,product,status,requested_by,updated_by)
SELECT domain,'Microsoft','PENDING',NULL,NULL FROM research
ON CONFLICT (domain) DO UPDATE SET
  product='Microsoft',
  updated_at=now()
WHERE dns_admin_domains.status='PENDING'
  AND dns_admin_domains.product IN ('Microsoft','Research 2026-11','custom');
DO $$
DECLARE total int;
BEGIN
  SELECT count(*) INTO total FROM dns_admin_domains
  WHERE domain IN ('bing.com','copilot.microsoft.com','microsoft.com',
    'software-static.download.prss.microsoft.com',
    'xbox.com','xboxdesignlab.xbox.com');
  IF total <> 6 THEN
    RAISE EXCEPTION 'Microsoft inventory not exactly six rows: %',total;
  END IF;
END $$;
COMMIT;
-- Shared apex bing.com/microsoft.com remain review-only. Copilot 403 in RU
-- vs 301 on DE (study sweep) is evidence for a per-host canary, NOT a permit
-- to auto-route.
