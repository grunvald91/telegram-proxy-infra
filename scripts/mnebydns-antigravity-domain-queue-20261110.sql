-- Owner-requested Google Antigravity DNS exact-host candidates (2026-11-10).
-- Queue only: never set APPLY_REQUESTED/ACTIVE, touch CoreDNS, or edit Nginx.
-- Existing rows (including ACTIVE routes, original product and revisions) remain unchanged.
BEGIN;
CREATE TEMP TABLE antigravity_requested_hosts (domain text PRIMARY KEY) ON COMMIT DROP;
INSERT INTO antigravity_requested_hosts (domain) VALUES
  ('antigravity.google'),
  ('daily-cloudcode-pa.googleapis.com'),
  ('aicode.googleapis.com'),
  ('accounts.google.com'),
  ('oauth2.googleapis.com'),
  ('generativelanguage.googleapis.com'),
  ('cloudcode-pa.googleapis.com'),
  ('antigravity-pa.googleapis.com'),
  ('antigravity.googleapis.com'),
  ('businessaicode.googleapis.com'),
  ('aiplatform.googleapis.com'),
  ('discoveryengine.googleapis.com');

INSERT INTO dns_admin_domains (domain, product, status, requested_by, updated_by)
  SELECT domain, 'Antigravity', 'PENDING', NULL, NULL
  FROM antigravity_requested_hosts
  WHERE true  -- Disambiguate INSERT..SELECT..ON CONFLICT in PostgreSQL.
  ON CONFLICT (domain) DO NOTHING;

SELECT 'antigravity_queue_entries=' || count(*)
  FROM dns_admin_domains JOIN antigravity_requested_hosts USING (domain);
SELECT 'antigravity_queue_status=' || a.domain || ':' || a.status
  FROM dns_admin_domains a
  JOIN antigravity_requested_hosts h USING (domain)
  ORDER BY a.domain;
COMMIT;
