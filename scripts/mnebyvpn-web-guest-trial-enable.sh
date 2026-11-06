#!/usr/bin/env bash
# Enable only the confirmed website guest VPN trial and restart the isolated
# public website. No paid checkout, Telegram OIDC, DNS or Xray node changes.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" -eq 0 ]] || exit 2
SHA="${1:?source SHA}"
[[ "$SHA" =~ ^[a-f0-9]{40}$ ]] || exit 2
ROOT=/opt/mnebyvpn
ENV_FILE="$ROOT/public/web.env"
REDEPLOY="${2:?path to verified web promote script}"
test -s "$ENV_FILE"
test -s "$REDEPLOY"
bash -n "$REDEPLOY"
test "$(cat "$ROOT/public/active_sha")" = "$SHA"
test "$(cat "$ROOT/staging/active_sha")" = "$SHA"
test "$(docker inspect -f '{{.Config.Image}}' mnebyvpn-vpn-worker)" = "mnebyvpn-stage-web:$SHA"
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8794/readyz)" = 200
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST \
  -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:8794/guest-trial)" = 401
test "$(docker exec mnebyvpn-stage-postgres psql -At -v ON_ERROR_STOP=1 \
  -U mnebyvpn_stage -d mnebyvpn_stage \
  -c "SELECT to_regclass('public.web_guest_claims');")" = web_guest_claims
test "$(docker exec mnebyvpn-stage-postgres psql -At -v ON_ERROR_STOP=1 \
  -U mnebyvpn_stage -d mnebyvpn_stage \
  -c "SELECT enabled FROM trial_offers WHERE product='vpn' AND duration_seconds=86400;")" = t

backup="$(mktemp "$ROOT/public/guest-trial-env-backup.XXXXXXXX")"
cp -p "$ENV_FILE" "$backup"
rollback() {
  code=$?
  trap - ERR
  if ((code!=0)); then
    cp -p "$backup" "$ENV_FILE"
    bash "$REDEPLOY" "$SHA" || echo 'CRITICAL: web guest env rollback needs manual attention'
    echo 'guest_trial_web_env_rolled_back=true'
  fi
  exit "$code"
}
trap rollback ERR
if grep -Eq '^WEB_GUEST_TRIAL_ENABLED=' "$ENV_FILE"; then
  sed -i 's/^WEB_GUEST_TRIAL_ENABLED=.*/WEB_GUEST_TRIAL_ENABLED=yes/' "$ENV_FILE"
else
  printf '\nWEB_GUEST_TRIAL_ENABLED=yes\n' >> "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"
bash "$REDEPLOY" "$SHA"
test "$(curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:8792/api/plans | \
  python3 -c 'import json,sys; x=json.load(sys.stdin); print(x.get("guestTrialEnabled") is True and not x.get("checkoutEnabled") and not x.get("loginEnabled"))')" = True
test "$(curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:8792/api/guest/status | \
  python3 -c 'import json,sys; print(json.load(sys.stdin).get("status"))')" = NONE
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 6 \
  -X POST -H 'Content-Type: application/json' -d '{"product":"vpn"}' \
  http://127.0.0.1:8792/api/guest/trial)" = 403
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 6 \
  -X POST -H 'Origin: https://mnebyvpn.site' -H 'Content-Type: application/json' \
  -d '{"product":"smart_dns"}' http://127.0.0.1:8792/api/guest/trial)" = 400
trap - ERR
rm -f "$backup"
echo "website_guest_trial_sha=$SHA"
echo 'website_guest_trial_available=true'
echo 'website_guest_unauthorized_and_invalid_requests_denied=true'
echo 'paid_checkout_and_telegram_oidc_still_disabled=true'
