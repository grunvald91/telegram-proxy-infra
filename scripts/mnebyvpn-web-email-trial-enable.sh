#!/usr/bin/env bash
# Restore owner-approved authenticated 24h VPN web trial on the existing website.
# Refuses if real worker, email sign-in or canonical trial plan are not ready.
# Never edits Stars, Prodamus, VPN nodes, DNS, nginx or other containers.
set -Eeuo pipefail
set +x
umask 077

SHA="${1:?Expected MNEBYVPN web release SHA}"
PROMOTER="${2:?Vetted website canary promoter script}"
ROOT=/opt/mnebyvpn
ENV_FILE="$ROOT/public/web.env"
[[ "$(id -u)" == 0 && "$SHA" =~ ^[a-f0-9]{40}$ ]] || exit 2
test -s "$PROMOTER" && bash -n "$PROMOTER"
test -s "$ENV_FILE"
[[ "$(cat "$ROOT/public/active_sha")" == "$SHA" ]] || {
  echo 'trial_enable=blocked_site_not_current'; exit 2;
}
docker image inspect "mnebyvpn-stage-web:$SHA" >/dev/null
for c in mnebyvpn-public-web mnebyvpn-vpn-worker mnebyvpn-stage-postgres; do
  [[ "$(docker inspect -f '{{.State.Running}}' "$c")" == true ]] || {
    echo "trial_enable=blocked_required_container_not_ready";exit 2;
  }
done
for setting in WEB_EMAIL_LOGIN_ENABLED=yes WEB_NETWORK_PROVISIONING_VERIFIED=yes; do
  grep -Fxq "$setting" "$ENV_FILE" || {
    echo "trial_enable=blocked_email_or_network_not_verified";exit 2;
  }
done
[[ "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 8 http://127.0.0.1:8794/readyz)" == 200 ]] || {
  echo 'trial_enable=blocked_vpn_worker_not_ready'; exit 2;
}
[[ "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 8 -X POST \
  -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:8794/guest-trial)" == 401 ]] || {
  echo 'trial_enable=blocked_vpn_worker_unauthorized_access';exit 2;
}
# Database-owned offer is checked before touching production settings.
[[ "$(docker exec mnebyvpn-stage-postgres psql -At -X -v ON_ERROR_STOP=1 \
  -U mnebyvpn_stage -d mnebyvpn_stage \
  -c "SELECT CASE WHEN EXISTS(SELECT 1 FROM trial_offers WHERE product='vpn' AND enabled AND duration_seconds=86400) THEN 'ready' ELSE 'blocked' END;")" == ready ]] || {
  echo 'trial_enable=blocked_vpn_offer_missing';exit 2;
}
old_checkout="$(grep -E '^WEB_CHECKOUT_ENABLED=' "$ENV_FILE" | tail -1)"
old_checkout="${old_checkout#WEB_CHECKOUT_ENABLED=}"
[[ "$old_checkout" == 0 || "$old_checkout" == 1 ]] || exit 2
if grep -Fxq 'WEB_TRIAL_ENABLED=yes' "$ENV_FILE"; then
  echo 'trial_config=already_enabled'
else
  grep -Fxq 'WEB_TRIAL_ENABLED=no' "$ENV_FILE" || {
    echo 'trial_enable=blocked_ambiguous_existing_flag';exit 2;
  }
fi

# Persist rollback privately; no account or credential is printed.
backup="$(mktemp "$ROOT/public/web-trial-backup.XXXXXXXX")"
cp -p -- "$ENV_FILE" "$backup"
changed=no
finish() {
  status=$?
  trap - EXIT
  if (( status != 0 )) && [[ "$changed" == yes ]]; then
    cp -p -- "$backup" "$ENV_FILE"
    bash "$PROMOTER" "$SHA" >/dev/null 2>&1 ||
      echo 'trial_rollback=manual_intervention_required'
    echo 'trial_rollback=previous_settings_restored'
  fi
  rm -f -- "$backup"
  exit "$status"
}
trap finish EXIT
if ! grep -Fxq 'WEB_TRIAL_ENABLED=yes' "$ENV_FILE"; then
  tmp="$(mktemp "$ROOT/public/web-trial-new.XXXXXXXX")"
  sed 's/^WEB_TRIAL_ENABLED=no$/WEB_TRIAL_ENABLED=yes/' "$ENV_FILE" > "$tmp"
  chown --reference="$ENV_FILE" "$tmp"
  chmod 600 "$tmp"
  mv -f -- "$tmp" "$ENV_FILE"
  changed=yes
fi

# The existing promoter runs staging canary, release rollback and validates
# all existing merchant flags without altering any payment configuration.
bash "$PROMOTER" "$SHA"
curl --noproxy '*' -fsS --max-time 9 http://127.0.0.1:8792/api/plans |
  EXPECT_CHECKOUT="$old_checkout" python3 -c '
import json,os,sys
x=json.load(sys.stdin)
assert x.get("emailLoginEnabled") is True
assert x.get("loginEnabled") is True
assert "vpn" in x.get("trialOffers",[])
assert x.get("checkoutEnabled") is (os.environ["EXPECT_CHECKOUT"]=="1")
'
[[ "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 7 \
  -X POST -H 'Content-Type: application/json' -d '{"product":"vpn"}' \
  http://127.0.0.1:8792/api/guest/trial)" == 403 ]] ||
  { echo 'trial_enable=blocked_anonymous_request_not_denied';exit 2; }
trap - EXIT
rm -f -- "$backup"
echo 'website_authenticated_24h_trial_visible=true'
echo 'anonymous_trial_denied=true'
echo 'paid_checkout_configuration_preserved=true'
echo 'vpn_dns_stars_and_prodamus_settings_unchanged=true'
