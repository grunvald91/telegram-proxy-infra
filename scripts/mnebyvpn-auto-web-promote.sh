#!/usr/bin/env bash
# Promote only the tested MNEBYVPN website container to its existing public port.
# No nginx, firewall, DNS, proxy, Telegram, payment or other-container changes.
set -Eeuo pipefail
umask 077

SHA="$1"
ROOT=/opt/mnebyvpn
PUBLIC="$ROOT/public"
ENV_FILE="$PUBLIC/web.env"
IMAGE="mnebyvpn-stage-web:$SHA"
NAME=mnebyvpn-public-web
CANARY=mnebyvpn-public-web-canary
LOCK=/run/lock/mnebyvpn-public-prepare.lock

[ "$(id -u)" -eq 0 ] || { echo 'Deploy must run with existing infrastructure privileges'; exit 2; }
[[ "$SHA" =~ ^[a-f0-9]{40}$ ]] || { echo 'Invalid commit SHA'; exit 2; }
exec 9>"$LOCK"
flock -w 90 9 || { echo 'Another website promotion is in progress'; exit 2; }
command -v docker >/dev/null && command -v curl >/dev/null && command -v python3 >/dev/null
docker image inspect "$IMAGE" >/dev/null
[ -f "$ENV_FILE" ] || { echo 'Missing existing public web environment; refusing to bootstrap'; exit 2; }
[ "$(docker inspect -f '{{.State.Running}}' mnebyvpn-stage-postgres)" = true ] || {
  echo 'Existing database is not running'; exit 2;
}

# Never enable the unfinished commercial functionality by deploying UI code.
for setting in   MNEBYVPN_ENV=production   WEB_BASE_URL=https://mnebyvpn.site   WEB_TELEGRAM_OIDC_ENABLED=no   WEB_PRODAMUS_WEBHOOK_ENABLED=no   WEB_CHECKOUT_ENABLED=0   WEB_TRIAL_ENABLED=no   WEB_NETWORK_PROVISIONING_VERIFIED=no   WEB_DNS_METERING_VERIFIED=no; do
  grep -Fxq "$setting" "$ENV_FILE" || {
    echo 'Existing production web environment violates the read-only deployment policy'; exit 2;
  }
done

# This deploy owns only the two named website containers and localhost ports.
port_busy() { ss -H -lnt | awk '{print $4}' | grep -Eq ":$1$"; }
if docker ps -a --format '{{.Names}}' | grep -qx "$CANARY"; then
  echo 'Canary name is occupied; refusing to replace unknown container'; exit 2
fi
# Select a presently unused high loopback port; do not reuse any occupied listener.
CANARY_PORT=''
for candidate in 18793 18794 18795 28793 28794; do
  if ! port_busy "$candidate"; then CANARY_PORT="$candidate"; break; fi
done
[ -n "$CANARY_PORT" ] || { echo 'No spare canary port available; refusing'; exit 2; }
has_public=no
old_image=''
if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  has_public=yes
  old_image="$(docker inspect -f '{{.Image}}' "$NAME")"
elif port_busy 8792; then
  echo 'Public web port belongs to an unknown service; refusing'; exit 2
fi

# The website reads Telegram subscriptions using a dedicated SELECT-only DB role.
# Never load the Telegram bot database writer credentials into this container.
test -s "$ROOT/bot/worker.env"
test -s "$ROOT/public/subscription-db.env" ||
  { echo 'Subscription DB reader credentials missing'; exit 2; }
grep -Eq '^VPN_SUBSCRIPTION_DATABASE_URL=postgresql://mnebyvpn_sub_ro:[a-f0-9]{64}@127[.]0[.]0[.]1:55433/mnebyvpn_stage$' \
  "$ROOT/public/subscription-db.env" ||
  { echo 'Subscription DB reader URL malformed'; exit 2; }
run_web() {
  local name="$1" image="$2" port="$3" ephemeral="$4"
  local policy_flags=()
  if [ "$ephemeral" = yes ]; then
    policy_flags=(--rm)
  else
    policy_flags=(--restart unless-stopped)
  fi
  grep -Eq '^VPN_WORKER_PROFILE_TOKEN=[a-f0-9]{64}$' "$ROOT/bot/worker.env" ||
    { echo 'Invalid private profile bridge token'; return 2; }
  local auth_env=()
  if grep -Fxq 'WEB_EMAIL_LOGIN_ENABLED=yes' "$ENV_FILE"; then
    test -s "$ROOT/public/auth-db.env" || {
      echo 'Scoped canonical auth DB environment missing'; return 2;
    }
    grep -Eq '^WEB_AUTH_DATABASE_URL=postgresql://mnebyvpn_site_auth:[a-f0-9]{64}@127[.]0[.]0[.]1:55433/mnebyvpn_stage$' "$ROOT/public/auth-db.env" || {
      echo 'Auth DB credential cannot be proven canonical and scoped'; return 2;
    }
    auth_env=(--env-file "$ROOT/public/auth-db.env")
  fi
  local merchant_env=()
  local billing_env=()
  if grep -Fxq 'WEB_PRODAMUS_WEBHOOK_ENABLED=yes' "$ENV_FILE" ||
     grep -Fxq 'WEB_CHECKOUT_ENABLED=1' "$ENV_FILE"; then
    test -s "$ROOT/public/billing-db.env" || {
      echo 'Canonical scoped merchant DB credential missing'; return 2;
    }
    grep -Eq '^WEB_BILLING_DATABASE_URL=postgresql://mnebyvpn_site_pay:[a-f0-9]{64}@127[.]0[.]0[.]1:55433/mnebyvpn_stage$' "$ROOT/public/billing-db.env" || {
      echo 'Billing DB credential cannot be proven canonical and scoped'; return 2;
    }
    billing_env=(--env-file "$ROOT/public/billing-db.env")
    test -s "$ROOT/public/prodamus.env" || {
      echo 'Approved payment webhook requires private Prodamus config'; return 2;
    }
    merchant_env=(--env-file "$ROOT/public/prodamus.env")
  fi
  docker run -d "${policy_flags[@]}" --name "$name" \
    --network host --user 1000:1000 --read-only \
    --tmpfs /tmp:rw,nosuid,nodev,size=32m \
    --cap-drop ALL --security-opt no-new-privileges --pids-limit 96 \
    --memory 300m --cpus 0.4 --env-file "$ENV_FILE" \
    --env-file "$ROOT/bot/worker.env" \
    --env-file "$ROOT/public/subscription-db.env" \
    "${auth_env[@]}" "${billing_env[@]}" "${merchant_env[@]}" -e "WEB_PORT=$port" "$image" >/dev/null
}
public_listener() { ss -H -lnt | awk '{print $4}' | grep -Fqx '127.0.0.1:8792'; }
healthy() {
  local port="$1"
  local require_logo="${2:-yes}"
  local code=''
  for attempt in $(seq 1 35); do
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$port/healthz" 2>/dev/null || true)"
    if [ "$code" = 200 ]; then break; fi
    sleep 1
  done
  [ "$code" = 200 ] || return 1
  local css
  css="$(curl -fsS --max-time 5 "http://127.0.0.1:$port/neo.css")" || return 1
  [ -n "$css" ] || return 1
  # A successful homepage is insufficient if the Telegram logo is missing.
  # Previous releases might predate this asset; rollback tolerates that.
  if [ "$require_logo" = yes ]; then
    local avatar_response
    avatar_response="$(curl -sS --max-time 5 -o /dev/null -w '%{http_code} %{content_type}'       "http://127.0.0.1:$port/brand-avatar.webp" || true)"
    [ "$avatar_response" = '200 image/webp' ] || {
      echo 'Brand asset missing or wrong content-type'; return 1;
    }
  fi
  local expect_email=no
  if grep -Fxq 'WEB_EMAIL_LOGIN_ENABLED=yes' "$ENV_FILE"; then
    grep -Eq '^MNEBYVPN_MAIL_GATEWAY_SECRET=[a-f0-9]{96}$' "$ENV_FILE" || {
      echo 'Email feature enabled without a valid private mail secret'; return 1;
    }
    expect_email=yes
  fi
  curl -fsS --max-time 5 "http://127.0.0.1:$port/api/plans" |
    EXPECT_EMAIL="$expect_email" python3 -c 'import sys,json,os; x=json.load(sys.stdin); y=(os.environ.get("EXPECT_EMAIL")=="yes"); assert x["checkoutEnabled"] is False and x["loginEnabled"] is y and x["emailLoginEnabled"] is y' || return 1
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$port/readyz")" = 503 ] || return 1
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$port/auth/login")" = 503 ] || return 1
}

cleanup_canary() {
  docker stop -t 3 "$CANARY" >/dev/null 2>&1 || true
}
trap cleanup_canary EXIT
run_web "$CANARY" "$IMAGE" "$CANARY_PORT" yes
healthy "$CANARY_PORT" || { echo 'New website failed canary health / security checks'; exit 2; }
cleanup_canary
trap - EXIT

# Downtime is limited to replacing this single named brochure container.
if [ "$has_public" = yes ]; then
  docker stop -t 12 "$NAME" >/dev/null
  docker rm "$NAME" >/dev/null
fi
if ! run_web "$NAME" "$IMAGE" 8792 no || ! healthy 8792 || ! public_listener; then
  echo 'Public website health failed; restoring previous image'
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if [ -n "$old_image" ]; then
    run_web "$NAME" "$old_image" 8792 no
    healthy 8792 no || { echo 'CRITICAL: previous public website image failed recovery'; exit 3; }
    echo 'public_rollback=restored_previous_image'
  fi
  exit 2
fi
test "$(docker inspect -f '{{.State.Running}}' "$NAME")" = true
tmp="$(mktemp "$PUBLIC/active_sha.tmp.XXXXXX")"
printf '%s\n' "$SHA" > "$tmp"
chmod 600 "$tmp"
mv -f "$tmp" "$PUBLIC/active_sha"

echo "public_web_sha=$SHA"
echo 'public_web_health=200'
echo 'public_web_readyz=503_expected'
echo 'public_checkout_enabled=false'
echo 'public_telegram_oidc_enabled=false'
if grep -Fxq 'WEB_EMAIL_LOGIN_ENABLED=yes' "$ENV_FILE"; then echo 'public_email_login_enabled=true'; else echo 'public_email_login_enabled=false'; fi
echo 'public_web_port=127.0.0.1:8792'
echo 'nginx_and_other_services_unchanged=yes'
