#!/usr/bin/env bash
# Stages the Prodamus merchant's HMAC signing secret on the owned server188.
# The secret is read ONLY from stdin, never command arguments or action logs.
# Does NOT enable checkout, signed webhook processing or run payments.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" -eq 0 ]] || exit 2
ROOT=/opt/mnebyvpn/public
test -s "$ROOT/web.env"
grep -Fxq 'WEB_BASE_URL=https://mnebyvpn.site' "$ROOT/web.env"
grep -Fxq 'WEB_CHECKOUT_ENABLED=0' "$ROOT/web.env"
grep -Fxq 'WEB_PRODAMUS_WEBHOOK_ENABLED=no' "$ROOT/web.env"
KEY="$(cat)"
# Prodamus documentation uses long printable signing secrets. Fail closed
# if this is not a raw token; never strip or print user-entered key bytes.
[[ "${#KEY}" -ge 32 && "${#KEY}" -le 256 && "$KEY" =~ ^[A-Za-z0-9_-]+$ ]] ||
  { echo 'Invalid HMAC key format; expected raw Prodamus secret from Payform Settings'; exit 2; }
DEST="$ROOT/prodamus.env"
if [[ -e "$DEST" ]]; then
  echo 'Prodamus secret already staged; refusing silent overwrite'
  exit 2
fi
TMP="$(mktemp "$ROOT/prodamus.env.XXXXXXXX")"
trap 'rm -f "$TMP"' EXIT
{
  printf '%s\n' 'PRODAMUS_FORM_URL=https://mnebyvpn.payform.ru/'
  printf '%s\n' 'PRODAMUS_NOTIFICATION_URL=https://mnebyvpn.site/webhooks/prodamus'
  printf '%s\n' 'PRODAMUS_SUCCESS_URL=https://mnebyvpn.site/#account'
  printf '%s\n' 'PRODAMUS_RETURN_URL=https://mnebyvpn.site/#plans'
  printf 'PRODAMUS_SIGN_SECRET=%s\n' "$KEY"
} > "$TMP"
chmod 600 "$TMP"
mv "$TMP" "$DEST"
trap - EXIT
echo 'merchant_form=mnebyvpn.payform.ru'
echo 'merchant_secret=staged_root_only_not_logged'
echo 'merchant_webhook_receiving=disabled_pending_live_verification'
echo 'merchant_checkout=disabled_pending_paid_order_provisioning'
