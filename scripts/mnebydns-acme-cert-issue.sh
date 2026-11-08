#!/usr/bin/env bash
# Obtain a publicly trusted cert for DNS-only hostname without touching port 443.
# Workflow-only; a new isolated nginx HTTP:80 vhost (not an existing proxy vhost).
set -Eeuo pipefail
test -n "${SSHPASS:-}" || { echo "missing_existing_ssh_credential"; exit 2; }
for tool in sshpass ssh dig curl openssl; do
  command -v "$tool" >/dev/null || { echo "missing_runner_dependency=$tool"; exit 2; }
done
hostname=dns.mnebyvpn.site
foreign_ipv4=89.125.90.101
for dns in 1.1.1.1 8.8.8.8 ns1.jino.ru; do
  answer="$(dig +time=3 +tries=1 +short "$$hostname" A "$$dns" | grep -E '^[0-9.]+$$' || true)"
  [[ "$answer" = "$foreign_ipv4" ]] || { echo "DNS_A_not_confirmed_for_resolver=$dns"; exit 2; }
done
echo "dns_public_resolver_checks=passed"
remote="root@$foreign_ipv4"
ssh_opts=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=12 -o LogLevel=ERROR)
connect() { sshpass -e ssh "${ssh_opts[@]}" "$remote" "$"; }
token="$(openssl rand -hex 16)"
created=false
rollback() {
  local code="$?"
  trap - ERR
  if [[ "$created" == true ]]; then
    connect "bash -se" <<'REMOTE' || true
set -Eeuo pipefail
conf=/etc/nginx/conf.d/93-mnebydns-acme.conf
if [[ -f "$conf" ]] && grep -Fq '# Managed only by MNEBYDNS certificate pilot' "$conf"; then
  rm -f -- "$conf"
  nginx -t >/dev/null 2>&1
  systemctl reload nginx
  echo "dedicated_acme_vhost_rolled_back=yes"
fi
REMOTE
  fi
  echo "certificate_stage_failed_exit=$code"
  exit "$code"
}
trap rollback ERR
created=true
connect "ACME_CHECK_TOKEN=$token bash -se" <<'REMOTE'
set -Eeuo pipefail
conf=/etc/nginx/conf.d/93-mnebydns-acme.conf
webroot=/var/www/mnebydns-acme
test ! -e "$conf" || { echo "dedicated_acme_conf_already_exists"; exit 2; }
test ! -e /etc/letsencrypt/live/dns.mnebyvpn.site || { echo "certificate_already_exists"; exit 2; }
test "$(ss -H -lntp 'sport = :80' | grep -c nginx || true)" -gt 0
nginx -t >/dev/null 2>&1
install -d -m 755 -o root -g root "$webroot/.well-known/acme-challenge"
cat > /etc/nginx/conf.d/.93-mnebydns-acme.conf.new <<'NGINX'
# Managed only by MNEBYDNS certificate pilot; exact-name HTTP-01 challenge.
server {
    listen 80;
    server_name dns.mnebyvpn.site;
    access_log off;
    error_log /var/log/nginx/mnebydns-acme-error.log warn;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/mnebydns-acme;
        default_type text/plain;
        try_files $uri =404;
    }
    location / {
        return 404;
    }
}
NGINX
chmod 644 /etc/nginx/conf.d/.93-mnebydns-acme.conf.new
mv -n /etc/nginx/conf.d/.93-mnebydns-acme.conf.new "$conf"
if ! nginx -t >/dev/null 2>&1; then
  rm -f -- "$conf"
  nginx -t
  echo "new_nginx_conf_invalid_rolled_back=yes"
  exit 1
fi
systemctl reload nginx
test "$(systemctl is-active nginx)" = "active"
printf '%s' "$ACME_CHECK_TOKEN" > "$webroot/.well-known/acme-challenge/mnebydns-check"
chmod 644 "$webroot/.well-known/acme-challenge/mnebydns-check"
echo "dedicated_http01_vhost=installed"
REMOTE
sleep 2
verify="$(curl --fail --silent --show-error --connect-timeout 4 --max-time 10 \
  --resolve "$hostname:80:$foreign_ipv4" \
  "http://$hostname/.well-known/acme-challenge/mnebydns-check")"
[[ "$verify" = "$token" ]] || { echo "external_http01_canary_failed"; false; }
echo "external_http01_canary=pass"
# Certbot reads existing nginx on port 80 via webroot and leaves :443 untouched.
connect 'bash -se' <<'REMOTE'
set -Eeuo pipefail
certbot certonly --non-interactive --agree-tos --register-unsafely-without-email \
  --webroot -w /var/www/mnebydns-acme \
  --cert-name dns.mnebyvpn.site -d dns.mnebyvpn.site
cert=/etc/letsencrypt/live/dns.mnebyvpn.site
test -s "$cert/fullchain.pem"
test -s "$cert/privkey.pem"
openssl x509 -in "$cert/cert.pem" -noout -checkhost dns.mnebyvpn.site | grep -Fq 'does match certificate'
openssl verify -CApath /etc/ssl/certs -untrusted "$cert/chain.pem" "$cert/cert.pem"
systemctl is-active nginx
nginx -t
test -n "$(ss -H -lnt 'sport = :443')"
rm -f -- /var/www/mnebydns-acme/.well-known/acme-challenge/mnebydns-check
echo "trusted_dot_certificate=issued"
echo "public_dot_listener=not_started"
echo "http01_webroot_stays_for_renewal=yes"
REMOTE
created=false
trap - ERR
echo "public_dns_tls_cert_prep=success"
