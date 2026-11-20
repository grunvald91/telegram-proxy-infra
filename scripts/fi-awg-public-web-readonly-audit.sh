#!/usr/bin/env bash
# Read-only inspection of the actual RU188 website/deployment preconditions.
# Never print environment VALUES, session tokens or customer records.
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || exit 2
ip -o -4 addr show | grep -Eq '188\.120\.254\.223/' || exit 2
test ! -e /root/mnebyvpn-controller/approvals/awg-delivery.enable
! systemctl is-active --quiet mnebyvpn-awg-delivery.service

flag="$(docker exec mnebyvpn-stage-postgres psql -AtX -v ON_ERROR_STOP=1 \
  -U mnebyvpn_stage -d mnebyvpn_stage -c \
  "SELECT enabled::text FROM public.vpn_release_flags WHERE feature='vpn_awg_clients'")"
[[ "$flag" == false ]] || exit 2
echo 'FI_AWG_AUDIT_RELEASE=disabled;WORKER_ACTIVE=false'

# Identify whether a stale immutable-release staging process is holding the
# independent ROOT-only flock. Do not send signals or change the lock file.
old_release='/opt/mnebyvpn-controller/awg-worker-releases/6743387075102698ab23ec06de364d0d8efd1dca'
new_release='/opt/mnebyvpn-controller/awg-worker-releases/446c331249085adb6536e3d9913fb4b68abf6cd7'
effective="$(systemctl show -P WorkingDirectory mnebyvpn-awg-delivery.service)"
if [[ "$effective" == "$old_release" ]]; then
  echo 'FI_AWG_AUDIT_EFFECTIVE_WORKER=OLD_INACTIVE'
elif [[ "$effective" == "$new_release" ]]; then
  echo 'FI_AWG_AUDIT_EFFECTIVE_WORKER=NEW_INACTIVE'
else
  echo 'FI_AWG_AUDIT_EFFECTIVE_WORKER=UNRECOGNIZED'
fi
manifest="$new_release/awg-client-worker-manifest.json"
if [[ -f "$manifest" && ! -L "$manifest" ]]; then
  echo 'FI_AWG_AUDIT_NEW_RELEASE_MANIFEST=present'
else
  echo 'FI_AWG_AUDIT_NEW_RELEASE_MANIFEST=missing'
fi

# Match only the dedicated FI staging process's full command line. This
# will not match unrelated Python, SSH, watchdog or AWG production processes.
stage_pid_count="$(pgrep -fc '^python3 /run/fi-awg-client-worker\.[A-Za-z0-9]{8}/fi_awg_client_worker_stage\.py --stage /run/fi-awg-client-worker\.[A-Za-z0-9]{8}
result="$(docker exec mnebyvpn-stage-postgres psql -AtX -v ON_ERROR_STOP=1 \
  -U mnebyvpn_stage -d mnebyvpn_stage -c \
  "SELECT (to_regclass('public.vpn_awg_device_requests') IS NOT NULL)::text,
     (to_regprocedure('public.website_request_fi_awg_device(text,uuid,text)') IS NOT NULL)::text,
     (to_regprocedure('public.website_fi_awg_device_status(text,uuid,text)') IS NOT NULL)::text")"
[[ "$result" == 'true|true|true' ]] || exit 2
echo 'FI_AWG_AUDIT_DATABASE=queue_and_rpc_present'

for file in /opt/mnebyvpn/public/active_sha /opt/mnebyvpn/staging/active_sha; do
  name="$(basename "$(dirname "$file")")"
  if [[ -f "$file" && ! -L "$file" ]];then
    sha="$(cat "$file")"
    [[ "$sha" =~ ^[a-f0-9]{40}$ ]] || exit 2
    echo "FI_AWG_AUDIT_$(echo "$name" | tr '[:lower:]' '[:upper:]')_SHA=$sha"
  else
    echo "FI_AWG_AUDIT_$(echo "$name" | tr '[:lower:]' '[:upper:]')_SHA=not_recorded"
  fi
done

if docker container inspect mnebyvpn-public-web >/dev/null 2>&1;then
  state="$(docker inspect -f '{{.State.Status}}' mnebyvpn-public-web)"
  [[ "$state" == running ]] || exit 2
  if docker exec mnebyvpn-public-web sh -c \
    'grep -q "fiAwgRegistrationAvailable" /srv/mnebyvpn/apps/web/src/server.ts' >/dev/null 2>&1;then
    echo 'FI_AWG_AUDIT_PUBLIC_WEB_SOURCE=new_registration_present'
  else
    echo 'FI_AWG_AUDIT_PUBLIC_WEB_SOURCE=old_or_uninspectable'
  fi
else
  echo 'FI_AWG_AUDIT_PUBLIC_WEB_SOURCE=container_missing'
fi

if [[ -f /opt/mnebyvpn/public/web.env && ! -L /opt/mnebyvpn/public/web.env ]];then
  for name in WEB_FI_AWG_REGISTRATION_ENABLED WEB_FI_AWG_MATERIAL_ENABLED WEB_FI_AWG_SERVER_PUBLIC_KEY WEB_FI_AWG_HEADER_PROTECTION_KEY;do
    if grep -q "^$name=" /opt/mnebyvpn/public/web.env;then
      echo "FI_AWG_AUDIT_$name=configured"
    else
      echo "FI_AWG_AUDIT_$name=not_configured"
    fi
  done
fi
for p in /healthz /api/auth/options /awg/setup;do
  code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' \
    --connect-timeout 3 --max-time 5 "http://127.0.0.1:8792$p" || true)"
  case "$p" in
    /healthz) k=HEALTH;;
    /api/auth/options) k=AUTH;;
    /awg/setup) k=AWG_PAGE;;
  esac
  [[ "$code" =~ ^[0-9]{3}$ ]] || exit 2
  echo "FI_AWG_AUDIT_PUBLIC_$k=$code"
done
echo 'FI_AWG_AUDIT=READONLY_COMPLETE;CLIENT_RELEASE=false'
 || true)"
[[ "$stage_pid_count" =~ ^[0-9]+$ ]] || exit 2
echo "FI_AWG_AUDIT_STAGE_PROCESS_COUNT=$stage_pid_count"
lock='/root/mnebyvpn-controller/awg-worker-source-stage.lock'
if [[ ! -e "$lock" ]];then
  echo 'FI_AWG_AUDIT_SOURCE_FLOCK=absent'
elif [[ -f "$lock" && ! -L "$lock" &&
        "$(stat -c '%u:%a:%h' -- "$lock")" == '0:600:1' ]]; then
  if flock -n -E 77 "$lock" -c /usr/bin/true; then
    echo 'FI_AWG_AUDIT_SOURCE_FLOCK=free'
  else
    code=$?
    if [[ "$code" == 77 ]]; then
      echo 'FI_AWG_AUDIT_SOURCE_FLOCK=held'
    else
      echo 'FI_AWG_AUDIT_SOURCE_FLOCK=unverifiable'
    fi
  fi
else
  echo 'FI_AWG_AUDIT_SOURCE_FLOCK=untrusted'
fi

result="$(docker exec mnebyvpn-stage-postgres psql -AtX -v ON_ERROR_STOP=1 \
  -U mnebyvpn_stage -d mnebyvpn_stage -c \
  "SELECT (to_regclass('public.vpn_awg_device_requests') IS NOT NULL)::text,
     (to_regprocedure('public.website_request_fi_awg_device(text,uuid,text)') IS NOT NULL)::text,
     (to_regprocedure('public.website_fi_awg_device_status(text,uuid,text)') IS NOT NULL)::text")"
[[ "$result" == 'true|true|true' ]] || exit 2
echo 'FI_AWG_AUDIT_DATABASE=queue_and_rpc_present'

for file in /opt/mnebyvpn/public/active_sha /opt/mnebyvpn/staging/active_sha; do
  name="$(basename "$(dirname "$file")")"
  if [[ -f "$file" && ! -L "$file" ]];then
    sha="$(cat "$file")"
    [[ "$sha" =~ ^[a-f0-9]{40}$ ]] || exit 2
    echo "FI_AWG_AUDIT_$(echo "$name" | tr '[:lower:]' '[:upper:]')_SHA=$sha"
  else
    echo "FI_AWG_AUDIT_$(echo "$name" | tr '[:lower:]' '[:upper:]')_SHA=not_recorded"
  fi
done

if docker container inspect mnebyvpn-public-web >/dev/null 2>&1;then
  state="$(docker inspect -f '{{.State.Status}}' mnebyvpn-public-web)"
  [[ "$state" == running ]] || exit 2
  if docker exec mnebyvpn-public-web sh -c \
    'grep -q "fiAwgRegistrationAvailable" /srv/mnebyvpn/apps/web/src/server.ts' >/dev/null 2>&1;then
    echo 'FI_AWG_AUDIT_PUBLIC_WEB_SOURCE=new_registration_present'
  else
    echo 'FI_AWG_AUDIT_PUBLIC_WEB_SOURCE=old_or_uninspectable'
  fi
else
  echo 'FI_AWG_AUDIT_PUBLIC_WEB_SOURCE=container_missing'
fi

if [[ -f /opt/mnebyvpn/public/web.env && ! -L /opt/mnebyvpn/public/web.env ]];then
  for name in WEB_FI_AWG_REGISTRATION_ENABLED WEB_FI_AWG_MATERIAL_ENABLED WEB_FI_AWG_SERVER_PUBLIC_KEY WEB_FI_AWG_HEADER_PROTECTION_KEY;do
    if grep -q "^$name=" /opt/mnebyvpn/public/web.env;then
      echo "FI_AWG_AUDIT_$name=configured"
    else
      echo "FI_AWG_AUDIT_$name=not_configured"
    fi
  done
fi
for p in /healthz /api/auth/options /awg/setup;do
  code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' \
    --connect-timeout 3 --max-time 5 "http://127.0.0.1:8792$p" || true)"
  case "$p" in
    /healthz) k=HEALTH;;
    /api/auth/options) k=AUTH;;
    /awg/setup) k=AWG_PAGE;;
  esac
  [[ "$code" =~ ^[0-9]{3}$ ]] || exit 2
  echo "FI_AWG_AUDIT_PUBLIC_$k=$code"
done
echo 'FI_AWG_AUDIT=READONLY_COMPLETE;CLIENT_RELEASE=false'
