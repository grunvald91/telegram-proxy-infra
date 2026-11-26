#!/usr/bin/env bash
set -euo pipefail

if ! command -v dig >/dev/null; then
  echo "FI_PUBLIC_DOT_DNS_TRANSPORT_UNAVAILABLE=dig_missing"
  exit 9
fi

for ns in ns1.jino.ru ns2.jino.ru ns3.jino.ru ns4.jino.ru; do
  for name in '*.fi.mnebyvpn.site' aaaaaaaaaaaa.fi.mnebyvpn.site bbbbbbbbbbbb.fi.mnebyvpn.site; do
    for type in A AAAA; do
      args=(-4 "@$ns" "$name" "$type" +norecurse +noall +comments +answer +time=3 +tries=1)
      if ! result=$(dig "${args[@]}"); then
        echo "FI_PUBLIC_DOT_DNS_RETRY_TCP=$ns:$name:$type"
        if ! result=$(dig "${args[@]}" +tcp); then
          echo "FI_PUBLIC_DOT_DNS_TRANSPORT_UNAVAILABLE=$ns:$name:$type"
          exit 9
        fi
      fi
      if ! grep -q 'status: NOERROR,' <<< "$result" || ! grep -qE '^;; flags: .*\baa\b' <<< "$result"; then
        echo "FI_PUBLIC_DOT_DNS_NOT_AUTHORITATIVE=$ns:$name:$type"
        exit 2
      fi
      answers=$(awk '/^[^;]/ && NF {print $4, $5}' <<< "$result")
      if [[ "$type" == A && "$answers" != 'A 217.11.167.91' ]] || [[ "$type" == AAAA && -n "$answers" ]]; then
        echo "FI_PUBLIC_DOT_DNS_UNEXPECTED_ANSWER=$ns:$name:$type"
        exit 2
      fi
    done
  done
done
echo 'FI_PUBLIC_DOT_AUTHORITATIVE_WILDCARD_VERIFIED=true'
