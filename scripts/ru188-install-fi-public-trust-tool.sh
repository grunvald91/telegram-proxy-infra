#!/usr/bin/env bash
# RU188: install ONLY a reviewed public-key verifier tool, no approval/enroll.
set -Eeuo pipefail
umask 077
expected_sha="$1"
[[ "$expected_sha" =~ ^[a-f0-9]{64}$ ]] || exit 2
[ "$(id -u)" -eq 0 ] || exit 2
[ -d /opt/mnebyvpn-controller ] || exit 2
[ -f /root/mnebyvpn-controller/bootstrap-manifest.json ] || exit 2
[ -f /etc/systemd/system/mnebyvpn-fi-enrollment.service ] || exit 2
source_file="/run/mnebyvpn-fi-trust-tool-reviewed.py"
directory="/opt/mnebyvpn-controller/tools"
target="$directory/stage-fi-public-trust.py"
trap 'rm -f "$source_file"' EXIT
[ -f "$source_file" ] && [ ! -L "$source_file" ] || exit 2
[ "$(stat -c %u "$source_file")" = 0 ] || exit 2
test "$(sha256sum "$source_file" | awk '{print $1}')" = "$expected_sha"
install -d -m 0700 "$directory"
[ "$(stat -c %u:%a "$directory")" = 0:700 ] || exit 2
if [ -e "$target" ] || [ -L "$target" ]; then
  # Actions retry is safe only if the already installed root-only inode
  # is precisely the reviewed, pinned public verifier script.
  [ -f "$target" ] && [ ! -L "$target" ] || exit 3
  [ "$(stat -c %u:%a "$target")" = "0:600" ] || exit 3
  [ "$(sha256sum "$target" | cut -d ' ' -f 1)" = "$expected_sha" ] || exit 3
  echo "fi_public_trust_tool_verified_existing=true"
  exit 0
fi
tmp="$(mktemp "$directory/.incoming-trust.XXXXXXXX")"
trap 'rm -f "$tmp" "$source_file"' EXIT
cat "$source_file" > "$tmp"
test "$(sha256sum "$tmp" | awk '{print $1}')" = "$expected_sha"
chmod 0600 "$tmp"
# Hard link is atomic create-if-absent on same filesystem; no overwrite.
ln "$tmp" "$target"
echo "fi_public_trust_tool_installed=true"
echo "independent_approval_created=false"
echo "fi_public_keys_staged=false"
echo "fi_enrollment_started=false"
