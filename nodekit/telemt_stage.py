#!/usr/bin/env python3
"""Verified, dormant Telemt stage. Never starts a service or issues credentials."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
from install_components import node_ready, safe_dir, safe_manifest
from nodekit import _promote_stage_noreplace

ROOT = Path("/var/lib/mnebyvpn-nodekit")
RELEASE = "3.5.17"
ASSETS = {
 "x86_64": ("telemt-x86_64-linux-gnu.tar.gz", "0570762ddcd79530d666b09e955b955bb52c9e134cc8b8ed1a0f50ad28d58a0e"),
 "aarch64": ("telemt-aarch64-linux-gnu.tar.gz", "f0d3d06d029f2b21dc66a44069bcc7bd20d32fcb34b5867c5250cee647785de6"),
}

class TelemtError(ValueError):
    pass

def config(host):
    if not isinstance(host, str) or len(host) > 253 or not all(
       label and len(label) <= 63 and label.replace("-", "").isalnum() and
       not label.startswith("-") and not label.endswith("-") for label in host.split(".")):
        raise TelemtError("Invalid inventory hostname")
    data = (f'[general]\nuse_middle_proxy = true\nlog_level = "silent"\n'
      f'[general.modes]\nclassic = false\nsecure = false\ntls = true\n'
      f'[general.links]\nshow = []\n[server]\nport = 9447\n'
      f'[server.api]\nenabled = false\nlisten = "127.0.0.1:9098"\n'
      f'whitelist = ["127.0.0.1/32"]\nread_only = true\n'
      f'[[server.listeners]]\nip = "127.0.0.1"\n'
      f'[censorship]\ntls_domain = "{host}"\nmask = false\n'
      f'tls_emulation = false\n[access.users]\n').encode()
    parsed = tomllib.loads(data.decode())
    if parsed["server"]["api"]["enabled"] is not False or parsed["access"]["users"]:
        raise TelemtError("Telemt stage must not authorize customers")
    return data

def extract_binary(data, arch):
    if arch not in ASSETS or len(data) > 16_000_000 or hashlib.sha256(data).hexdigest() != ASSETS[arch][1]:
        raise TelemtError("Unverified Telemt release archive")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        items = [x for x in archive.getmembers() if x.name.lstrip("./") == "telemt"]
        if len(items) != 1 or not items[0].isfile() or not 4 < items[0].size <= 40_000_000:
            raise TelemtError("Unsafe Telemt release member")
        stream = archive.extractfile(items[0])
        if stream is None:
            raise TelemtError("Missing release payload")
        binary = stream.read(40_000_001)
    if not binary.startswith(b"\x7fELF") or len(binary) > 40_000_000:
        raise TelemtError("Unexpected Telemt executable")
    return binary

def download(arch):
    if arch not in ASSETS:
        raise TelemtError("Unsupported CPU architecture")
    filename = ASSETS[arch][0]
    uri = f"https://github.com/telemt/telemt/releases/download/{RELEASE}/{filename}"
    req = urllib.request.Request(uri, headers={"User-Agent": "MNEBYVPN-Nodekit/1"})
    data = bytearray()
    with urllib.request.urlopen(req, timeout=40) as source:
        while chunk := source.read(65536):
            data.extend(chunk)
            if len(data) > 16_000_000:
                raise TelemtError("Telemt download oversized")
    return extract_binary(bytes(data), arch)

def check_file(path, digest, maximum):
    if path.is_symlink() or not path.is_file():
        raise TelemtError("Missing or symlinked file")
    s = path.stat()
    if s.st_uid != 0 or s.st_mode & 0o077 or s.st_size > maximum:
        raise TelemtError("Unsafe file permissions or size")
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() != digest:
        raise TelemtError("File differs from recorded stage")
    return content

def inspect(node, host):
    folder = node / "telemt-stage"
    safe_dir(folder)
    manifest = safe_manifest(folder / "manifest.json")
    if (manifest.get("node_id") != node.name or manifest.get("host") != host or
        manifest.get("version") != RELEASE or manifest.get("state") != "staged" or
        manifest.get("enabled") is not False or manifest.get("users_enabled") is not False or
        set(manifest.get("files", {})) != {"telemt", "config.toml", "service.candidate"}):
        raise TelemtError("Unsafe Telemt candidate manifest")
    for name, digest in manifest["files"].items():
        content = check_file(folder / name, digest, 40_000_000)
        if name == "config.toml" and content != config(host):
            raise TelemtError("Telemt config was modified")
        if name == "telemt" and not content.startswith(b"\x7fELF"):
            raise TelemtError("Telemt binary is not ELF")
    return {"node_id": node.name, "telemt_version": RELEASE, "staged": True,
            "public_listener_enabled": False, "systemd_installed": False,
            "users_enabled": False, "ready": False}

def stage(node, host):
    target = node / "telemt-stage"
    if target.exists() or target.is_symlink():
        return inspect(node, host)
    binary = download(os.uname().machine)
    candidate = Path(tempfile.mkdtemp(prefix=".telemt-", dir=node))
    try:
        os.chmod(candidate, 0o700)
        unit = (f"[Unit]\nDescription=Nodekit Telemt {node.name} (dormant)\n"
          f"[Service]\nType=simple\nExecStart={target}/telemt {target}/config.toml\n"
          f"WorkingDirectory={target}\nNoNewPrivileges=true\nPrivateTmp=true\n"
          f"ProtectSystem=strict\n[Install]\nWantedBy=multi-user.target\n").encode()
        content = {"telemt": binary, "config.toml": config(host), "service.candidate": unit}
        for name, body in content.items():
            path = candidate / name
            with path.open("xb") as output:
                output.write(body)
            path.chmod(0o700 if name == "telemt" else 0o600)
        info = {"node_id": node.name, "host": host, "version": RELEASE,
                "state": "staged", "enabled": False, "users_enabled": False,
                "files": {k: hashlib.sha256(v).hexdigest() for k,v in content.items()}}
        record = candidate / "manifest.json"
        record.write_text(json.dumps(info, sort_keys=True) + "\n")
        record.chmod(0o600)
        if target.exists() or target.is_symlink():
            raise TelemtError("Concurrent Telemt stage")
        _promote_stage_noreplace(candidate, target)
    finally:
        if candidate.exists():
            shutil.rmtree(candidate)
    return inspect(node, host)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--node-id", required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--mode", choices=("stage","inspect"), required=True)
    args = ap.parse_args()
    try:
        if os.geteuid() != 0:
            raise TelemtError("Root-only stage")
        node = node_ready(ROOT, args.node_id, allow_production=True)
        review = safe_manifest(node / "manifest.json")
        if review.get("advertise_host") != args.host:
            raise TelemtError("Unexpected inventory hostname")
        print(json.dumps(stage(node,args.host) if args.mode=="stage"
                         else inspect(node,args.host), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, tarfile.TarError) as exc:
        print("NODEKIT_TELEMT_STAGE_ERROR=" + type(exc).__name__, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
