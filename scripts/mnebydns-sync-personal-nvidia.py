#!/usr/bin/env python3
"""Add the verified NVIDIA catalog entries to the existing RU188 DoT containers."""
from __future__ import annotations

import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote

BASE = Path("/etc/mnebydns/personal-dot")
MOUNT = "/run/mnebydns-personal"
FILE_KEY = "MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_FILE"
SHA_KEY = "MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_SHA256"
EDGE = "89.125.90.101"
SERVICES = ("mnebydns-personal-dot-private", "mnebydns-personal-dot")
DOMAIN = re.compile(r"(?:[a-z0-9][a-z0-9-]{0,62}\.)*(?:nvidia\.com|nvcr\.io)\Z")


def docker(*args, check=True):
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          timeout=25, check=check)


def inspect(name):
    result = docker("inspect", "--type", "container", name, check=False)
    if result.returncode:
        return None
    return json.loads(result.stdout)[0]


class DockerHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect("/var/run/docker.sock")


def create_container(name, config, host_config):
    conn = DockerHTTP("localhost", timeout=15)
    try:
        conn.request("POST", "/containers/create?name=" + quote(name),
                     json.dumps(dict(config, HostConfig=host_config)),
                     {"Content-Type": "application/json"})
        response = conn.getresponse()
        if response.status != 201:
            raise RuntimeError(f"Docker rejected container settings ({response.status})")
        return json.loads(response.read(32768))["Id"]
    finally:
        conn.close()


def read_exact(sock, amount):
    reply = bytearray()
    while len(reply) < amount:
        chunk = sock.recv(amount - len(reply))
        if not chunk:
            raise RuntimeError("Unexpected DNS EOF")
        reply.extend(chunk)
    return bytes(reply)


def mapped_answer(env, name):
    address = env["MNEBYDNS_PERSONAL_MAPPED_DOT_IP"]
    port = int(env["MNEBYDNS_PERSONAL_MAPPED_DOT_PORT"])
    server_name = env["MNEBYDNS_PERSONAL_MAPPED_DOT_NAME"]
    if port not in (853, 1853) or address not in ("10.66.77.1", EDGE):
        raise RuntimeError("Unrecognized existing mapped DoT endpoint")
    query = (os.urandom(2) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             + b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
             + b"\x00\x00\x01\x00\x01")
    with socket.create_connection((address, port), timeout=8) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=server_name) as tls:
            tls.sendall(struct.pack("!H", len(query)) + query)
            reply = read_exact(tls, struct.unpack("!H", read_exact(tls, 2))[0])
    # CoreDNS owner entries return a single IPv4 A answer at the end of the
    # response. The request carries no EDNS OPT and asks for a single record.
    return (len(reply) >= 28 and reply[:2] == query[:2] and not reply[3] & 15
            and reply[6:12] == b"\x00\x01\x00\x00\x00\x00"
            and reply[-14:-10] == b"\x00\x01\x00\x01" and reply[-6:-4] == b"\x00\x04"
            and reply[-4:] == socket.inet_aton(EDGE))


def ready(name, expected_id, env):
    port = int(env["MNEBYDNS_PERSONAL_DOT_HEALTH_PORT"])
    for _ in range(14):
        data = inspect(name)
        if data and data["Id"] == expected_id and data["State"]["Running"]:
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                try:
                    conn.request("GET", "/readyz")
                    if conn.getresponse().status == 200:
                        return
                finally:
                    conn.close()
            except OSError:
                pass
        time.sleep(0.5)
    raise RuntimeError("Personal DoT readiness probe did not pass")


def rollback(service, backup, old_id, stage):
    if (stage / "committed").is_file():
        return
    saved = inspect(backup)
    live = inspect(service)
    if saved and saved["Id"] == old_id:
        if live:
            marker = (live["Config"]["Labels"] or {}).get("io.mnebydns.nvidia-rollout")
            if marker != stage.name:
                raise RuntimeError("Unexpected personal DNS container replacement")
            docker("rm", "-f", service)
        docker("rename", backup, service)
    live = inspect(service)
    if not live or live["Id"] != old_id:
        raise RuntimeError("Personal DNS rollback could not prove original container")
    if not live["State"]["Running"]:
        docker("start", service)


def update(service, domains, run_id):
    live = inspect(service)
    if not live or not live["State"]["Running"]:
        print("nvidia_personal_service_not_running=" + service, flush=True)
        return
    cfg, host = live["Config"], live["HostConfig"]
    env = dict(entry.split("=", 1) for entry in cfg["Env"])
    if (host["NetworkMode"] != "host" or not host["ReadonlyRootfs"]
            or host["AutoRemove"] or host["RestartPolicy"]["Name"] != "unless-stopped"
            or not any(m["Source"] == str(BASE) and m["Destination"] == MOUNT
                       and not m["RW"] for m in live["Mounts"])):
        raise RuntimeError("Unrecognized existing personal DNS container settings")
    pinned = Path(env[FILE_KEY])
    if pinned.parent != Path(MOUNT) or not re.fullmatch(r"policy[a-zA-Z0-9_.-]*\.json", pinned.name):
        raise RuntimeError("Unrecognized pinned policy location")
    old_file = BASE / pinned.name
    if old_file.is_symlink() or old_file.stat().st_size > 1024 * 1024:
        raise RuntimeError("Untrusted active personal policy")
    old = old_file.read_bytes()
    if hashlib.sha256(old).hexdigest() != env[SHA_KEY]:
        raise RuntimeError("Active personal DNS policy checksum mismatch")
    before = json.loads(old)
    if not isinstance(before, list) or not all(isinstance(entry, str) for entry in before):
        raise RuntimeError("Invalid active personal DNS catalog")
    additions = set(domains) - set(before)
    if not additions:
        print("nvidia_personal_policy_already_current=" + service, flush=True)
        return
    verified = set()
    for domain in sorted(additions):
        try:
            if mapped_answer(env, domain):
                verified.add(domain)
                continue
        except (OSError, RuntimeError):
            pass
        print(f"nvidia_personal_mapped_route_deferred={service}:{domain}", flush=True)
    if not verified:
        print("nvidia_personal_no_new_verified_routes=" + service, flush=True)
        return
    additions = verified

    new = (json.dumps(sorted(set(before) | additions), separators=(",", ":")) + "\n").encode()
    checksum = hashlib.sha256(new).hexdigest()
    target = BASE / f"policy-nvidia-{checksum}.json"
    if target.is_symlink():
        raise RuntimeError("Unexpected personal policy symlink")
    if not target.exists():
        with tempfile.NamedTemporaryFile(dir=BASE, prefix=".nvidia-", delete=False) as temp:
            temp.write(new)
            os.fchmod(temp.fileno(), old_file.stat().st_mode & 0o777)
            os.fchown(temp.fileno(), old_file.stat().st_uid, old_file.stat().st_gid)
        os.replace(temp.name, target)
    if target.read_bytes() != new:
        raise RuntimeError("Existing merged personal policy checksum mismatch")
    env[FILE_KEY] = f"{MOUNT}/{target.name}"
    env[SHA_KEY] = checksum
    cfg = dict(cfg, Image=live["Image"], Env=[f"{key}={value}" for key, value in env.items()])
    backup = f"{service}-before-nvidia-{run_id}"
    stage = Path("/run") / f"{service}-nvidia-{run_id}"
    stage.mkdir(mode=0o700)
    old_id = live["Id"]
    name = stage.name
    labels = dict(cfg.get("Labels") or {})
    labels["io.mnebydns.nvidia-rollout"] = name
    cfg["Labels"] = labels
    completed = False
    subprocess.run(["systemd-run", "--quiet", "--unit", name, "--on-active=5m",
                    sys.executable, str(Path(__file__).resolve()), "rollback",
                    service, backup, old_id, str(stage)], timeout=12, check=True)
    try:
        docker("stop", service)
        docker("rename", service, backup)
        new_id = create_container(service, cfg, host)
        docker("start", service)
        ready(service, new_id, env)
        (stage / "committed").touch()
        completed = True
    except BaseException:
        rollback(service, backup, old_id, stage)
        completed = True
        raise
    finally:
        if completed:
            subprocess.run(["systemctl", "stop", name + ".timer"], timeout=10,
                           check=False, capture_output=True)
    print(f"nvidia_personal_policy_applied={service} additions={len(additions)}", flush=True)


def main():
    lock = Path("/run/lock/mnebydns-personal-nvidia.lock")
    with lock.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        if len(sys.argv) == 6 and sys.argv[1] == "rollback":
            service, backup, old_id, stage = sys.argv[2:]
            if service not in SERVICES or not backup.startswith(service + "-before-nvidia-"):
                raise RuntimeError("Unexpected rollback target")
            rollback(service, backup, old_id, Path(stage))
            return
        if len(sys.argv) < 3 or not re.fullmatch(r"[1-9][0-9]{8,12}", sys.argv[1]):
            raise RuntimeError("Missing production run identifier")
        run_id, *domains = sys.argv[1:]
        if any(not DOMAIN.fullmatch(domain) for domain in domains) or len(set(domains)) != len(domains):
            raise RuntimeError("Unexpected domains in verified NVIDIA catalog")
        for service in SERVICES:
            update(service, domains, run_id)


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, TypeError, ValueError, RuntimeError,
            http.client.HTTPException, subprocess.SubprocessError) as exc:
        # Never print Docker environment or engine response bodies.
        print(f"nvidia_personal_sync_error={type(exc).__name__}", file=sys.stderr)
        if isinstance(exc, RuntimeError):
            print(str(exc), file=sys.stderr)
        raise SystemExit(2) from None
