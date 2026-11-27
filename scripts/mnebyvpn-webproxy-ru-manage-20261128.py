#!/usr/bin/env python3
"""Manage multi-domain Telegram WEB proxy (tproxy-server + mtproxy-ru) profiles.

Keeps profiles across tproxy-server-ru / tproxy-server-ru2 synchronized with the
shared official mtproto-proxy backend (up to 16 unique -S secrets), validates
config/profiles before restart, exports tg://webproxy? links, and runs local
admin/systemd health checks. Never prints secrets to git or hardcoded files.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import grp
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

DEFAULT_INSTANCES = "ru1:/etc/tproxy-server-ru,ru2:/etc/tproxy-server-ru2"
DEFAULT_MTPROXY_ENV = "/etc/mtproxy-ru/mtproxy.env"
DEFAULT_TPROXY_BIN = "/usr/local/bin/tproxy-server"
DEFAULT_SYSTEMCTL_BIN = "systemctl"

VALID_CARRIER_MODES = frozenset({"https", "https-lanes", "websocket", "websocket-lanes"})
HEX32_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_MTPROXY_SECRETS = 16


@dataclass(frozen=True)
class ProxyInstance:
    """One tproxy-server instance backed by config.json + profiles.json."""

    name: str
    state_dir: Path
    service_name: str

    @property
    def config_path(self) -> Path:
        return self.state_dir / "config.json"

    @property
    def profiles_path(self) -> Path:
        return self.state_dir / "profiles.json"


def _service_name_for_instance(inst_name: str) -> str:
    if inst_name == "ru1":
        return "tproxy-server-ru.service"
    return f"tproxy-server-{inst_name}.service"


def parse_instances(spec: str) -> list[ProxyInstance]:
    """Parse comma-separated `name:/path` instance specs."""
    out: list[ProxyInstance] = []
    seen: set[str] = set()
    for raw in spec.split(","):
        item = raw.strip()
        if not item:
            continue
        if ":" not in item:
            raise ValueError(f"Invalid instance spec {item!r}; expected name:/path")
        name, path_s = item.split(":", 1)
        name = name.strip()
        if not name or name in seen:
            raise ValueError(f"Invalid or duplicate instance name: {name!r}")
        seen.add(name)
        out.append(ProxyInstance(name=name, state_dir=Path(path_s.strip()), service_name=_service_name_for_instance(name)))
    if not out:
        raise ValueError("No tproxy instances configured")
    return out


def active_instances(instances: list[ProxyInstance], *, require_all: bool = False) -> list[ProxyInstance]:
    """Filter configured instances to existing state dirs unless require_all=True."""
    if require_all:
        return instances
    present = [inst for inst in instances if inst.config_path.is_file() and inst.profiles_path.is_file()]
    if not present:
        raise RuntimeError("No deployed tproxy-server instances found under configured paths")
    return present


def normalize_hex_secret(secret_hex: str) -> str:
    """Validate and lowercase a 16-byte (32-hex) MTProxy secret."""
    cleaned = secret_hex.strip().lower()
    if not HEX32_RE.fullmatch(cleaned):
        raise ValueError("Secret must be exactly 32 lowercase/uppercase hex characters")
    return cleaned


def encode_webproxy_secret(secret_hex: str) -> str:
    """Encode 32-hex secret as URL-safe unpadded base64 with 0x70 WEB prefix byte."""
    raw = bytes.fromhex(normalize_hex_secret(secret_hex))
    return base64.urlsafe_b64encode(b"\x70" + raw).decode("ascii").rstrip("=")


def build_webproxy_link(hostname: str, base_path: str, secret_hex: str) -> str:
    """Build canonical `tg://webproxy?server=...&secret=...` client URI."""
    host = hostname.strip().lower().rstrip("/")
    if not host:
        raise ValueError("hostname must be non-empty")
    path = base_path.strip().strip("/")
    server = f"{host}/{path}" if path else host
    return (
        "tg://webproxy?server="
        + urllib.parse.quote(server, safe="")
        + "&secret="
        + encode_webproxy_secret(secret_hex)
    )


def _atomic_write_text(path: Path, content: str, *, mode: int, group_name: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(tmp_path, mode)
        if group_name and os.geteuid() == 0:
            try:
                gid = grp.getgrnam(group_name).gr_gid
                os.chown(tmp_path, 0, gid)
            except KeyError:
                pass
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def _load_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def validate_instances(
    instances: list[ProxyInstance],
    *,
    tproxy_bin: str = DEFAULT_TPROXY_BIN,
    run_binary_check: bool = False,
) -> dict:
    """Validate config.json + profiles.json across instances and secret count limit."""
    unique_secrets: list[str] = []
    seen_secrets: set[str] = set()
    summary: dict[str, dict] = {}

    for inst in instances:
        cfg = _load_json(inst.config_path)
        hostname = str(cfg.get("public_hostname", "")).strip()
        if not hostname or hostname != hostname.lower():
            raise ValueError(f"{inst.name}: invalid public_hostname {hostname!r}")

        prof_doc = _load_json(inst.profiles_path)
        profiles = prof_doc.get("profiles")
        if not isinstance(profiles, list) or not profiles:
            raise ValueError(f"{inst.name}: profiles must be a non-empty list")

        max_profiles = 32
        limits = cfg.get("limits")
        if isinstance(limits, dict) and isinstance(limits.get("max_profiles"), int):
            max_profiles = limits["max_profiles"]
        if len(profiles) > max_profiles:
            raise ValueError(f"{inst.name}: {len(profiles)} profiles exceed max_profiles={max_profiles}")

        seen_names: set[str] = set()
        inst_secrets: set[str] = set()
        for entry in profiles:
            if not isinstance(entry, dict):
                raise ValueError(f"{inst.name}: profile entry must be an object")
            pname = str(entry.get("name", "")).strip()
            if not pname or pname in seen_names:
                raise ValueError(f"{inst.name}: invalid or duplicate profile name {pname!r}")
            seen_names.add(pname)

            sec = normalize_hex_secret(str(entry.get("secret", "")))
            if sec in inst_secrets:
                raise ValueError(f"{inst.name}: duplicate secret in profile {pname!r}")
            inst_secrets.add(sec)

            mode = str(entry.get("carrier_mode", "https")).strip()
            if mode not in VALID_CARRIER_MODES:
                raise ValueError(f"{inst.name}/{pname}: invalid carrier_mode {mode!r}")

            backend = str(entry.get("backend", "")).strip()
            if not backend or ":" not in backend:
                raise ValueError(f"{inst.name}/{pname}: invalid backend {backend!r}")

            if sec not in seen_secrets:
                seen_secrets.add(sec)
                unique_secrets.append(sec)

        if run_binary_check:
            cmd = [
                tproxy_bin,
                "-check",
                "-config",
                str(inst.config_path),
                "-profiles-file",
                str(inst.profiles_path),
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                raise RuntimeError(
                    f"{inst.name}: tproxy-server -check failed (rc={res.returncode}): {res.stderr.strip() or res.stdout.strip()}"
                )

        summary[inst.name] = {
            "hostname": hostname,
            "base_path": str(cfg.get("base_path", "")),
            "profile_count": len(profiles),
        }

    if not 1 <= len(unique_secrets) <= MAX_MTPROXY_SECRETS:
        raise ValueError(
            f"Total unique MTProxy secrets must be 1..{MAX_MTPROXY_SECRETS}, got {len(unique_secrets)}"
        )

    return {
        "valid": True,
        "unique_secret_count": len(unique_secrets),
        "unique_secrets": unique_secrets,
        "instances": summary,
    }


def sync_mtproxy_env(
    instances: list[ProxyInstance],
    mtproxy_env_path: Path,
    *,
    tproxy_bin: str = DEFAULT_TPROXY_BIN,
    run_binary_check: bool = False,
) -> dict:
    """Sync all unique instance secrets into mtproxy.env MTPROXY_SECRET_ARGS."""
    validation = validate_instances(instances, tproxy_bin=tproxy_bin, run_binary_check=run_binary_check)
    secrets_list: list[str] = validation["unique_secrets"]
    secret_args = " ".join(f"-S {s}" for s in secrets_list)

    existing_lines: list[str] = []
    if mtproxy_env_path.is_file():
        existing_lines = mtproxy_env_path.read_text(encoding="utf-8").splitlines()

    filtered = [
        ln for ln in existing_lines
        if ln.strip() and not ln.startswith("MTPROXY_SECRET=") and not ln.startswith("MTPROXY_SECRET_ARGS=")
    ]
    filtered.append(f"MTPROXY_SECRET={secrets_list[0]}")
    filtered.append(f'MTPROXY_SECRET_ARGS="{secret_args}"')
    payload = "\n".join(filtered) + "\n"

    _atomic_write_text(mtproxy_env_path, payload, mode=0o640, group_name="mtproxy")
    return {
        "mtproxy_env": str(mtproxy_env_path),
        "secret_count": len(secrets_list),
    }


def _find_instance(instances: list[ProxyInstance], name: str) -> ProxyInstance:
    for inst in instances:
        if inst.name == name:
            return inst
    raise KeyError(f"Unknown instance {name!r}")


def mutate_profile(
    *,
    action: str,
    instances: list[ProxyInstance],
    instance_name: str,
    profile_name: str,
    carrier_mode: str = "websocket",
    backend: str = "127.0.0.1:2399",
    max_sessions: int | None = None,
    max_streams: int | None = None,
    max_streams_per_session: int | None = None,
    mtproxy_env_path: Path = Path(DEFAULT_MTPROXY_ENV),
    tproxy_bin: str = DEFAULT_TPROXY_BIN,
    run_binary_check: bool = False,
    apply_restarts: bool = False,
    systemctl_bin: str = DEFAULT_SYSTEMCTL_BIN,
) -> dict:
    """Add, rotate, or remove a WEB-proxy profile atomically and sync mtproxy-ru."""
    inst = _find_instance(instances, instance_name)
    doc = _load_json(inst.profiles_path)
    profiles: list[dict] = list(doc.get("profiles", []))
    before_bytes = inst.profiles_path.read_bytes()

    if carrier_mode not in VALID_CARRIER_MODES:
        raise ValueError(f"Unsupported carrier_mode: {carrier_mode!r}")

    idx = next((i for i, p in enumerate(profiles) if p.get("name") == profile_name), None)
    new_secret: str | None = None

    if action == "add":
        if idx is not None:
            raise ValueError(f"Profile {profile_name!r} already exists in {instance_name}")
        new_secret = secrets.token_hex(16)
        entry: dict = {
            "name": profile_name,
            "secret": new_secret,
            "backend": backend,
            "carrier_mode": carrier_mode,
        }
        limits: dict[str, int] = {}
        if max_sessions is not None:
            limits["max_sessions"] = max_sessions
        if max_streams is not None:
            limits["max_streams"] = max_streams
        if max_streams_per_session is not None:
            limits["max_streams_per_session"] = max_streams_per_session
        if limits:
            entry["limits"] = limits
        profiles.append(entry)
    elif action == "rotate":
        if idx is None:
            raise KeyError(f"Profile {profile_name!r} not found in {instance_name}")
        new_secret = secrets.token_hex(16)
        updated = dict(profiles[idx])
        updated["secret"] = new_secret
        profiles[idx] = updated
    elif action == "remove":
        if idx is None:
            raise KeyError(f"Profile {profile_name!r} not found in {instance_name}")
        if len(profiles) <= 1:
            raise ValueError(f"Refusing to remove the last remaining profile from {instance_name}")
        profiles.pop(idx)
    else:
        raise ValueError(f"Unsupported action: {action!r}")

    doc["profiles"] = profiles
    _atomic_write_text(inst.profiles_path, json.dumps(doc, indent=2) + "\n", mode=0o400)
    try:
        sync_res = sync_mtproxy_env(
            active_instances(instances),
            mtproxy_env_path,
            tproxy_bin=tproxy_bin,
            run_binary_check=run_binary_check,
        )
    except BaseException:
        _atomic_write_text(inst.profiles_path, before_bytes.decode("utf-8"), mode=0o400)
        raise

    if apply_restarts:
        subprocess.run([systemctl_bin, "restart", "mtproxy-ru.service"], check=True)
        subprocess.run([systemctl_bin, "restart", inst.service_name], check=True)

    cfg = _load_json(inst.config_path)
    out = {
        "action": action,
        "instance": instance_name,
        "profile": profile_name,
        "mtproxy_secrets_total": sync_res["secret_count"],
        "restarted": apply_restarts,
    }
    if new_secret is not None:
        out["link"] = build_webproxy_link(str(cfg["public_hostname"]), str(cfg.get("base_path", "")), new_secret)
    return out


def export_links(instances: list[ProxyInstance], *, include_raw_secrets: bool = True) -> list[dict]:
    """Export all configured tg://webproxy links across active instances."""
    rows: list[dict] = []
    for inst in instances:
        cfg = _load_json(inst.config_path)
        hostname = str(cfg["public_hostname"])
        base_path = str(cfg.get("base_path", ""))
        server = f"{hostname}/{base_path}".strip("/") if base_path else hostname
        prof_doc = _load_json(inst.profiles_path)
        for p in prof_doc["profiles"]:
            sec_hex = normalize_hex_secret(str(p["secret"]))
            row = {
                "instance": inst.name,
                "name": p["name"],
                "carrier_mode": p.get("carrier_mode", "https"),
                "server": server,
                "link": build_webproxy_link(hostname, base_path, sec_hex),
            }
            if include_raw_secrets:
                row["secret_hex"] = sec_hex
                row["secret_b64"] = encode_webproxy_secret(sec_hex)
            if "limits" in p:
                row["limits"] = p["limits"]
            rows.append(row)
    return rows


def _parse_metrics(text: str) -> dict[str, float]:
    out: dict[str, float] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if len(parts) == 2:
            try:
                out[parts[0]] = float(parts[1])
            except ValueError:
                pass
    return out


def healthcheck(
    instances: list[ProxyInstance],
    *,
    systemctl_bin: str = DEFAULT_SYSTEMCTL_BIN,
    public_check: bool = False,
) -> dict:
    """Verify mtproxy-ru + tproxy-server-ru* systemd units, /healthz, and metrics."""
    units = ["mtproxy-ru.service", *(inst.service_name for inst in instances)]
    unit_states: dict[str, str] = {}
    healthy = True

    for unit in units:
        res = subprocess.run([systemctl_bin, "is-active", unit], capture_output=True, text=True)
        state = res.stdout.strip() or res.stderr.strip() or "unknown"
        unit_states[unit] = state
        if res.returncode != 0 or state != "active":
            healthy = False

    admin_stats: dict[str, dict] = {}
    public_stats: dict[str, int] = {}

    for inst in instances:
        cfg = _load_json(inst.config_path)
        admin = str(cfg.get("admin_listen", "")).strip()
        if not admin:
            healthy = False
            admin_stats[inst.name] = {"error": "missing admin_listen"}
            continue
        try:
            with urllib.request.urlopen(f"http://{admin}/healthz", timeout=4) as r:
                hz = r.read().decode("utf-8", errors="replace").strip()
                hz_code = r.status
            with urllib.request.urlopen(f"http://{admin}/metrics", timeout=4) as r2:
                metrics = _parse_metrics(r2.read().decode("utf-8", errors="replace"))
            ok = hz_code == 200 and hz == "ok"
            if not ok:
                healthy = False
            admin_stats[inst.name] = {
                "healthz": hz,
                "sessions_live": int(metrics.get("tproxy_sessions_live", 0)),
                "streams_live": int(metrics.get("tproxy_streams_live", 0)),
                "sessions_total": int(metrics.get("tproxy_sessions_created_total", 0)),
                "dial_failures_total": int(metrics.get("tproxy_backend_dial_failures_total", 0)),
                "streams_rejected_total": int(metrics.get("tproxy_streams_rejected_total", 0)),
            }
        except Exception as exc:
            healthy = False
            admin_stats[inst.name] = {"error": f"{type(exc).__name__}: {exc}"}

        if public_check:
            host = str(cfg["public_hostname"])
            bp = str(cfg.get("base_path", "")).strip("/")
            url = f"https://{host}/{bp}/" if bp else f"https://{host}/"
            try:
                with urllib.request.urlopen(url, timeout=6) as pr:
                    public_stats[inst.name] = pr.status
                if public_stats[inst.name] != 200:
                    healthy = False
            except Exception:
                public_stats[inst.name] = 0
                healthy = False

    out = {"healthy": healthy, "units": unit_states, "instances": admin_stats}
    if public_check:
        out["public_http"] = public_stats
    return out


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Manage multi-domain Telegram WEB proxy profiles and mtproxy-ru")
    p.add_argument("--instances", default=os.environ.get("MNEBYVPN_WEBPROXY_INSTANCES", DEFAULT_INSTANCES))
    p.add_argument("--mtproxy-env", default=os.environ.get("MNEBYVPN_MTPROXY_RU_ENV", DEFAULT_MTPROXY_ENV))
    p.add_argument("--tproxy-bin", default=os.environ.get("MNEBYVPN_TPROXY_BIN", DEFAULT_TPROXY_BIN))
    p.add_argument("--systemctl-bin", default=os.environ.get("MNEBYVPN_SYSTEMCTL_BIN", DEFAULT_SYSTEMCTL_BIN))

    sub = p.add_subparsers(dest="cmd", required=True)

    pv = sub.add_parser("validate")
    pv.add_argument("--run-binary-check", action="store_true")
    pv.add_argument("--require-all", action="store_true")

    ps = sub.add_parser("sync-mtproxy")
    ps.add_argument("--run-binary-check", action="store_true")
    ps.add_argument("--restart", action="store_true")

    for act in ("add-profile", "rotate-profile", "remove-profile"):
        pm = sub.add_parser(act)
        pm.add_argument("--instance", required=True)
        pm.add_argument("--name", required=True)
        if act == "add-profile":
            pm.add_argument("--carrier-mode", default="websocket", choices=sorted(VALID_CARRIER_MODES))
            pm.add_argument("--backend", default="127.0.0.1:2399")
            pm.add_argument("--max-sessions", type=int, default=None)
            pm.add_argument("--max-streams", type=int, default=None)
            pm.add_argument("--max-streams-per-session", type=int, default=None)
        pm.add_argument("--run-binary-check", action="store_true")
        pm.add_argument("--apply", action="store_true")

    pe = sub.add_parser("export-links")
    pe.add_argument("--format", choices=("json", "text"), default="json")
    pe.add_argument("--redact-secrets", action="store_true")

    ph = sub.add_parser("healthcheck")
    ph.add_argument("--public-check", action="store_true")

    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    all_instances = parse_instances(args.instances)
    mtproxy_env = Path(args.mtproxy_env)

    if args.cmd == "validate":
        target = active_instances(all_instances, require_all=args.require_all)
        res = validate_instances(target, tproxy_bin=args.tproxy_bin, run_binary_check=args.run_binary_check)
        print(json.dumps({k: v for k, v in res.items() if k != "unique_secrets"}, indent=2, sort_keys=True))
        return 0

    if args.cmd == "sync-mtproxy":
        target = active_instances(all_instances)
        res = sync_mtproxy_env(target, mtproxy_env, tproxy_bin=args.tproxy_bin, run_binary_check=args.run_binary_check)
        if args.restart:
            subprocess.run([args.systemctl_bin, "restart", "mtproxy-ru.service"], check=True)
        print(json.dumps(res, indent=2, sort_keys=True))
        return 0

    if args.cmd in ("add-profile", "rotate-profile", "remove-profile"):
        short_action = args.cmd.split("-", 1)[0]
        res = mutate_profile(
            action=short_action,
            instances=all_instances,
            instance_name=args.instance,
            profile_name=args.name,
            carrier_mode=getattr(args, "carrier_mode", "websocket"),
            backend=getattr(args, "backend", "127.0.0.1:2399"),
            max_sessions=getattr(args, "max_sessions", None),
            max_streams=getattr(args, "max_streams", None),
            max_streams_per_session=getattr(args, "max_streams_per_session", None),
            mtproxy_env_path=mtproxy_env,
            tproxy_bin=args.tproxy_bin,
            run_binary_check=args.run_binary_check,
            apply_restarts=args.apply,
            systemctl_bin=args.systemctl_bin,
        )
        print(json.dumps(res, indent=2, sort_keys=True))
        return 0

    if args.cmd == "export-links":
        rows = export_links(active_instances(all_instances), include_raw_secrets=not args.redact_secrets)
        if args.format == "json":
            print(json.dumps(rows, indent=2))
        else:
            for r in rows:
                print(f"[{r['instance']}] {r['name']} ({r['carrier_mode']}) -> {r['link']}")
        return 0

    if args.cmd == "healthcheck":
        res = healthcheck(active_instances(all_instances), systemctl_bin=args.systemctl_bin, public_check=args.public_check)
        print(json.dumps(res, indent=2, sort_keys=True))
        return 0 if res["healthy"] else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
