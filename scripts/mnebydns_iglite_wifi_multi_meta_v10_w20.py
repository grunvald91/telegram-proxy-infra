#!/usr/bin/env python3
"""Owner-approved bounded multi-Meta DE SmartDNS 15min SNI-split trial.

Verified Instagram/Meta hostnames are routed through DE while temporary
Temporary TCP Window Scale=0 and early ACK advertised window=20 apply to all
new DE TCP connections; only 11 selected Meta hostnames are routed via DNS.
On the same boot a 1200-second transient systemd rollback timer restores state.
If the VPS reboots during the trial, that timer will not survive; restore from
the owner's offsite backup may be needed. Temporary-only mode is explicit.
"""
from __future__ import annotations
import hashlib
import importlib.util
import ipaddress
import os
from pathlib import Path
import re
import signal
import threading
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time

ROOT = Path("/var/lib/mneby-iglite-wifi-de-20261111-v10")
RECOVERY_UNIT = "mneby-ig-lite-v10-recover.service"
PERSISTENT_STAGE = Path("/usr/local/libexec/mneby-iglite-v10")
MUTATION_MARKER = "mutation-ready"
NGINX = Path("/etc/nginx/nginx.conf")
CORE = Path("/opt/mnebydns-dot/Corefile")
CHECKPOINT_CURRENT = Path("/opt/mnebydns-stable-checkpoints/current")
RENDERER = Path(__file__).resolve().parent / "mnebydns-owner-domain-render-20261110.py"
DE = "89.125.90.101"
HOST = "iglite-z.instagram.com"
HOSTS = (
    "iglite-z.instagram.com", "i.instagram.com",
    "i-fallback.instagram.com", "test-gateway.instagram.com",
    "graph.instagram.com", "z-m-gateway.facebook.com",
    "graph.facebook.com", "www.instagram.com",
    "www.facebook.com", "static.xx.fbcdn.net",
    "scontent.xx.fbcdn.net",
)
TABLE = "mneby_ig_lite_w20_20261111_v10"
UNIT = "mneby-ig-lite-wifi-20261111-v10"
TRIAL_SECONDS = 900
WATCHDOG_SECONDS = 1200
MIN_ROLLBACK_MARGIN = 75
WSFILE = Path("/proc/sys/net/ipv4/tcp_window_scaling")
TEST_WINDOW = 20
FIRST_CLIENT_PACKETS = 16

def command(argv, *, input=None, timeout=25, check=True):
    p = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(argv[0] + " failed with status " + str(p.returncode))
    return p

def sha(data):
    return hashlib.sha256(data).hexdigest()

def write_exclusive(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

def fsync_directory(directory):
    fd=os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(fd)
    finally: os.close(fd)

def atomic_replace(path, data):
    target = path.with_name(path.name + ".mneby-iglite-temp")
    if target.exists() or target.is_symlink():
        raise RuntimeError("Prior staging file still present")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        shutil.copystat(path, target)
        os.replace(target, path)
    finally:
        if target.exists():
            target.unlink()

def baseline():
    if os.geteuid() != 0:
        raise RuntimeError("Root required")
    if os.environ.get("MNEBY_IGLITE_LIVE_APPROVED") != "YES":
        raise RuntimeError("Owner-approved one-shot flag required")
    for svc in ("nginx.service", "mnebydns-dot.service"):
        if command(["systemctl", "is-active", "--quiet", svc], check=False).returncode:
            raise RuntimeError("Baseline service inactive")
    addrs = command(["ip", "-4", "-o", "addr", "show"]).stdout
    if not re.search(r"\s89[.]125[.]90[.]101/", addrs):
        raise RuntimeError("Not the verified DE host")
    if command(["nft", "list", "table", "inet", TABLE], check=False).returncode == 0:
        raise RuntimeError("Prior nft table exists")
    if command(["systemctl", "is-active", "--quiet", UNIT + ".timer"],
               check=False).returncode == 0:
        raise RuntimeError("Prior rollback timer active")
    # Independent earlier watchdog must not overwrite this trial's files.
    if command(["systemctl", "is-active", "--quiet",
                "mneby-ig-lite-short-20261111.timer"],
               check=False).returncode == 0:
        raise RuntimeError("Earlier run still has an active rollback timer")
    if command(["nft", "list", "table", "inet",
                "mneby_ig_lite_w4_20261111"],
               check=False).returncode == 0:
        raise RuntimeError("Earlier experiment still has active nft table")
    # Never terminate an older independent timer to force a new trial.
    # Wait until BOTH its timer and rollback service are no longer running.
    prior_units = ("mneby-ig-lite-short-20261111-v2",
                   "mneby-ig-lite-short-20261111-v3",
                   "mneby-ig-lite-short-20261111-v4",
                   "mneby-ig-lite-short-20261111-v5",
                   "mneby-ig-lite-wifi-20261111-v6",
                   "mneby-ig-lite-wifi-20261111-v7",
                   "mneby-ig-lite-wifi-20261111-v8",
                   "mneby-ig-lite-wifi-20261111-v9")
    for tick in range(76):
        in_flight = any(
            command(["systemctl", "is-active", "--quiet", name + suffix],
                    check=False).returncode == 0
            for name in prior_units for suffix in (".timer", ".service")
        )
        if not in_flight:
            break
        if tick == 0:
            print("iglite_wait_previous_rollback=ACTIVE_WILL_WAIT", flush=True)
        time.sleep(2)
    else:
        raise RuntimeError("Earlier rollback watchdog did not finish; new test blocked")
    print("iglite_previous_rollback_watchdog_finished=true", flush=True)
    for old_table in ("mneby_ig_lite_w4_20261111_v2",
                      "mneby_ig_lite_w4_20261111_v3",
                      "mneby_ig_lite_w4_20261111_v4",
                      "mneby_ig_lite_w4_20261111_v5",
                      "mneby_ig_lite_w4_20261111_v6",
                      "mneby_ig_lite_w4_20261111_v7",
                      "mneby_ig_lite_w4_20261111_v8",
                      "mneby_ig_lite_w4_20261111_v9"):
        if command(["nft", "list", "table", "inet", old_table],
                   check=False).returncode == 0:
            raise RuntimeError("Earlier global Window4 table still active")
    if ROOT.exists():
        raise RuntimeError("Prior one-shot state exists; refuse duplicate")
    # Temporary-only mode is owner approved for this single 900s experiment.
    # The transient 1200s independent systemd rollback timer remains REQUIRED.
    # No claim is made for automatic reboot recovery: user holds offsite backup.
    if Path(__file__).resolve().parent != PERSISTENT_STAGE:
        raise RuntimeError("Live script must run from persistent stage")
    if os.environ.get("MNEBY_IGLITE_TEMPORARY_ONLY_APPROVED") != "YES":
        if command(["systemctl", "is-enabled", "--quiet", RECOVERY_UNIT],
                   check=False).returncode != 0:
            raise RuntimeError("Reboot-persistent recovery service is not enabled")
    else:
        print("iglite_reboot_recovery=NOT_INSTALLED_OWNER_OPTED_FOR_BACKUP",flush=True)
    if command(["systemctl", "is-active", "--quiet", RECOVERY_UNIT],
               check=False).returncode == 0:
        raise RuntimeError("Recovery service already running")
    if WSFILE.read_text().strip() != "1":
        raise RuntimeError("TCP scaling baseline must be on")
    current = CHECKPOINT_CURRENT.read_text().strip()
    stable = Path(current)
    if not stable.is_dir():
        raise RuntimeError("Checkpoint dir absent")
    pairs = (("dns.stable", CORE), ("nginx.stable", NGINX))
    for name, path in pairs:
        original = stable / name
        if not original.is_file() or original.read_bytes() != path.read_bytes():
            raise RuntimeError("Live baseline diverged from stable checkpoint")
    if not RENDERER.is_file():
        raise RuntimeError("Exact route renderer not staged")
    return NGINX.read_bytes(), CORE.read_bytes()

def owner():
    spec = importlib.util.spec_from_file_location("exact", RENDERER)
    if not spec or not spec.loader:
        raise RuntimeError("Renderer import unavailable")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def nft_rules():
    # Limit SYNACK and early ACK window to 20 bytes until the first 16
    # client packets. Window scaling=0 is temporary and restored by watchdog.
    return (
        "add table inet " + TABLE + "\n"
        "add chain inet " + TABLE + " output { type filter hook output priority mangle; policy accept; }\n"
        "add rule inet " + TABLE + " output oifname \"eth0\" ip saddr " + DE
        + " tcp sport 443 ct original packets < " + str(FIRST_CLIENT_PACKETS)
        + " tcp flags & ack == ack counter tcp window set " + str(TEST_WINDOW)
        + " comment \"MNEBY_IG_WIFI_WINDOW20_EARLY\"\n"
        "add chain inet " + TABLE + " post { type filter hook postrouting priority 100; policy accept; }\n"
        "add rule inet " + TABLE + " post oifname \"eth0\" ip saddr " + DE
        + " tcp sport 443 ct original packets < " + str(FIRST_CLIENT_PACKETS)
        + " tcp flags & ack == ack meta mark set meta mark | 0x40000000"
        + " counter comment \"MNEBY_IG_WIFI_PRESERVE_ACK\"\n"
    )


def rollback(*, boot=False):
    """Independent restore; boot mode runs before the normal DNS/nginx start."""
    if not ROOT.is_dir():
        print("iglite_rollback=NO_STATE", flush=True)
        return
    if not (ROOT / MUTATION_MARKER).is_file():
        # Backups might have been written before the first mutation; reboot
        # cannot need restoration in that phase.
        print("iglite_rollback=NO_MUTATION", flush=True)
        return
    nft_absent = command(["nft", "list", "table", "inet", TABLE], check=False).returncode != 0
    wsbackup = ROOT / "tcp_window_scaling.original"
    original_ws = wsbackup.read_text().strip() if wsbackup.is_file() else None
    originals = ((ROOT / "nginx.original").is_file() and (ROOT / "core.original").is_file())
    if (nft_absent and originals and original_ws is not None
        and WSFILE.read_text().strip() == original_ws
        and NGINX.read_bytes() == (ROOT / "nginx.original").read_bytes()
        and CORE.read_bytes() == (ROOT / "core.original").read_bytes()
        and (boot or all(command(["systemctl", "is-active", "--quiet", svc],
                                 check=False).returncode == 0
                         for svc in ("nginx.service", "mnebydns-dot.service")))):
        print("iglite_rollback=ALREADY_RESTORED", flush=True)
        return
    failures = []
    # Remove the test table first, minimizing global window manipulation.
    if command(["nft", "list", "table", "inet", TABLE], check=False).returncode == 0:
        try: command(["nft", "delete", "table", "inet", TABLE])
        except Exception: failures.append("nft")
    if original_ws not in ("0", "1"):
        failures.append("window_scaling_backup_missing")
    elif WSFILE.read_text().strip() != original_ws:
        try: command(["sysctl", "-w", "net.ipv4.tcp_window_scaling=" + original_ws])
        except Exception: failures.append("window_scaling_restore")
    for key, path in (("core", CORE), ("nginx", NGINX)):
        orig = ROOT / (key + ".original")
        candidate = ROOT / (key + ".candidate")
        if not orig.is_file() or not candidate.is_file():
            failures.append(key + "_backup_missing")
            continue
        now = path.read_bytes()
        good = orig.read_bytes()
        after = candidate.read_bytes()
        if now == good:
            continue
        if now != after:
            failures.append(key + "_drift")
            continue
        try: atomic_replace(path, good)
        except Exception: failures.append(key + "_restore")
    # During boot we are ordered before nginx/DoT startup. Never start or
    # reload those services from a Before= one-shot, avoiding a dependency
    # ordering cycle. On a live rollback verify both services are operational.
    if not boot:
        try:
            command(["nginx", "-t"], timeout=20)
            command(["systemctl", "reload", "nginx.service"], timeout=20)
        except Exception: failures.append("nginx_health")
        try:
            command(["systemctl", "restart", "mnebydns-dot.service"], timeout=30)
        except Exception: failures.append("dns_health")
    good = (command(["nft", "list", "table", "inet", TABLE], check=False).returncode != 0
            and original_ws is not None and WSFILE.read_text().strip() == original_ws
            and NGINX.read_bytes() == (ROOT / "nginx.original").read_bytes()
            and CORE.read_bytes() == (ROOT / "core.original").read_bytes()
            and (boot or all(command(["systemctl", "is-active", "--quiet", svc],
                                     check=False).returncode == 0
                             for svc in ("nginx.service", "mnebydns-dot.service"))))
    if not good or failures:
        print("iglite_rollback=FAILED_" + ",".join(failures), flush=True)
        raise RuntimeError("Rollback not verified")
    print("iglite_rollback=" + ("BOOT_FILES_AND_SYSCTL_RESTORED"
          if boot else "VERIFIED_ORIGINAL_BYTES_AND_SERVICES"), flush=True)

def dot_query_a():
    qname = b"".join(bytes((len(part),))+part.encode("ascii")
                     for part in HOST.split(".")) + b"\x00"
    question = struct.pack("!HHHHHH", 0x7171, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    with socket.create_connection((DE, 853), timeout=5) as tcp:
        tcp.settimeout(5)
        with ssl.create_default_context().wrap_socket(tcp, server_hostname="dns.mnebyvpn.site") as tls:
            tls.sendall(struct.pack("!H", len(question)) + question)
            def recv(n):
                data=b""
                while len(data)<n:
                    part=tls.recv(n-len(data))
                    if not part: raise RuntimeError("DoT EOF")
                    data+=part
                return data
            size=struct.unpack("!H",recv(2))[0]
            resp=recv(size)
    if len(resp)<12:
        raise RuntimeError("DoT response too short")
    tid, flags, qd, an, _ns, _ar=struct.unpack_from("!HHHHHH",resp)
    if tid!=0x7171 or not flags & 0x8000 or flags & 0xf:
        raise RuntimeError("DoT transaction or RCODE mismatch")
    def skip_name(at):
        for _ in range(128):
            if at>=len(resp): raise RuntimeError("Truncated DNS name")
            label=resp[at]
            if label&0xc0==0xc0:
                if at+1>=len(resp): raise RuntimeError("Truncated DNS pointer")
                return at+2
            if label&0xc0 or label>63: raise RuntimeError("Invalid DNS label")
            at+=1
            if label==0:return at
            at+=label
        raise RuntimeError("DNS name loop")
    at=12
    for _ in range(qd):
        at=skip_name(at)+4
        if at>len(resp):raise RuntimeError("Truncated DNS question")
    answers=[]
    for _ in range(an):
        at=skip_name(at)
        if at+10>len(resp):raise RuntimeError("Truncated DNS answer")
        kind, cls, _ttl, length=struct.unpack_from("!HHIH",resp,at)
        at+=10
        if at+length>len(resp): raise RuntimeError("Truncated DNS RDATA")
        if kind==1 and cls==1 and length==4:
            answers.append(socket.inet_ntoa(resp[at:at+4]))
        at+=length
    if answers != [DE]:
        raise RuntimeError("Wrong DoT IPv4 records for exact Lite hostname")
    return True


def live_tls():
    ctx = ssl.create_default_context()
    with socket.create_connection((DE, 443), timeout=7) as tcp:
        tcp.settimeout(7)
        with ctx.wrap_socket(tcp, server_hostname=HOST) as tls:
            if not tls.getpeercert():
                raise RuntimeError("Meta certificate not verified")
            return tls.version()


def observe_wifi_tcp_headers(seconds):
    """Aggregate eth0 TCP443 packet *headers*; never log IPs or TLS contents."""
    import collections
    import shutil
    if not shutil.which("tcpdump"):
        raise RuntimeError("Wi-Fi capture cannot start: tcpdump absent")
    counters = collections.Counter()
    clients = set()
    pattern = re.compile(
        r"\bIP (\d{1,3}(?:\.\d{1,3}){3})\.(\d+)\s*>\s*"
        r"(\d{1,3}(?:\.\d{1,3}){3})\.(\d+):.*?"
        r"\bFlags \[([^\]]+)\].*?\blength (\d+)"
    )
    proc = subprocess.Popen(
        ["tcpdump", "-i", "eth0", "-n", "-nn", "-l", "-tt", "-s", "96",
         "tcp and host " + DE + " and port 443"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1
    )
    def consume():
        for line in proc.stdout:
            m = pattern.search(line)
            if not m:
                continue
            src, srcport, dst, dstport, flags, length = m.groups()
            n = int(length)
            inbound = dst == DE and dstport == "443"
            outbound = src == DE and srcport == "443"
            if inbound:
                clients.add(src)
                if "S" in flags and "." not in flags:
                    counters["inbound_syn"] += 1
                if n:
                    counters["inbound_data_segments"] += 1
                    if n <= 4:
                        counters["inbound_data_le4"] += 1
                    else:
                        counters["inbound_data_gt4"] += 1
            if outbound:
                if "S" in flags and "." in flags:
                    counters["outbound_synack"] += 1
                    win = re.search(r"\bwin (\d+)\b", line)
                    if win and int(win.group(1)) == TEST_WINDOW:
                        counters["outbound_synack_window20"] += 1
                elif "S" in flags:
                    counters["outbound_syn_only"] += 1
                elif "." in flags and n == 0:
                    counters["outbound_ack_only"] += 1
    thread = threading.Thread(target=consume, daemon=True)
    thread.start()
    time.sleep(.7)
    if proc.poll() is not None:
        raise RuntimeError("tcpdump exited before capture became ready")
    print("iglite_wifi_header_capture=READY_ON_ETH0", flush=True)
    ready_epoch = int(time.time())
    # A metadata-only readiness marker lets a separate Actions job confirm
    # activation while this long-running SSH job is still executing.
    write_exclusive(ROOT / "ready_epoch", str(ready_epoch).encode("ascii"))
    print("iglite_wifi_capture_start_epoch_s=" + str(ready_epoch), flush=True)
    print("iglite_wifi_15min_window=READY", flush=True)
    try:
        time.sleep(seconds)
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
        thread.join(timeout=5)
        if thread.is_alive():
            proc.kill()
            thread.join(timeout=3)
        if proc.stdout:
            proc.stdout.close()
    names = ("inbound_syn", "inbound_data_segments", "inbound_data_le4",
             "inbound_data_gt4", "outbound_synack",
             "outbound_synack_window20", "outbound_syn_only", "outbound_ack_only")
    for name in names:
        print("iglite_wifi_" + name + "=" + str(counters[name]), flush=True)
    print("iglite_wifi_unique_peer_sources=" + str(len(clients)), flush=True)
    print("iglite_wifi_observation_is_all_tcp443_not_just_meta=true", flush=True)
    print("iglite_wifi_window20_and_mark_change_global_tcp443=true", flush=True)
    print("iglite_wifi_pcap_persisted=false", flush=True)
    print("iglite_wifi_android_peer_identified=false", flush=True)
    print("iglite_wifi_sni_byte_split=NOT_PROVEN_BY_HEADER_CAPTURE", flush=True)
    print("iglite_wifi_header_metric_cannot_identify_phone=true", flush=True)
    sufficient = (counters["outbound_synack_window20"] > 0
                  and counters["inbound_syn"] > 0
                  and counters["inbound_data_segments"] > 0)
    print("iglite_wifi_transport_observation_valid=" + str(sufficient).lower(), flush=True)
    if not sufficient:
        raise RuntimeError("Missing real Window20 SYNACK/client data: trial inconclusive")

def live():
    originals = baseline()
    m = owner()
    ng, core = originals[0].decode(), originals[1].decode()
    accepted = []
    skipped = []
    for hostname in HOSTS:
        try:
            origin = m.origin_ip(hostname)  # HTTPS certificate validated on DE.
            next_ng = m.nginx_add(ng, hostname, origin)
            next_core = m.core_add(core, hostname)
        except (OSError, RuntimeError, ValueError) as err:
            skipped.append(hostname)
            print("iglite_meta_host_skipped=" + hostname + ":" + type(err).__name__, flush=True)
            continue
        ng, core = next_ng, next_core
        accepted.append(hostname)
        print("iglite_meta_host_routed=" + hostname, flush=True)
    print("iglite_meta_expected_count=" + str(len(HOSTS)), flush=True)
    print("iglite_meta_verified_count=" + str(len(accepted)), flush=True)
    print("iglite_meta_skipped_count=" + str(len(skipped)), flush=True)
    if len(accepted) != len(HOSTS) or HOST not in accepted:
        print("iglite_meta_full_coverage=FAIL_BEFORE_LIVE_MUTATION", flush=True)
        raise RuntimeError("Required Meta domains missing: do not label partial trial as full coverage")
    print("iglite_meta_full_coverage=PASS_EXACT_HOSTS_ONLY", flush=True)
    reverse_ng, reverse_core = ng, core
    for hostname in reversed(accepted):
        reverse_ng = m.nginx_remove(reverse_ng, hostname)
        reverse_core = m.core_remove(reverse_core, hostname)
    if reverse_ng.encode() != originals[0] or reverse_core.encode() != originals[1]:
        raise RuntimeError("Multi-route candidate is not byte-reversible")
    print("iglite_meta_routed_count=" + str(len(accepted)), flush=True)
    rules = nft_rules()
    command(["nft", "--check", "-f", "-"], input=rules)
    print("iglite_approved_origin_tls_verified=true", flush=True)
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=False)
    write_exclusive(ROOT / "tcp_window_scaling.original", WSFILE.read_bytes())
    write_exclusive(ROOT / "nginx.original", originals[0])
    write_exclusive(ROOT / "core.original", originals[1])
    write_exclusive(ROOT / "nginx.candidate", ng.encode())
    write_exclusive(ROOT / "core.candidate", core.encode())
    fsync_directory(ROOT)
    fsync_directory(ROOT.parent)
    # nginx syntax parser BEFORE changing any live file.
    command(["nginx", "-t", "-c", str(ROOT / "nginx.candidate")], timeout=25)
    print("iglite_nginx_candidate_syntax_verified=true", flush=True)
    # Independent rollback before touching either service or firewall.
    watchdog_arm_start = time.monotonic()
    command(["systemd-run", "--quiet", "--collect", "--unit", UNIT,
             "--on-active=" + str(WATCHDOG_SECONDS) + "s",
             "/usr/bin/python3", str(Path(__file__).resolve()), "rollback"])
    if command(["systemctl", "is-active", "--quiet", UNIT + ".timer"],
               check=False).returncode:
        raise RuntimeError("Rollback timer not armed")
    print("iglite_independent_rollback_armed=true", flush=True)
    # This durable marker is the last state write before the first mutation.
    # The boot service checks it, so an interrupted backup does not cause
    # a false recovery attempt.
    write_exclusive(ROOT / MUTATION_MARKER, b"armed\n")
    fsync_directory(ROOT)
    try:
        command(["sysctl", "-w", "net.ipv4.tcp_window_scaling=0"])
        print("iglite_live_temporary_kernel_tcp_window_scaling=0", flush=True)
        atomic_replace(NGINX, ng.encode())
        command(["nginx", "-t"], timeout=20)
        command(["systemctl", "reload", "nginx.service"], timeout=20)
        atomic_replace(CORE, core.encode())
        command(["systemctl", "restart", "mnebydns-dot.service"], timeout=30)
        # A systemctl restart can complete before the public-only DoT bind
        # is accepting connections; service-is-active alone is not readiness.
        # A complete route requires no alternate IPv6/CNAME/HTTPS/SVCB
        # reply that lets Android connect directly to Meta instead of DE.
        # Load this helper ONLY during live mode, never during rollback.
        from mnebydns_iglite_dns_wire_checks import check_exact_types
        for hostname in accepted:
            for retry in range(21):
                try:
                    dns_checks = check_exact_types(host=hostname)
                    break
                except (ConnectionRefusedError, ConnectionResetError, TimeoutError):
                    if retry == 20:
                        raise
                    time.sleep(.5)
            for qtype, verdict in dns_checks.items():
                if verdict not in ("A_EXACT_DE", "NO_ALIAS_OR_IPV6"):
                    raise RuntimeError("Unexpected Meta DoT response")
            print("iglite_meta_dot_verified=" + hostname, flush=True)
        print("iglite_live_dot_route_DE=PASS_NO_IPV6_OR_SVCB_ESCAPE", flush=True)
        print("iglite_live_meta_tls=" + live_tls(), flush=True)
        command(["nft", "-f", "-"], input=rules)
        remaining_watchdog = WATCHDOG_SECONDS - (time.monotonic() - watchdog_arm_start)
        print("iglite_wifi_watchdog_remaining_before_probe_s=" + str(int(remaining_watchdog)), flush=True)
        if remaining_watchdog < TRIAL_SECONDS + MIN_ROLLBACK_MARGIN:
            raise RuntimeError("Rollback watchdog may expire during active Wi-Fi capture")
        print("iglite_live_window20_early_no_ws=ACTIVE", flush=True)
        # Independent binary PCAP parser reads TLS SNI only in memory.
        # No packet bytes, client addresses or payloads are persisted.
        from mnebydns_iglite_sni_observer import begin, finish, summary
        pcap_proc, pcap_thread, sni_analyzer, failures = begin(HOSTS)
        print("iglite_sni_pcap_observer=READY", flush=True)
        try:
            observe_wifi_tcp_headers(TRIAL_SECONDS)
        finally:
            summary(finish(pcap_proc, pcap_thread, sni_analyzer, failures))
        snapshot=command(["nft", "-a", "list", "table", "inet", TABLE]).stdout
        matches = re.findall(r"counter packets (\d+)", snapshot)
        if len(matches) != 2:
            raise RuntimeError("Expected exactly two test-owned nft counters")
        print("iglite_live_window20_early_ack_hits=" + matches[0], flush=True)
        print("iglite_live_mark_early_ack_hits=" + matches[1], flush=True)
        if int(matches[0]) == 0 or int(matches[1]) == 0:
            raise RuntimeError("Early ACK window20 and NFQUEUE bypass were not both observed")
    finally:
        rollback()
    print("iglite_end_to_end_android=NOT_TESTED", flush=True)

if __name__ == "__main__":
    if len(sys.argv)!=2 or sys.argv[1] not in ("live", "rollback", "boot-rollback"):
        raise SystemExit("Usage: canary.py live|rollback|boot-rollback")
    if sys.argv[1]=="rollback":
        rollback()
    elif sys.argv[1]=="boot-rollback":
        rollback(boot=True)
    else:
        live()
