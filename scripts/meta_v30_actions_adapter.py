#!/usr/bin/env python3
"""Pinned SSH Actions adapter for the two-server v29 trial.

Validate is offline; preflight is remote and read-only; activate is gated by
workflow_dispatch, manual approval and a current public phone IPv4.
"""
from __future__ import annotations
import argparse
import io
import json
import os
import signal
from pathlib import Path
import shlex
import subprocess
import tarfile
import time
from meta_v29_two_server_sequence import Trial, checked_phone_ip, RU, DE
from meta_v31_sni_evidence import validate_report,write_report

ROOT=Path(__file__).resolve().parents[1]
STAGE="/usr/local/libexec/mneby-meta-v26"
FILES=(
    "meta_v26_de_stage.py", "meta_v26_ru_stage.py",
    "meta_v26_readonly_preflight.py", "meta_v25_source_view.py",
    "meta_v25_view_runtime_smoke.py", "meta_v28_dot_view_smoke.py",
    "meta_v23_ru_firsthop_preview.py", "meta_v15_receive_window.py",
    "mnebydns_iglite_sni_observer.py",
    "mnebydns_iglite_dns_wire_checks.py", "meta_v31_sni_evidence.py",
    "mnebydns_iglite_wifi_multi_meta_v10_w20.py",
    "mnebydns-owner-domain-render-20261110.py",
)
HOSTS={"de":DE,"ru":RU}
SECRETS={"de":"RELAY89_SSH_PASSWORD","ru":"SERVER188_SSH_PASSWORD"}
SCRIPTS={"de":"meta_v26_de_stage.py","ru":"meta_v26_ru_stage.py"}
COMMANDS={
    "de":frozenset(("stage","enable-dns","disable-dns","status","rollback","reset")),
    "ru":frozenset(("start","status","rollback","reset","evidence")),
}
APPROVAL="CONFIRM_CURRENT_PHONE_IP_AND_SNI_TEST"
HEALTH={
    "de":(
        "meta_v26_de_nginx_state=EXPERIMENT",
        "meta_v26_de_dns_state=EXPERIMENT",
        "meta_v26_de_timer_active=true",
        "meta_v26_de_nginx_active=true",
        "meta_v26_de_dns_active=true",
        "meta_v26_de_dot_wire=PASS",
    ),
    "ru":(
        "meta_v26_ru_table_present=true",
        "meta_v26_ru_worker_ready=true",
        "meta_v26_ru_timer_active=true",
        "meta_v26_ru_firewall_scoped=true",
        "meta_v26_ru_evidence_ready=true",
        "meta_v26_ru_wg_tls=PASS",
    ),
}

def validate_manifest(root=ROOT):
    known=root/"ops/mnebydns-owner-ssh-known_hosts"
    if not known.is_file() or not known.stat().st_size:
        raise RuntimeError("pinned SSH host identities missing")
    paths=[]
    for name in FILES:
        path=root/"scripts"/name
        if not path.is_file() or path.is_symlink():
            raise RuntimeError("approved stage file missing or symlink: "+name)
        paths.append(path)
    return tuple(paths)

def bundle(root=ROOT):
    paths=validate_manifest(root)
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode="w") as archive:
        for path in paths:
            body=path.read_bytes()
            info=tarfile.TarInfo(path.name)
            info.size=len(body)
            info.mode=0o600
            archive.addfile(info,io.BytesIO(body))
    return output.getvalue()

def cancel_trial(signum,frame):
    raise InterruptedError("operator requested cancellation")


def check_approval(phone_ip,approved,event):
    peer=checked_phone_ip(phone_ip)
    if event!="workflow_dispatch" or approved!=APPROVAL:
        raise PermissionError("manually approved workflow_dispatch required")
    return peer

class Remote:
    def __init__(self,*,repo_root=ROOT,env=None):
        self.root=repo_root
        self.env=dict(os.environ if env is None else env)
        validate_manifest(repo_root)
        self.known=repo_root/"ops/mnebydns-owner-ssh-known_hosts"
        self.payload=bundle(repo_root)

    def call(self,role,command,*,data=None,timeout=65):
        if role not in HOSTS:raise ValueError("unapproved node")
        secret=self.env.get(SECRETS[role],"")
        if not secret:raise RuntimeError("SSH credential missing for "+role)
        opts=[
            "sshpass","-e","ssh","-T","-o","BatchMode=no",
            "-o","ConnectTimeout=12","-o","StrictHostKeyChecking=yes",
            "-o","HostKeyAlgorithms=ssh-ed25519",
            "-o","UserKnownHostsFile="+str(self.known),
            "-o","GlobalKnownHostsFile=/dev/null",
            "-o","UpdateHostKeys=no","-o","LogLevel=ERROR",
            "root@"+HOSTS[role],command,
        ]
        result=subprocess.run(
            opts,input=data,capture_output=True,timeout=timeout,
            env=dict(self.env,SSHPASS=secret),
        )
        if result.returncode:
            detail=(result.stderr or b"").decode("utf-8",errors="replace")[-6000:]
            # Credentials are only supplied through the environment, never
            # command arguments; still redact them before returning diagnostics.
            detail=detail.replace(secret,"[REDACTED]")
            raise RuntimeError(role+" SSH operation failed: exit "+str(result.returncode)+"\n"+detail)
        return result.stdout.decode("utf-8",errors="replace")

    def preflight(self,role):
        command=(
            "set -eu; umask 077; "
            "d=$(mktemp -d /tmp/mneby-v30-ro.XXXXXXXX); "
            "trap 'rm -rf -- \"$d\"' EXIT; "
            "tar -xf - -C \"$d\"; "
            f"python3 \"$d/meta_v26_readonly_preflight.py\" {role}"
        )
        out=self.call(role,command,data=self.payload,timeout=95)
        if "meta_v26_"+role+"_live_preflight=PASS" not in out:
            raise RuntimeError(role+" real read-only preflight did not pass")
        if role=="de" and "meta_v26_de_loopback_dot_tls_source_split=PASS" not in out:
            raise RuntimeError("DE real binary DoT source-view test missing")
        if "meta_v26_"+role+"_no_prod_writes=true" not in out:
            raise RuntimeError(role+" readonly attestation missing")
        return out

    def stage_files(self,role):
        command=(
            "set -eu; umask 077; "
            "test ! -L /usr/local/libexec; "
            "if test ! -d /usr/local/libexec; then "
            "install -d -m 0755 -o root -g root /usr/local/libexec; fi; "
            f"test ! -e {STAGE}; "
            "d=$(mktemp -d /usr/local/libexec/.mneby-meta-v26.XXXXXXXX); "
            "trap 'rm -rf -- \"$d\"' EXIT; "
            "tar -xf - -C \"$d\" --no-same-owner --no-same-permissions; "
            "chown -R root:root \"$d\"; chmod 700 \"$d\"; "
            f"mv -- \"$d\" {STAGE}; "
            "trap - EXIT"
        )
        self.call(role,command,data=self.payload,timeout=50)

    def run(self,role,action,peer=None):
        if role not in COMMANDS or action not in COMMANDS[role]:
            raise ValueError("unapproved remote action")
        needs_peer=action in ("stage","start")
        if needs_peer!=(peer is not None):
            raise ValueError("wrong peer argument for remote action")
        script=STAGE+"/"+SCRIPTS[role]
        command=("MNEBY_META_V26_APPROVED=YES /usr/bin/python3 "
                 +shlex.quote(script)+" "+shlex.quote(action))
        if needs_peer:command+=" --peer "+shlex.quote(checked_phone_ip(peer))
        return self.call(role,command,timeout=145 if needs_peer else 70)

    def verify_health(self):
        for role in ("de","ru"):
            lines=self.run(role,"status").splitlines()
            for line in HEALTH[role]:
                if line not in lines:
                    raise RuntimeError(role+" health check failed: "+line)

    def collect_evidence(self,*,final=False,require_success=False):
        report=json.loads(self.run("ru","evidence"))
        # Persist before checking success and before remote reset deletes state.
        # Failed/no-traffic experiments must retain their actual evidence too.
        directory=Path(self.env.get("RUNNER_TEMP","/tmp"))/"meta-v31-evidence"
        directory.mkdir(mode=0o700,parents=True,exist_ok=True)
        write_report(directory/"phone-sni.json",report)
        print("meta_v31_sni_verdict="+str(report.get("verdict","NO_EVIDENCE")),flush=True)
        counts=report.get("stats",{})
        for key in ("target_clienthello","sni_split","sni_unsplit","sni_boundary_indeterminate"):
            print("meta_v31_"+key+"="+str(counts.get(key,0)),flush=True)
        if require_success:validate_report(report,final=final)
        return report

    def active_window(self,seconds):
        self.verify_health()
        self.collect_evidence(require_success=True)
        print("meta_v30_phone_test_ready=true",flush=True)
        print("meta_v30_test_window_started=true",flush=True)
        print("meta_v30_test_window_seconds="+str(seconds),flush=True)
        until=time.monotonic()+seconds
        checks=0
        while True:
            self.verify_health()
            self.collect_evidence(require_success=True)
            checks+=1
            print("meta_v30_health_check_count="+str(checks),flush=True)
            remaining=until-time.monotonic()
            if remaining<=0:
                print("meta_v30_test_window_completed=true",flush=True)
                return
            time.sleep(min(15,remaining))

    def reset(self,role):
        self.run(role,"reset")
        state="/var/lib/mneby-meta-v26-"+role
        timer="mneby-meta-v26-"+role+"-watchdog.timer"
        safe=("set -eu; "
              f"test ! -e {state}; "
              f"if systemctl is-active --quiet {timer}; then exit 3; fi; "
              f"rm -rf -- {STAGE}")
        self.call(role,safe,timeout=40)

def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("validate","preflight","activate"),required=True)
    p.add_argument("--phone-ip")
    p.add_argument("--minutes",type=int,default=30)
    args=p.parse_args(argv)
    if args.mode=="validate":
        validate_manifest()
        print("meta_v30_adapter_manifest=PASS",flush=True)
        print("meta_v30_no_automatic_live_trigger=true",flush=True)
        return
    if args.mode=="activate":
        if not args.phone_ip:raise ValueError("current phone IPv4 required")
        peer=check_approval(args.phone_ip,os.environ.get("MNEBY_META_V30_APPROVED"),
                            os.environ.get("GITHUB_EVENT_NAME"))
        if args.minutes not in (5,15,30):
            raise ValueError("approved window must be 5, 15 or 30 minutes")
    if args.mode=="activate":
        signal.signal(signal.SIGTERM,cancel_trial)
        signal.signal(signal.SIGINT,cancel_trial)
    adapter=Remote()
    for role in ("de","ru"):
        adapter.preflight(role)
        print("meta_v30_"+role+"_preflight=PASS",flush=True)
    if args.mode=="preflight":
        print("meta_v30_production_changes=false",flush=True)
        return
    installed=[]
    attempted=False
    failure=None
    try:
        for role in ("de","ru"):
            adapter.stage_files(role)
            installed.append(role)
        attempted=True
        Trial(adapter.run,adapter.active_window).run(peer,seconds=args.minutes*60)
    except BaseException as exc:
        failure=exc
    if attempted:
        try:adapter.collect_evidence(final=True,require_success=failure is None)
        except BaseException as exc:
            if failure is None:failure=exc
    cleanup_errors=[]
    for role in reversed(installed):
        try:adapter.reset(role)
        except BaseException as exc:
            cleanup_errors.append(role+":"+type(exc).__name__)
    if cleanup_errors:
        raise RuntimeError("v30 cleanup verification failed: "+",".join(cleanup_errors)) from failure
    if failure:
        raise RuntimeError("v30 trial failed; cleanup verified") from failure
    print("meta_v30_trial_finished_cleanup_verified=true",flush=True)
    print("meta_v31_phone_sni_segmentation=OBSERVED",flush=True)
    print("meta_v30_instagram_android_works=NOT_PROVEN",flush=True)

if __name__=="__main__":
    main()
