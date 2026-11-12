#!/usr/bin/env python3
"""Fail-closed two-server v29 trial sequence, OFFLINE abstraction only.

This module does not implement SSH, install files or activate production.
A future reviewed caller may inject a remote adapter after authoritative
phone-IPv4 and public DoT source isolation checks. Independent RU and DE
same-boot recovery timers remain required by their individual controllers.
"""
from __future__ import annotations

from collections.abc import Callable
import ipaddress

RU="188.120.254.223"
DE="89.125.90.101"
SECONDS=900
MAX_SECONDS=1800
SETUP=(("de","stage"),("ru","start"),("de","enable-dns"))
CLEANUP=(("de","disable-dns"),("ru","rollback"),("de","rollback"))


def checked_phone_ip(value: str) -> str:
    if value=="all":return value
    ip=ipaddress.IPv4Address(value)
    if not ip.is_global or str(ip) in (RU,DE):
        raise ValueError("distinct public test-device IPv4 required")
    return str(ip)


def plan() -> tuple[tuple[str,str], ...]:
    return SETUP+CLEANUP


class TrialFailure(RuntimeError):
    pass


class Trial:
    def __init__(self, remote: Callable[[str,str,str|None],None],
                 active_window: Callable[[int],None]):
        self.remote=remote
        self.active_window=active_window

    def run(self, peer: str, *, seconds: int = SECONDS) -> None:
        peer=checked_phone_ip(peer)
        if type(seconds) is not int or not 1<=seconds<=MAX_SECONDS:
            raise ValueError("test must end within 1800 seconds")
        primary=None
        cleanup_failures=[]
        try:
            for server,command in SETUP:
                self.remote(server,command,peer if command in ("stage","start") else None)
            # The callback may emit health probes throughout the 15-minute
            # manual-phone window; failure immediately triggers teardown.
            self.active_window(seconds)
        except BaseException as exc:
            primary=exc
        finally:
            # First revoke the scoped DoT answer while RU still routes it,
            # then stop RU interception and finally remove DE SNI routes.
            # Always attempt all stages even after a partial failure.
            for server,command in CLEANUP:
                try:self.remote(server,command,None)
                except BaseException as exc:
                    cleanup_failures.append(server+":"+command+":"+type(exc).__name__)
        if cleanup_failures:
            raise TrialFailure("coordinated cleanup incomplete: "+",".join(cleanup_failures)) from primary
        if primary:
            raise TrialFailure("trial aborted after "+type(primary).__name__) from primary


if __name__=="__main__":
    for server,command in plan():
        print(server+"."+command)
    print("meta_v29_live_activation=NOT_IMPLEMENTED")
    print("meta_v29_android_e2e=NOT_TESTED")
