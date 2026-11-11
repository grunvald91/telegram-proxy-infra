#!/usr/bin/env python3
"""Offline CoreDNS source-IP split-view renderer; never applies live files.

Duplicates ONLY the existing DoT server block before its unchanged fallback.
The first block handles one explicit IPv4 (view plugin); everyone else keeps
the byte-identical original. Fail closed on unreviewed syntax.
"""
from __future__ import annotations
import ipaddress
import re
from dataclasses import dataclass
from meta_v23_ru_firsthop_preview import RU_EDGE, HOSTS, load_renderer

VIEW_NAME="mneby_meta_phone"
VIEW_LINE="    view "+VIEW_NAME+" {\n        expr client_ip() == '{peer}'\n    }\n"
DOT_HEADER=re.compile(r"(?m)^[ \t]*(?:tls://)?(?:\.|[0-9.]+)?:853[ \t]*\{[ \t]*(?:#[^\n]*)?$")

@dataclass(frozen=True)
class ViewPlan:
    original: str
    candidate: str
    selected_source: str
    selected_hosts: int

    def verify_rollback(self) -> None:
        prefix=self.candidate[:len(self.candidate)-len(self.original)]
        if not prefix or self.candidate!=prefix+self.original:
            raise RuntimeError("original Corefile was not preserved byte-for-byte")
        if self.candidate.count("view "+VIEW_NAME)!=1:
            raise RuntimeError("non-unique owner source-IP view")

def check_plugins(output: str)->None:
    names=set(output.split())
    for name in ("view","template","tls"):
        if name not in names:
            raise RuntimeError("CoreDNS binary lacks "+name+" plugin")

def source_peer(peer: str)->str:
    parsed=ipaddress.IPv4Address(peer)
    if not parsed.is_global or str(parsed) in (RU_EDGE,"89.125.90.101"):
        raise ValueError("distinct global test client IPv4 required")
    return str(parsed)

def _block_end(text: str, offset: int)->int:
    """Scan matching braces, ignoring quoted CoreDNS template text/comments."""
    if text[offset]!="{":
        raise ValueError("not a CoreDNS block")
    depth=0;quoted=False;comment=False;escape=False
    for pos in range(offset,len(text)):
        char=text[pos]
        if comment:
            if char=="\n":comment=False
            continue
        if quoted:
            if escape:escape=False
            elif char=="\\":escape=True
            elif char=='"':quoted=False
            continue
        if char=='"':quoted=True
        elif char=="#":comment=True
        elif char=="{":depth+=1
        elif char=="}":
            depth-=1
            if depth==0:return pos+1
            if depth<0:raise ValueError("Corefile brace imbalance")
    raise ValueError("incomplete CoreDNS server block")

def render(*, corefile: str, phone_ip: str, compiled_plugins: str)->ViewPlan:
    peer=source_peer(phone_ip)
    check_plugins(compiled_plugins)
    if VIEW_NAME in corefile:
        raise ValueError("an experimental source view is already present")
    matches=list(DOT_HEADER.finditer(corefile))
    if len(matches)!=1:
        raise ValueError("exactly one reviewed DoT :853 block required")
    selected=matches[0]
    start=selected.start()
    # Only server blocks beginning at top level are supported. No imports,
    # ambiguous nested :853 headers or already-overlapping pilot routes.
    before=corefile[:start]
    if "import " in corefile or before.count("{")!=before.count("}"):
        raise ValueError("cannot establish an unambiguous top-level DNS block")
    block_end=_block_end(corefile,corefile.index("{",selected.start(),selected.end()))
    block=corefile[start:block_end]
    if not block.endswith("}"):
        raise ValueError("unreviewed trailing CoreDNS block syntax")
    renderer=load_renderer()
    duplicate=block
    for host in HOSTS:
        duplicate=renderer.core_add(duplicate,host,route_edge=RU_EDGE)
    # Place the restricted block first; do not rewrite the existing fallback.
    header_end=duplicate.index("{")+1
    gated=duplicate[:header_end]+"\n"+VIEW_LINE.replace("{peer}",peer)+duplicate[header_end:]
    candidate=gated+"\n"+corefile
    result=ViewPlan(corefile,candidate,peer,len(HOSTS))
    result.verify_rollback()
    if candidate[len(gated)+1:]!=corefile:
        raise RuntimeError("baseline fallback Corefile differs")
    for host in HOSTS:
        if duplicate.count('answer "{{ .Name }} 20 IN A '+RU_EDGE+'"')!=len(HOSTS):
            raise RuntimeError("a Meta route escaped the source-gated block")
    return result
