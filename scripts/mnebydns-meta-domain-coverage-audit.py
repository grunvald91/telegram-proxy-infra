#!/usr/bin/env python3
"""Read-only source-backed candidate coverage audit for Instagram/Threads.
This does NOT modify DNS, Nginx, network policy or active canary routes.
Known sources are documented in docs/mnebydns-meta-domain-gap-research-20261109.md.
Candidate != observed domain; only a device capture can establish use.
"""
from __future__ import annotations
import importlib.util
import json
import pathlib
import sys

HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("meta", HERE/"mnebydns-meta-overlay.py")
assert spec and spec.loader
meta=importlib.util.module_from_spec(spec)
spec.loader.exec_module(meta)

CANDIDATES={
  "instagram.com":"core",
  "www.instagram.com":"core",
  "i.instagram.com":"core",
  "api.instagram.com":"core",
  "graph.instagram.com":"core",
  "edge-chat.instagram.com":"core",
  "gateway.instagram.com":"core",
  "z-p42-chat-e2ee-ig.facebook.com":"core",
  "scontent-hel3-1.cdninstagram.com":"media",
  "static.cdninstagram.com":"media",
  "instagram.fura3-1.fna.fbcdn.net":"media",
  "static.xx.fbcdn.net":"media",
  "threads.com":"core",
  "www.threads.com":"core",
  "threads.net":"core",
  "graph.threads.net":"core",
  "instagramstatic-a.akamaihd.net":"media",
  # These next entries occur in external reports but were never observed
  # in a reliable app-specific capture on this user's device.
  "igcdn-photos-e-a.akamaihd.net":"unconfirmed_media_candidate",
  "igcdn-videos-a-0-a.akamaihd.net":"unconfirmed_media_candidate",
  "threadsapp.net":"unconfirmed_legacy_candidate",
  "otel.atmeta.com":"unconfirmed_telemetry_candidate",
  "giphy.com":"unconfirmed_gif_candidate",
}
def covered(name:str)->bool:
  return name in meta.EXACT or any(
    name == suffix or name.endswith("."+suffix)
    for suffix in meta.SUFFIXES
  )

def run():
  assert len(meta.EXACT)==17 and len(meta.SUFFIXES)==17
  rows=[dict(host=k,type=v,covered=covered(k))
        for k,v in CANDIDATES.items()]
  missing=[row for row in rows if not row["covered"]]
  assert {r["host"] for r in missing}=={
    "igcdn-photos-e-a.akamaihd.net",
    "igcdn-videos-a-0-a.akamaihd.net",
    "threadsapp.net","otel.atmeta.com","giphy.com"}
  assert all(r["covered"] for r in rows if r["type"] in ("core","media"))
  print(json.dumps({
    "source":"current code: mnebydns-meta-overlay.py, no live host capture",
    "existing_meta_exact":len(meta.EXACT),
    "existing_meta_suffixes":len(meta.SUFFIXES),
    "candidate_count":len(rows),
    "out_of_policy_candidates":missing,
    "all_core_names_in_code":True,
    "live_app_success_inferred":False,
    "live_network_changed":False
  },ensure_ascii=False,indent=2))
  print("meta_candidate_domain_gap_offline_audit=PASS")
if __name__=="__main__":
  if sys.argv[1:]:raise SystemExit("No args; read-only")
  run()
