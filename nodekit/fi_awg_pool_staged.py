#!/usr/bin/env python3
"""Stage one trusted FI217 AWG pool in RU188, without granting any client.

Two fixed modes:
- fi-material: read (never alter) FI's verified dormant AWG 3.1 config and
  output only NONSECRET public-key/hostname/subnet metadata.
- ru-stage: transactionally insert ONLY the absent FI pool in "staged" state;
  preserve every existing row and refuse drift. Never mark "verified".
This is not live grant/revoke, an E2E proof, or a customer release.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import fcntl
import sys

FI_IP="217.11.167.91"
NODE="fi-test-01"
HOST="fi.mnebyvpn.site"
PORT=51821
SUBNET="10.73.91.0/24"
MATERIAL_FIELDS={"node_id","host","port","subnet","server_public_key"}
KEY=re.compile(r"[A-Za-z0-9+/]{43}=\Z")
STATE=Path("/var/lib/mnebyvpn-nodekit")/NODE

class PoolStageError(ValueError):
    pass

def reject(reason: str) -> None:
    print("FI_AWG_POOL_STAGE_BLOCKED="+reason,file=sys.stderr)
    raise PoolStageError(reason)

def on_host(ip: str) -> bool:
    if os.geteuid()!=0:
        return False
    for _,interface in socket.if_nameindex():
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as fd:
            try:
                raw=fcntl.ioctl(fd.fileno(),0x8915,
                                struct.pack("256s",interface.encode("ascii")))
                if socket.inet_ntoa(raw[20:24])==ip:return True
            except (OSError,UnicodeError):
                pass
    return False

def validate_public(material: object) -> dict:
    if not isinstance(material,dict) or set(material)!=MATERIAL_FIELDS:
        reject("invalid_node_material_shape")
    if (material.get("node_id")!=NODE or material.get("host")!=HOST or
        type(material.get("port")) is not int or material["port"]!=PORT or
        material.get("subnet")!=SUBNET):
        reject("unexpected_fi_node_or_ipam")
    key=material.get("server_public_key")
    if not isinstance(key,str) or not KEY.fullmatch(key):
        reject("invalid_node_awg_public_key")
    try:
        decoded=base64.b64decode(key,validate=True)
    except ValueError:
        reject("invalid_node_awg_public_key")
    if len(decoded)!=32 or base64.b64encode(decoded).decode()!=key:
        reject("noncanonical_node_awg_public_key")
    return material

def from_fi() -> None:
    if not on_host(FI_IP):
        reject("not_independently_known_fi217_root")
    # The existing externally tested validator checks root-owned immutable
    # manifests, source hash, dormant units, absence of subscribers, egress,
    # and canonical AWG 3.1 public key material.
    from awg_external_canary import material
    info=material()
    config=STATE/"amneziawg"/"awg0.conf"
    if config.is_symlink() or not config.is_file():
        reject("missing_canonical_fi_awg_config")
    text=config.read_text("ascii")
    if not re.search(r"(?m)^Address = 10\.73\.91\.1/24$",text):
        reject("unexpected_fi_awg_subnet")
    record=validate_public({
        "node_id":NODE,"host":info["hostname"],"port":info["port"],
        "subnet":SUBNET,"server_public_key":info["server_public_key"],
    })
    print(json.dumps(record,sort_keys=True,separators=(",",":")))

def safe_material(path:Path) -> dict:
    if path.is_symlink() or not path.is_file():
        reject("missing_signed_transport_metadata")
    st=path.stat()
    if (st.st_uid!=0 or not stat.S_ISREG(st.st_mode) or
        st.st_mode&0o077 or st.st_size>2048 or st.st_size<2):
        reject("untrusted_material_file")
    try:
        return validate_public(json.loads(path.read_bytes()))
    except (ValueError,UnicodeDecodeError):
        reject("invalid_material_json")

def stage_on_ru(path:Path) -> None:
    import fi_awg_row_lock_gateway_stage as db
    if not on_host(db.RU):
        reject("not_canonical_ru188")
    # Existing preflight proves enrollment, dedicated scoped role, immutable
    # signer, canonical loopback PostgreSQL, no worker activation and no
    # customer release; all of these remain in force for this transaction.
    db.preflight()
    item=safe_material(path)
    pub=item["server_public_key"]
    # pub is strictly validated base64, so it cannot contain SQL delimiters.
    # All other SQL interpolation is from fixed constants in this file.
    script=f"""
BEGIN;
SET LOCAL statement_timeout='6s';
SET LOCAL lock_timeout='2s';
DO $fi_pool$
DECLARE existing public.vpn_awg_node_pools%ROWTYPE;
BEGIN
 IF (SELECT enabled FROM public.vpn_release_flags
     WHERE feature='vpn_awg_clients' FOR SHARE) IS DISTINCT FROM false
 THEN RAISE EXCEPTION 'FI_POOL_RELEASE_NOT_CLOSED'; END IF;
 IF (SELECT status FROM public.vpn_node_enrollment_inventory
     WHERE node_id='{NODE}' FOR SHARE) IS DISTINCT FROM 'enrolled'
 THEN RAISE EXCEPTION 'FI_POOL_NODE_NOT_ENROLLED'; END IF;
 SELECT * INTO existing FROM public.vpn_awg_node_pools
  WHERE node_id='{NODE}' FOR UPDATE;
 IF NOT FOUND THEN
  INSERT INTO public.vpn_awg_node_pools
   (node_id,endpoint_host,server_public_key,listen_port,subnet_cidr,state,
    external_e2e_proof_sha256,verified_at)
  VALUES ('{NODE}','{HOST}','{pub}',{PORT},'{SUBNET}','staged',NULL,NULL);
 ELSE
  IF (existing.endpoint_host,existing.server_public_key,
      existing.listen_port,existing.subnet_cidr::text)
     IS DISTINCT FROM ('{HOST}','{pub}',{PORT},'{SUBNET}')
  THEN RAISE EXCEPTION 'FI_POOL_EXISTING_BINDING_DRIFT'; END IF;
  IF existing.state NOT IN ('staged','verified','degraded','disabled')
  THEN RAISE EXCEPTION 'FI_POOL_UNEXPECTED_STATE'; END IF;
 END IF;
END
$fi_pool$;
COMMIT;
"""
    db.sql(script)
    result=db.sql(
      "SELECT node_id,endpoint_host,server_public_key,listen_port::text,"
      "subnet_cidr::text,state,COALESCE(external_e2e_proof_sha256,''),"
      "COALESCE((verified_at IS NOT NULL)::text,'false') "
      "FROM public.vpn_awg_node_pools WHERE node_id='fi-test-01';")
    fields=result.split("|")
    if (len(fields)!=8 or fields[:5]!=[
        NODE,HOST,pub,str(PORT),SUBNET] or
        fields[5] not in ("staged","verified","degraded","disabled") or
        not (fields[6]=="" or re.fullmatch("[a-f0-9]{64}",fields[6])) or
        fields[7] not in ("true","false")):
        reject("pool_postcondition_failed")
    if fields[5]=="staged" and (fields[6]!="" or fields[7]!="false"):
        reject("staged_pool_must_not_claim_external_proof")
    if fields[5]=="verified" and (not fields[6] or fields[7]!="true"):
        reject("verified_pool_missing_e2e_evidence")
    print("FI_AWG_POOL_STAGE=STAGED;POOL_PRESENT=true;POOL_STATE="+fields[5]+
          ";CLIENT_RELEASE=false;WORKER_STARTED=false")

def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",required=True,choices=("fi-material","ru-stage"))
    parser.add_argument("--material",type=Path)
    args=parser.parse_args()
    if args.mode=="fi-material":
        if args.material is not None:reject("unexpected_material_path")
        from_fi()
    else:
        if args.material is None:reject("missing_material_path")
        stage_on_ru(args.material)

if __name__=="__main__":
    try:
        main()
    except (PoolStageError,OSError,ValueError,TypeError,KeyError,
            UnicodeError,RuntimeError):
        raise SystemExit(2)
