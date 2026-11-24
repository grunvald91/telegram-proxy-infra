#!/usr/bin/env python3
"""Forced-command RU controller bridge for the enrolled FI DNS node only.

Persistent stdio frames, not arbitrary SSH forwarding or remote shell.
The signed meter ABI remains independently authenticated at the controller.
The only additional operation is retrieving the already signed DNS snapshot.
"""
from __future__ import annotations
import fcntl
import json
import os
from pathlib import Path
import select
import socket
import stat
import struct
import sys
import time

SNAPSHOT = Path("/var/lib/mnebyvpn-fi-dns-controller/snapshot.json")
SLOTS = Path("/var/lib/mnebyvpn-fi-dns-controller/ssh-slots")
COMMAND = "fi-dns-rpc-v1"
METER_PORT = 18856
MAX_REQUEST = 4096
MAX_SNAPSHOT = 700000
SNAPSHOT_OP = b"MNEBYVPN_FI_DNS_SNAPSHOT_V1"
PING_OP = b"MNEBYVPN_FI_DNS_PING_V1"
PONG = b"MNEBYVPN_FI_DNS_PONG_V1"


def read_exact(fd, length, timeout):
    end=time.monotonic()+timeout
    data=bytearray()
    while len(data)<length:
        left=end-time.monotonic()
        if left<=0 or not select.select([fd],[],[],left)[0]:
            raise TimeoutError("frame deadline")
        part=os.read(fd,length-len(data))
        if not part:
            raise EOFError
        data.extend(part)
    return bytes(data)


def write_frame(fd, data):
    # Root-only enrolled SSH sessions; bound a peer that stops reading.
    frame=memoryview(struct.pack("!I",len(data))+data)
    end=time.monotonic()+5
    os.set_blocking(fd,False)
    while frame:
        left=end-time.monotonic()
        if left<=0 or not select.select([],[fd],[],left)[1]:
            raise TimeoutError("response deadline")
        try:
            n=os.write(fd,frame)
        except BlockingIOError:
            continue
        if not n:
            raise EOFError
        frame=frame[n:]


def snapshot():
    fd=os.open(SNAPSHOT,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,"rb") as file:
        s=os.fstat(file.fileno())
        if (not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o077
                or not 1<=s.st_size<=MAX_SNAPSHOT):
            raise ValueError("unsafe outbox")
        data=file.read(MAX_SNAPSHOT+1)
        if len(data)!=s.st_size:
            raise ValueError("outbox changed")
    # The receiver verifies the actual controller signature and validity.
    obj=json.loads(data)
    if not isinstance(obj,dict) or obj.get("nodeId")!="fi-test-01" or obj.get("countryCode")!="FI":
        raise ValueError("wrong snapshot")
    return data


def recv_exact(sock,size):
    result=bytearray()
    while len(result)<size:
        data=sock.recv(size-len(result))
        if not data:
            raise EOFError
        result.extend(data)
    return bytes(result)


def meter(data):
    if not 1<=len(data)<=MAX_REQUEST or not data.startswith(b"{"):
        raise ValueError("invalid meter frame")
    with socket.create_connection(("127.0.0.1",METER_PORT),timeout=2) as conn:
        conn.sendall(struct.pack("!I",len(data))+data)
        n=struct.unpack("!I",recv_exact(conn,4))[0]
        if not 1<=n<=MAX_REQUEST:
            raise ValueError("invalid meter reply")
        response=recv_exact(conn,n)
        if conn.recv(1):
            raise ValueError("trailing meter reply")
        return response


def acquire_slot():
    s=SLOTS.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o077:
        raise ValueError("unsafe slot directory")
    for number in range(12):
        fd=os.open(SLOTS/str(number),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:
                raise ValueError("unsafe slot file")
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            os.close(fd)
        except BaseException:
            os.close(fd)
            raise
    raise ValueError("session cap")


def serve(infd=0,outfd=1):
    end=time.monotonic()+3600
    for _ in range(100000):
        if time.monotonic()>end:
            return
        try:
            header=read_exact(infd,4,90)
        except EOFError:
            return
        length=struct.unpack("!I",header)[0]
        if not 1<=length<=MAX_REQUEST:
            raise ValueError("invalid request size")
        data=read_exact(infd,length,2)
        reply=PONG if data==PING_OP else snapshot() if data==SNAPSHOT_OP else meter(data)
        write_frame(outfd,reply)


if __name__=="__main__":
    try:
        if os.geteuid()!=0 or os.environ.get("SSH_ORIGINAL_COMMAND")!=COMMAND or len(sys.argv)!=1:
            raise ValueError("forced command only")
        slot=acquire_slot()
        try:
            serve()
        finally:
            os.close(slot)
    except (OSError,EOFError,ValueError,TypeError,TimeoutError):
        # No user payload, credential, SQL or exception contents in logs.
        raise SystemExit(2)
