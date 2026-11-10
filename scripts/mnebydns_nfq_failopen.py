#!/usr/bin/env python3
"""Minimal libnetfilter_queue adapter; kernel queue overflow MUST fail open."""
from __future__ import annotations

import ctypes as C
import ctypes.util
import errno
import logging
import os
import struct

LOG = logging.getLogger("mnebydns.nfq")
NF_ACCEPT = 1
NFQNL_COPY_PACKET = 2
NFQA_CFG_F_FAIL_OPEN = 1


def load_library():
    path = ctypes.util.find_library("netfilter_queue")
    if not path:
        raise RuntimeError("libnetfilter_queue is not installed; refusing to start")
    lib = C.CDLL(path, use_errno=True)
    definitions = {
        "nfq_open": (C.c_void_p, []),
        "nfq_close": (C.c_int, [C.c_void_p]),
        "nfq_create_queue": (C.c_void_p, [C.c_void_p, C.c_uint16, C.c_void_p, C.c_void_p]),
        "nfq_destroy_queue": (C.c_int, [C.c_void_p]),
        "nfq_set_mode": (C.c_int, [C.c_void_p, C.c_uint8, C.c_uint32]),
        "nfq_set_queue_flags": (C.c_int, [C.c_void_p, C.c_uint32, C.c_uint32]),
        "nfq_set_queue_maxlen": (C.c_int, [C.c_void_p, C.c_uint32]),
        "nfq_fd": (C.c_int, [C.c_void_p]),
        "nfq_handle_packet": (C.c_int, [C.c_void_p, C.c_void_p, C.c_int]),
        "nfq_get_msg_packet_hdr": (C.c_void_p, [C.c_void_p]),
        "nfq_get_payload": (C.c_int, [C.c_void_p, C.POINTER(C.c_void_p)]),
        "nfq_set_verdict": (C.c_int, [C.c_void_p, C.c_uint32, C.c_uint32, C.c_uint32, C.c_void_p]),
    }
    for name, (restype, args) in definitions.items():
        fn = getattr(lib, name)
        fn.restype = restype
        fn.argtypes = args
    return lib


def must_succeed(result, action):
    if result < 0:
        error = C.get_errno()
        raise OSError(error, f"{action} failed; test aborted")


def run_queue(queue_num, transform, *, ready_file=None, max_len=256):
    """Verify fail-open in kernel before announcing readiness to firewall installer."""
    lib = load_library()
    h = lib.nfq_open()
    if not h:
        raise RuntimeError("nfq_open failed")
    qh = None
    callback_type = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p)
    stats = {"seen": 0, "changed": 0, "unchanged": 0, "errors": 0}

    def callback(q, _msg, data, _user):
        hdr = lib.nfq_get_msg_packet_hdr(data)
        if not hdr:
            LOG.error("No NFQUEUE packet ID; cannot issue verdict")
            return -1
        packet_id = struct.unpack("!I", C.string_at(hdr, 4))[0]
        out = C.c_void_p()
        size = lib.nfq_get_payload(data, C.byref(out))
        raw = C.string_at(out, size) if size > 0 and out.value else b""
        stats["seen"] += 1
        try:
            modified = transform(raw)
            if not isinstance(modified, bytes) or len(modified) != len(raw):
                raise ValueError("Handler must return bytes of unchanged length")
        except Exception:
            stats["errors"] += 1
            LOG.exception("Packet handler error; accepting unchanged")
            modified = raw
        if modified != raw:
            stats["changed"] += 1
            buf = C.create_string_buffer(modified)
            ptr = C.cast(buf, C.c_void_p)
            count = len(modified)
        else:
            stats["unchanged"] += 1
            ptr = None
            count = 0
        outcome = lib.nfq_set_verdict(q, packet_id, NF_ACCEPT, count, ptr)
        if outcome < 0:
            stats["errors"] += 1
            LOG.error("nfq_set_verdict failed with errno=%s", C.get_errno())
        return outcome

    cb = callback_type(callback)
    try:
        qh = lib.nfq_create_queue(h, queue_num, cb, None)
        if not qh:
            raise RuntimeError("nfq_create_queue failed; queue may already be owned")
        must_succeed(lib.nfq_set_mode(qh, NFQNL_COPY_PACKET, 65535), "nfq_set_mode")
        must_succeed(lib.nfq_set_queue_flags(qh, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN),
                     "nfq_set_queue_flags(FAIL_OPEN)")
        must_succeed(lib.nfq_set_queue_maxlen(qh, max_len), "nfq_set_queue_maxlen")
        fd = lib.nfq_fd(h)
        if fd < 0:
            raise RuntimeError("nfq_fd failed")
        if ready_file:
            fd_marker = os.open(ready_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd_marker, b"ready\n")
            finally:
                os.close(fd_marker)
        while True:
            try:
                data = os.read(fd, 65535)
            except OSError as exc:
                if exc.errno == errno.ENOBUFS:
                    LOG.warning("Netlink ENOBUFS; kernel queue is configured FAIL_OPEN")
                    continue
                raise
            if not data:
                raise RuntimeError("NFQUEUE netlink EOF")
            payload = C.create_string_buffer(data)
            must_succeed(lib.nfq_handle_packet(h, payload, len(data)), "nfq_handle_packet")
    finally:
        if ready_file:
            try:
                os.unlink(ready_file)
            except FileNotFoundError:
                pass
        if qh:
            lib.nfq_destroy_queue(qh)
        lib.nfq_close(h)
        LOG.info("NFQUEUE stats: %s", stats)
