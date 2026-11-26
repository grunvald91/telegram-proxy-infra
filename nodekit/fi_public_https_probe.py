#!/usr/bin/env python3
"""External TLS/HTTP positive and explicit unknown-SNI negative controls."""
import secrets
import socket
import ssl
import struct
import sys

FI = "217.11.167.91"
CTX = ssl.create_default_context()

def dot_denial():
    name = secrets.token_hex(6) + ".fi.mnebyvpn.site"
    query = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
    with socket.create_connection((name, 853), timeout=8) as raw:
        assert raw.getpeername()[0] == FI
        with CTX.wrap_socket(raw, server_hostname=name) as tls:
            tls.sendall(struct.pack("!H", len(query)) + query)
            if tls.recv(2) != b"":
                raise RuntimeError("FI_UNKNOWN_DNS_ACCEPTED")
    print("FI_UNKNOWN_DNS_DENIED=true", flush=True)

def positive(name):
    with socket.create_connection((FI, 443), timeout=8) as raw:
        with CTX.wrap_socket(raw, server_hostname=name) as tls:
            tls.sendall(("HEAD / HTTP/1.1\r\nHost: " + name + "\r\nConnection: close\r\n\r\n").encode("ascii"))
            with tls.makefile("rb") as stream:
                status = stream.readline(2048).split()
            if len(status) < 2 or status[0] not in (b"HTTP/1.0", b"HTTP/1.1") or not status[1].isdigit() or not 100 <= int(status[1]) <= 599:
                raise RuntimeError("invalid_http_response")
            print("FI_EXTERNAL_HTTPS=" + name + ":" + status[1].decode(), flush=True)

def negative():
    with socket.create_connection((FI, 443), timeout=8) as raw:
        try:
            with CTX.wrap_socket(raw, server_hostname="example.org"):
                raise RuntimeError("FI_UNKNOWN_HTTPS_ACCEPTED")
        except ssl.SSLCertVerificationError:
            raise RuntimeError("FI_UNKNOWN_HTTPS_REACHED_ORIGIN") from None
        except (ssl.SSLEOFError, ConnectionResetError):
            pass
        except ssl.SSLError as error:
            if error.reason not in ("UNEXPECTED_EOF_WHILE_READING", "TLSV1_ALERT_INTERNAL_ERROR"):
                raise
    print("FI_UNKNOWN_HTTPS_DENIED=true", flush=True)

if __name__ == "__main__":
    dot_denial()
    if sys.argv[1:] == ["https"]:
        for name in ("www.youtube.com", "api.openai.com", "claude.ai"):
            positive(name)
        negative()
        dot_denial()
