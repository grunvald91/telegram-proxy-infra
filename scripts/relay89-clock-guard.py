#!/usr/bin/env python3
"""Keep relay89 within MTProxy clock tolerance when UDP NTP is unavailable."""
import argparse
import email.utils
import json
import statistics
import time
import urllib.request
import uuid

SOURCES = (
    "https://www.google.com/generate_204",
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://api.telegram.org/",
)

def validated_offset(samples):
    offsets = [offset for offset, rtt in samples if 0 <= rtt <= 3]
    if len(offsets) < 2:
        raise ValueError("at least two timely HTTPS sources required")
    if max(offsets) - min(offsets) > 2:
        raise ValueError("HTTPS time sources disagree")
    offset = statistics.median(offsets)
    if abs(offset) > 300:
        raise ValueError("clock offset exceeds bounded automatic repair")
    return offset

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    samples = []
    for source in SOURCES:
        start = time.time()
        monotonic_start = time.monotonic()
        try:
            request = urllib.request.Request(
                source + "?clockcheck=" + uuid.uuid4().hex,
                headers={"Cache-Control": "no-cache", "User-Agent": "relay89-clock-guard/1"},
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                server_time = email.utils.parsedate_to_datetime(response.headers["Date"]).timestamp()
            rtt = time.monotonic() - monotonic_start
            # Detect a concurrent clock correction while the request was running.
            if abs((time.time() - start) - rtt) > 0.5:
                raise ValueError("clock changed during observation")
            offset = server_time - (start + rtt / 2)
            samples.append((offset, rtt))
            print(json.dumps({"source": source, "offset_seconds": round(offset, 3),
                              "rtt_seconds": round(rtt, 3)}), flush=True)
        except Exception as exc:
            print(json.dumps({"source": source, "error": type(exc).__name__}), flush=True)
    offset = validated_offset(samples)
    corrected = False
    if args.apply and abs(offset) > 5:
        time.clock_settime(time.CLOCK_REALTIME, time.time() + offset)
        corrected = True
    print(json.dumps({"median_offset_seconds": round(offset, 3), "corrected": corrected}), flush=True)

if __name__ == "__main__":
    main()
