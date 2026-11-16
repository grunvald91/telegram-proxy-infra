#!/usr/bin/env python3
"""Read-only CoreDNS owner insertion anchor shape without customer records."""
import pathlib,re,json,hashlib
c=pathlib.Path("/opt/mnebydns-dot/Corefile").read_text()
a="    cache 30\n"
b="    cache 30 {\n"
g="    template IN A gemini.google.com {"
z=c.find(g)
nextcache=(re.search(r"(?m)^    cache 30(?:[ \t]*\{|[ \t]*$)",c[z:]) if z>=0 else None)
print(json.dumps({"read_only":True,
 "core_sha":hashlib.sha256(c.encode()).hexdigest(),
 "original_cache_count":c.count(a),"resilient_cache_count":c.count(b),
 "gemini_a_template_count":c.count(g),
 "first_cache_after_gemini":bool(nextcache),
 "cache_anchor_line_distance":c[z:z+nextcache.start()].count("\n") if nextcache else None}))
