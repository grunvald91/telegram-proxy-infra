#!/usr/bin/env python3
"""Read-only report comparing LIVE legacy public DoT and personal DoT configuration.
No personal credentials or SQL access. No service changes. DNS probes are bounded.
"""
import concurrent.futures
import hashlib
import json
import os
import pathlib
import re
import secrets
import socket
import ssl
import struct
import time

RU = json.loads(pathlib.Path("ru-personal-snapshot.json").read_text())
DE = json.loads(pathlib.Path("de-legacy-snapshot.json").read_text())
policy = RU["policy"]
assert len(set(policy)) == len(policy), "duplicate personal rules"
exact = {d for d in policy if not d.startswith("*.")}
wild = {d[2:] for d in policy if d.startswith("*.")}
def classified(name):
    return name in exact or any(name.endswith("." + suffix) for suffix in wild)
def sample(rule):
    return "www." + rule[2:] if rule.startswith("*.") else rule

def split_map(config, key):
    marker = "map $ssl_preread_server_name $" + key + " {"
    assert marker in config, f"Nginx map {key} missing"
    return config.split(marker,1)[1].split("}",1)[0]

map443 = split_map(DE["nginx"], "direct_mtproxy_backend")
map853 = split_map(DE["sni853"], "personal_dot_target")
map443_lines = [line.strip() for line in map443.splitlines()
                if line.strip() and not line.strip().startswith("#")]
legacy_exact443 = set()
regex443 = []
other443 = []
for line in map443_lines:
    s = line.strip().split("#",1)[0].strip()
    if not s or not s.endswith(";"):
        continue
    parts=s[:-1].split()
    if len(parts)!=2:continue
    name,backend=parts
    if name.startswith("~"):regex443.append((name,backend))
    elif name == "default":pass
    elif re.fullmatch(r"[a-z0-9.-]+",name):legacy_exact443.add(name.lower())
    else:other443.append(name)
# Parse CoreDNS routing templates; note that one regex may represent entire families.
core = DE["corefile"]
templates = len(re.findall(r"(?m)^\s*template\s+IN\s+(?:A|AAAA|CNAME|HTTPS|SVCB)\s",core))
matches = re.findall(r"(?m)^\s*match\s+(.+)$",core)
core_exact = set()
for line in core.splitlines():
    match=re.match(r"^\s*template\s+IN\s+A\s+([^\s{]+)\s*\{",line)
    if match:
        q=match.group(1).lower().rstrip(".")
        if q!="." and re.fullmatch(r"[a-z0-9.-]+",q):core_exact.add(q)

def query_dot(name, t=1):
    tid=secrets.randbelow(65535)
    q=struct.pack("!HHHHHH",tid,256,1,0,0,0)
    q+=b"".join(bytes([len(x)])+x.encode() for x in name.split("."))+b"\0"+struct.pack("!HH",t,1)
    started=time.monotonic()
    with socket.create_connection(("89.125.90.101",853),timeout=5) as raw:
        raw.settimeout(7)
        with ssl.create_default_context().wrap_socket(raw,server_hostname="dns.mnebyvpn.site") as tls:
            tls.sendall(struct.pack("!H",len(q))+q)
            head=tls.recv(2)
            if len(head)!=2:raise RuntimeError("missing DNS frame")
            length=struct.unpack("!H",head)[0]
            if not 12<=length<=16384:raise RuntimeError("invalid DNS frame")
            data=b""
            while len(data)<length:
                part=tls.recv(length-len(data))
                if not part:raise RuntimeError("partial DNS frame")
                data+=part
    assert data[:2]==q[:2], "DNS ID mismatch"
    rcode=data[3]&15
    off=12
    def skip(off):
        for _ in range(128):
            n=data[off]
            if n&192==192:return off+2
            if n==0:return off+1
            off+=n+1
        raise ValueError("invalid DNS name")
    for _ in range(struct.unpack("!H",data[4:6])[0]):off=skip(off)+4
    ips=[]
    for _ in range(struct.unpack("!H",data[6:8])[0]):
        off=skip(off)
        typ,cls,ttl,n=struct.unpack_from("!HHIH",data,off)
        off+=10
        if typ==1 and cls==1 and n==4:ips.append(socket.inet_ntoa(data[off:off+4]))
        off+=n
    return {"rcode":rcode,"ips":sorted(set(ips)),"ms":round(1000*(time.monotonic()-started))}

def probe_one(rule):
    name=sample(rule)
    try:
        return (rule,name,query_dot(name))
    except Exception as e:
        return (rule,name,{"error":type(e).__name__ + ": " + str(e)[:64]})
# 158 bounded read-only live DNS tests, no brute-force or credentials.
with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
    records=list(pool.map(probe_one,sorted(policy)))
missing=[]
errors=[]
edge_count=0
for rule,name,ans in records:
    if "error" in ans:errors.append((rule,name,ans["error"]))
    elif "89.125.90.101" in ans["ips"]:edge_count+=1
    else:missing.append((rule,name,ans))
# Also compare known exact Nginx 443 host entries against personalized policy;
# these are HTTPS route *candidates* only, not proof of legacy DNS rewrites.
legacy_https_only=sorted(legacy_exact443-set(d for d in legacy_exact443 if classified(d)))
covered443=sorted(d for d in legacy_exact443 if classified(d))
# Common DNS policy can route a regex family rather than exact list.
def nice(rows,limit=100):
    return ", ".join("**"+str(x[0])+"**" for x in rows[:limit]) or "нет"
report=[]
def add(t=""):report.append(t)
add("# Сравнение действующих DNS-маршрутов: стандартный / персональный")
add("")
add("Ревизия только чтения. Текущее состояние серверов на момент запуска GitHub Actions.")
add("")
add("## Как проходят запросы")
add("")
add("| Этап | Обычный DNS | Персональный DNS |")
add("|---|---|---|")
add("| Клиентский TLS/SNI | `dns.mnebyvpn.site:853` | `<12-символьный идентификатор>.dns.mnebyvpn.site:853` |")
add("| Вход DE :853 | `iptables PREROUTING` → Nginx `:8854` → CoreDNS `89.125.90.101:853` | тот же Nginx `:8854` → защищённый WG → RU `10.66.77.2:8856` |")
add("| Проверка доступа | нет PostgreSQL-проверки персонального ID | Node.js: проверка идентификатора (положительный кеш 60 сек) |")
add("| Выбор ветки | CoreDNS на DE применяет общие DNS-шаблоны | Node.js проверяет локальный закреплённый список; premium → DE CoreDNS через `10.66.77.1:1853`, direct → `1.1.1.1:853` |")
add("| Квоты | нет персональных операций reserve/settle | для premium резерв/подтверждение в PostgreSQL при каждом успешном запросе |")
add("| HTTPS при DNS-ответе с адресом DE | клиент → DE `:443` → общий Nginx SNI → целевой сервис | такой же маршрут (если адрес DE получен) |")
add("")
add("## Списки и объём")
add("")
add(f"- **Персональные правила из активного файла: {len(policy)}** (точных {len(exact)}, масок `*.` — {len(wild)}).")
add(f"- **Обычный DNS**: шаблонных блоков CoreDNS для типов A/AAAA/CNAME/HTTPS/SVCB — **{templates}**, строк `match` — **{len(matches)}**, записей `template IN A <домен>` — **{len(core_exact)}**. Это НЕ количество доменов: регулярное выражение может охватывать тысячи имён.")
add(f"- **Общий HTTPS-прокси :443**: записей SNI `map` — **{len(map443_lines)}**, точных DNS-имён — **{len(legacy_exact443)}**, регулярных SNI-правил — **{len(regex443)}**. Это другой уровень маршрутизации, не список DNS-доменов.")
add(f"- Из точных HTTPS SNI имён **{len(legacy_https_only)}** НЕ попадают в персональную premium-политику; **{len(covered443)}** попадают. Для остальных возможен матч через регулярные выражения.")
add("")
add("## Фактические ответы обычного DNS на все персональные правила")
add("")
add(f"Проверено по одному DNS A-запросу для каждого из {len(policy)} правил (для `*.` брали `www.` + домен).")
add(f"- Получен адрес DE **89.125.90.101**: **{edge_count}**.")
add(f"- Другой адрес или отсутствие A: **{len(missing)}**.")
add(f"- Сетевая/протокольная ошибка: **{len(errors)}**.")
add("")
add("**Важное ограничение:** один тестовый поддомен НЕ доказывает поведение всех имён, покрытых маской, а наличие правила SNI :443 не доказывает переадресацию DNS.")
add("")
add("### Персональные правила, для которых обычный DNS НЕ выдал зарубежный IP")
add("")
if missing:
    for rule,name,ans in missing:
        add(f"- `{rule}` → проба `{name}`: RCODE={ans['rcode']}; IPv4={','.join(ans['ips']) or '(нет)'}")
else:add("Не обнаружено на проверенных пробах.")
add("")
add("### Сетевые ошибки контрольных DNS-запросов")
add("")
if errors:
    for rule,name,err in errors:add(f"- `{rule}` → `{name}`: {err}")
else:add("Не обнаружено.")
add("")
add("### Точные HTTPS SNI адреса, не входящие в персональный premium")
add("")
for d in legacy_https_only:add(f"- `{d}`")
if not legacy_https_only:add("Таких адресов нет.")
add("")
add("### Полный действующий список 158 персональных правил")
add("")
for d in sorted(policy):add(f"- `{d}`")
add("")
add("## Диагностические выводы / границы достоверности")
add("")
add("- Не выполнялись запросы с персональным секретом пользователя; функция авторизации и квоты сравниваются по активной конфигурации и проверенному коду, а не по реальному биллингу клиента.")
add("- Полную математически точную разность с «неперсональным списком доменов» невозможно получить простым вычитанием строк: CoreDNS использует регулярные выражения и маршрутизирует целые семейства имён.")
add("- Если обычный DNS отдал адрес DE, а персональный отправил имя по ветке direct, получится разное подключение при одинаковом устройстве.")
out="\n".join(report)+"\n"
pathlib.Path("mnebydns-legacy-personal-route-diff-20261114.md").write_text(out)
summary=os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    with open(summary,"a") as f:
        f.write("\n".join(report[:report.index("### Точные HTTPS SNI адреса, не входящие в персональный premium")])+"\n")
print("AUDIT_ACTIVE_PERSONAL_RULES",len(policy))
print("AUDIT_ACTIVE_PERSONAL_EXACT",len(exact))
print("AUDIT_ACTIVE_PERSONAL_WILDCARDS",len(wild))
print("AUDIT_DE_COREDNS_TEMPLATE_BLOCKS",templates)
print("AUDIT_DE_COREDNS_MATCH_LINES",len(matches))
print("AUDIT_DE_NGINX443_MAP_ITEMS",len(map443_lines))
print("AUDIT_DE_NGINX443_EXACT_HOSTS",len(legacy_exact443))
print("AUDIT_DE_NGINX443_REGEX_GROUPS",len(regex443))
print("AUDIT_NGINX_EXACT_HTTPS_HOSTS_NOT_IN_PERSONAL",len(legacy_https_only))
print("AUDIT_PERSONAL_VS_LEGACY_SAMPLED_EDGE",edge_count)
print("AUDIT_PERSONAL_VS_LEGACY_SAMPLED_NONEDGE",len(missing))
print("AUDIT_PERSONAL_VS_LEGACY_SAMPLED_ERRORS",len(errors))
for d in legacy_https_only:print("AUDIT_NGINX_HTTPS_EXACT_NOT_PREMIUM",d)
for row in missing:print("AUDIT_LEGACY_DNS_NONEDGE_RULE",str(row))
for row in errors:print("AUDIT_LEGACY_DNS_QUERY_ERROR",str(row))
for q in ("chatgpt.com","www.chatgpt.com","ws.chatgpt.com","auth.openai.com","android.chat.openai.com","example.org"):
    print("AUDIT_PERSONAL_CLASSIFICATION",q,"premium" if classified(q) else "direct")
print("AUDIT_PERSONAL_ACTIVE_UPSTREAMS",RU["env"])
print("AUDIT_DE_853_ROUTE",DE["sni853"])
print("AUDIT_FINISHED_READ_ONLY=true")
