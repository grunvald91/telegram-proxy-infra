#!/usr/bin/env python3
"""Offline deterministic full-size contract for MNEBYDNS single-source policy."""
import importlib.util
import json
import pathlib
import tempfile

GEN=pathlib.Path(__file__).with_name("mnebydns-personal-shared-policy-generate-20261114.py")
sp=importlib.util.spec_from_file_location("mnebydns_policy_generator", GEN)
assert sp and sp.loader
mod=importlib.util.module_from_spec(sp)
sp.loader.exec_module(mod)

def exact_template(domain):
    escaped=domain.replace(".","[.]")
    return (
        f"    template IN A {domain} {{\n"
        f"        match ^{escaped}[.]$\n"
        f'        answer "{{{{ .Name }}}} 20 IN A 89.125.90.101"\n'
        f"    }}\n"
    )
def family_template(roots):
    names="|".join(x.replace(".","\\.") for x in roots)
    pattern=f"(?i)^(?:[a-z0-9-]+[.])*(?:{names})[.]$"
    return (
        f"    template IN A . {{\n"
        f"        match {pattern}\n"
        f'        answer "{{{{ .Name }}}} 20 IN A 89.125.90.101"\n'
        f"    }}\n"
    )
exact=[f"site{i:03d}.example.net" for i in range(262)]
family1=[f"family{i:03d}.googlehost.test" for i in range(70)]
family2=["chatgpt.com","openai.com","oaistatic.com","oaiusercontent.com","oaistatsig.com"]
core="tls://.:853 {\n"+"".join(map(exact_template,exact))+family_template(family1)+family_template(family2)+"}\n"
old=exact[:151]+["chatgpt.com","auth.openai.com"]+["*."+n for n in family2]
assert len(old)==158
with tempfile.TemporaryDirectory(prefix="mnebydns-single-source-test-") as d:
    root=pathlib.Path(d)
    config=root/"Corefile"
    personal=root/"prior.json"
    output=root/"derived"/"premium.json"
    config.write_text(core)
    personal.write_text(json.dumps(old))
    manifest=mod.generate(config,personal,output)
    assert manifest["core_a_templates"]==264
    assert manifest["core_exact_domains"]==262
    assert manifest["core_family_roots"]==75
    assert manifest["previous_unmapped_exact"]==111
    assert manifest["original_policy_count"]==158
    assert manifest["new_policy_count"]==412
    derived=json.loads(output.read_text())
    assert len(derived)==412
    assert mod.classify(set(derived),"www.googlehost.example.net") is False
    assert mod.classify(set(derived),"video.family000.googlehost.test") is True
    assert mod.classify(set(derived),"auth.openai.com") is True
    assert mod.classify(set(derived),"example.org") is False
    assert mod.classify(set(derived),"api.telegram.org") is False
    assert output.read_text().endswith("\n")
    previous=output.read_bytes()
    mod.generate(config,personal,output)
    assert output.read_bytes()==previous, "different output for identical CoreDNS source"
    # Production contains additional exact host routes. They must be inherited
    # without a new static count or second personalized domain registry.
    extended=core[:-2] + "".join(
        map(exact_template,[f"growth{i:03d}.example.net" for i in range(300)])
    ) + "}\n"
    config.write_text(extended)
    expanded=mod.generate(config,personal,output)
    assert expanded["core_a_templates"]==564
    assert expanded["core_exact_domains"]==562
    assert expanded["new_policy_count"]==712
    assert mod.classify(set(json.loads(output.read_text())),"growth299.example.net")
    config.write_text(core)
    mod.generate(config,personal,output)
    # An old policy-only domain must not be retained or silently removed.
    personal.write_text(json.dumps(old[:-1]+["*.unrelated.example.com"]))
    try:
        mod.generate(config,personal,output)
    except ValueError as e:
        assert "not backed" in str(e)
    else:raise AssertionError("old-only policy unexpectedly accepted")
    personal.write_text(json.dumps(old))
    # Any unmapped A must make the review fail closed.
    config.write_text(core.replace("89.125.90.101","188.120.254.223",1))
    try:
        mod.generate(config,personal,output)
    except ValueError as e:
        assert "fully routed" in str(e)
    else:raise AssertionError("foreign A template unexpectedly accepted")
    # A broad unmatched family must never be accepted as unreviewed policy.
    config.write_text(core.replace("(?i)^(?:[a-z0-9-]+[.])*(?:","(?i)^.*(?:",1))
    try:
        mod.generate(config,personal,output)
    except ValueError as e:
        assert "noncanonical" in str(e)
    else:raise AssertionError("unreviewed family expression was accepted")
print("MNEBYDNS_SINGLE_SOURCE_262_EXACT_75_FAMILIES_111_MISSING=PASS")
print("MNEBYDNS_SINGLE_SOURCE_OLD_ONLY_UNKNOWN_REGEX_FOREIGN_IP_REJECTED=PASS")
