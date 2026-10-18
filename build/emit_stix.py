#!/usr/bin/env python3
"""Emit a STIX 2.1 bundle from the curated IOC file.

Why STIX specifically: Amnesty's MVT already does mobile forensics well and
consumes STIX. We do not compete with it (SPEC-scanner.md non-goals) — we hand its
users the indicators so they can run their own trusted tool against their own
devices. A newsroom admin can load the same bundle into MISP or a SIEM.

Deterministic IDs: object UUIDs are uuid5 over a fixed namespace plus the
indicator value, so re-running this emitter produces the SAME ids. MISP and MVT
can then de-duplicate across updates instead of accumulating copies.

Usage:
    python emit_stix.py [--iocs ../iocs/adfection_iocs.txt] [--out ../dist/adfection.stix.json]

No network access. Reads one local file, writes one local file.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "scan"))

from adint_scan import iocs as iocmod  # noqa: E402

# Stable namespace for this project's deterministic STIX ids.
NAMESPACE = uuid.UUID("6f0b4a2e-5d1c-4f3b-9a7e-adf3c70f1001")

CITIZENLAB_URL = ("https://citizenlab.ca/research/"
                  "how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/")

# Per-tier wording. The tier is the whole point of the curation: a delivery domain
# in your logs means something very different from a C&C callback.
TIER_DESCRIPTION = {
    "cc": "Candiru command-and-control server. A connection to this is the most "
          "serious of the indicator classes.",
    "validator": "Candiru validator server. Profiled a device and decided per "
                 "device whether to deliver an exploit.",
    "delivery": "Discover-Tech / Controlium ad-delivery infrastructure. An "
                "impression from this is NOT proof of infection — not every ad "
                "carried a payload.",
    "historical": "Infrastructure from the separate, older 2021 'Hooking Candiru' "
                  "campaign. Included because a hit would still be significant.",
    "sample": "SHA-256 of a published Candiru sample. One build only; another "
              "victim's binary will not match.",
    "candiru": "Candiru-attributed server infrastructure. The source lists eight "
               "clusters mixing victim-facing C2 with higher-tier operator "
               "infrastructure and does not state which role this domain had, so "
               "the role is unspecified. A hit is serious.",
    "candiru-ip": "IP address of Candiru-attributed infrastructure. WEAKER THAN A "
                  "DOMAIN: these are mostly cloud-hosted addresses from a 2025 "
                  "report and are very likely reassigned to unrelated tenants by "
                  "now. Only meaningful if the hit is dated within the reporting "
                  "period.",
}

PATTERN_FOR_TYPE = {
    iocmod.TYPE_DOMAIN: "[domain-name:value = '{}']",
    iocmod.TYPE_IP: "[ipv4-addr:value = '{}']",
    iocmod.TYPE_SHA256: "[file:hashes.'SHA-256' = '{}']",
}


def _det_id(prefix: str, key: str) -> str:
    return "{}--{}".format(prefix, uuid.uuid5(NAMESPACE, prefix + ":" + key))


def build_bundle(ioc_set: iocmod.IocSet, now: datetime.datetime) -> dict:
    stamp = now.replace(microsecond=0).isoformat() + "Z"
    objects = []

    identity_id = _det_id("identity", "adint-shield")
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": stamp,
        "modified": stamp,
        "name": "adint-scan IOC set",
        "identity_class": "system",
        "description": "Curated from public reporting. NOT affiliated with, and "
                       "NOT endorsed by, The Citizen Lab or Confiant.",
    })

    malware_id = _det_id("malware", "candiru")
    objects.append({
        "type": "malware",
        "spec_version": "2.1",
        "id": malware_id,
        "created": stamp,
        "modified": stamp,
        "name": "Candiru",
        "is_family": True,
        "description": "Mercenary spyware from the Israeli vendor Candiru "
                       "(US-blacklisted since 2021), delivered zero-click through "
                       "Discover-Tech's Controlium ad platform in the AdFection "
                       "campaign.",
        "external_references": [{
            "source_name": "The Citizen Lab",
            "description": "Exposing AdFection (2026-10-15)",
            "url": CITIZENLAB_URL,
        }],
    })

    relationships = []
    for ind in ioc_set.indicators:
        pattern_tpl = PATTERN_FOR_TYPE.get(ind.type)
        if not pattern_tpl:
            continue
        ind_id = _det_id("indicator", ind.value)
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": stamp,
            "modified": stamp,
            "created_by_ref": identity_id,
            "name": ind.value,
            "description": TIER_DESCRIPTION.get(ind.tier, ind.tier),
            "indicator_types": ["malicious-activity"],
            "pattern": pattern_tpl.format(ind.value),
            "pattern_type": "stix",
            "valid_from": stamp,
            # Provenance travels with every indicator. A hit without a citation is
            # unusable, so sourcing is a label, not a footnote.
            "labels": ["tier:" + ind.tier, "confidence:" + ind.confidence],
            # STIX confidence is 0-100. 'secondary' means we read it in a summary
            # of the report rather than the report body: treat it as lower.
            "confidence": 85 if ind.confidence == "primary" else 50,
            "external_references": [{
                "source_name": "The Citizen Lab",
                "description": "Exposing AdFection (2026-10-15)",
                "url": CITIZENLAB_URL,
            }],
        })
        relationships.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": _det_id("relationship", "indicates:" + ind.value),
            "created": stamp,
            "modified": stamp,
            "relationship_type": "indicates",
            "source_ref": ind_id,
            "target_ref": malware_id,
        })

    objects.extend(relationships)
    return {
        "type": "bundle",
        "id": _det_id("bundle", "adfection"),
        "objects": objects,
    }


def main(argv=None) -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    p = argparse.ArgumentParser(description="Emit a STIX 2.1 bundle from the IOC file.")
    p.add_argument("--iocs", default=os.path.join(here, "..", "iocs",
                                                  "adfection_iocs.txt"))
    p.add_argument("--out", default=os.path.join(here, "..", "dist",
                                                 "adfection.stix.json"))
    args = p.parse_args(argv)

    ioc_set = iocmod.load(args.iocs)
    # Use the indicator set's committed 'as-of' date, not the wall clock, so the
    # bundle is byte-identical on every build (reproducible; no spurious churn).
    stamp = datetime.datetime.strptime(ioc_set.asof, "%Y-%m-%d") if ioc_set.asof \
        else datetime.datetime.utcnow()
    bundle = build_bundle(ioc_set, stamp)

    out = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(bundle, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    n_ind = sum(1 for o in bundle["objects"] if o["type"] == "indicator")
    print("wrote {}".format(out))
    print("  {} indicator objects, {} objects total".format(
        n_ind, len(bundle["objects"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
