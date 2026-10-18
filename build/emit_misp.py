#!/usr/bin/env python3
"""Emit a MISP event (JSON) from the curated IOC file.

Why MISP: the victims in this campaign were institutions — the ICC, the IAEA,
Al Jazeera. Institutions deploy by policy, not by 400 people installing a browser
extension (DESIGN.md). One newsroom admin importing one MISP event protects
everyone behind that gateway.

Usage:
    python emit_misp.py [--iocs ../iocs/adfection_iocs.txt] [--out ../dist/adfection.misp.json]

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

NAMESPACE = uuid.UUID("6f0b4a2e-5d1c-4f3b-9a7e-adf3c70f1001")

CITIZENLAB_URL = ("https://citizenlab.ca/research/"
                  "how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/")

# MISP attribute type per inferred indicator type.
MISP_TYPE = {
    iocmod.TYPE_DOMAIN: "domain",
    iocmod.TYPE_IP: "ip-dst",
    iocmod.TYPE_SHA256: "sha256",
}

# Which MISP object-relation category each tier belongs in.
MISP_CATEGORY = {
    "cc": "Network activity",
    "validator": "Network activity",
    "delivery": "Network activity",
    "historical": "Network activity",
    "sample": "Payload delivery",
    "candiru": "Network activity",
    "candiru-ip": "Network activity",
}

# to_ids says "this is safe to turn into a detection rule". Delivery-tier ad
# infrastructure is deliberately NOT to_ids: an ad impression is not proof of
# infection, and shipping it as a detection signature would bury analysts in
# false positives and teach them to ignore the feed (D4, precision over coverage).
# `candiru` domains are included: they are attributed attack infrastructure with
# distinctive names, so a detection rule on them is defensible.
# `candiru-ip` is deliberately EXCLUDED. Cloud IPs from a 2025 report are very
# likely reassigned, and shipping 109 of them as detection signatures would
# generate alerts on innocent tenants and teach analysts to mute the feed.
TO_IDS_TIERS = {"cc", "validator", "sample", "candiru"}


def build_event(ioc_set: iocmod.IocSet, now: datetime.datetime) -> dict:
    date = now.strftime("%Y-%m-%d")
    stamp = str(int(now.timestamp()))

    attributes = []
    for ind in ioc_set.indicators:
        misp_type = MISP_TYPE.get(ind.type)
        if not misp_type:
            continue
        attributes.append({
            "uuid": str(uuid.uuid5(NAMESPACE, "misp-attr:" + ind.value)),
            "type": misp_type,
            "category": MISP_CATEGORY.get(ind.tier, "Network activity"),
            "value": ind.value,
            "to_ids": ind.tier in TO_IDS_TIERS,
            "timestamp": stamp,
            "comment": "tier={} confidence={} (Citizen Lab, Exposing AdFection, "
                       "2026-10-15)".format(ind.tier, ind.confidence),
            "Tag": [
                {"name": 'adint:tier="{}"'.format(ind.tier)},
                {"name": 'adint:confidence="{}"'.format(ind.confidence)},
            ],
        })

    return {
        "Event": {
            "uuid": str(uuid.uuid5(NAMESPACE, "misp-event:adfection")),
            "info": "AdFection / Discover-Tech / Candiru — zero-click spyware "
                    "delivered through real-time ad bidding",
            "date": date,
            "timestamp": stamp,
            # 2 = "Possibly false" is wrong here; 1 = Confirmed for primary-sourced
            # indicators read out of the report body.
            "analysis": "2",
            "threat_level_id": "1",
            "published": False,
            "Attribute": attributes,
            "Tag": [
                {"name": 'type:OSINT'},
                {"name": 'misp-galaxy:mercenary-spyware="Candiru"'},
                {"name": 'adint:campaign="AdFection"'},
            ],
            "Object": [],
            "extra": {
                "source": "The Citizen Lab, 'Exposing AdFection' (2026-10-15) and "
                          "Confiant, 'ADINT' (2026-10-15).",
                "source_url": CITIZENLAB_URL,
                "attribution_note": "Neither The Citizen Lab nor Confiant is "
                                    "affiliated with this tool or endorses it. "
                                    "Their report is the source; the tool is not "
                                    "theirs.",
                "caveat": "An ad impression from the delivery-tier infrastructure "
                          "is NOT proof of infection. The validator server decided "
                          "per device whether to proceed. A hit means investigate.",
            },
        }
    }


def main(argv=None) -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    p = argparse.ArgumentParser(description="Emit a MISP event from the IOC file.")
    p.add_argument("--iocs", default=os.path.join(here, "..", "iocs",
                                                  "adfection_iocs.txt"))
    p.add_argument("--out", default=os.path.join(here, "..", "dist",
                                                 "adfection.misp.json"))
    args = p.parse_args(argv)

    ioc_set = iocmod.load(args.iocs)
    # Deterministic: use the committed 'as-of' date, not the wall clock, so the
    # event is byte-identical on every build (reproducible; no spurious churn).
    stamp = datetime.datetime.strptime(ioc_set.asof, "%Y-%m-%d") if ioc_set.asof \
        else datetime.datetime.utcnow()
    event = build_event(ioc_set, stamp)

    out = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(event, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    attrs = event["Event"]["Attribute"]
    to_ids = sum(1 for a in attrs if a["to_ids"])
    print("wrote {}".format(out))
    print("  {} attributes, {} marked to_ids (detection-safe tiers only)".format(
        len(attrs), to_ids))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
