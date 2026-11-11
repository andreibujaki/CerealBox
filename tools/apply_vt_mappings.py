#!/usr/bin/env python3
"""Apply verified SHA1<->SHA256 mappings into cereal-iocs.json and hash-map.csv."""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IOC = ROOT / "iocs" / "cereal-iocs.json"
CSV = ROOT / "iocs" / "hash-map.csv"

# VirusTotal UI verified
VERIFIED = {
    "4A3C263977417FB6977B0E598C9E3BC5924F390C": "13FE1EB9B182B076A815F84D34B66365809D0CFF32DF6F5B85AA7EF4DEEE98E0",
    "7742C6B0AAF114335CEF7EBAB11290CB18A0B8B3": "241AAC14756A0F29EDD084B858623DB259D59C77EA44889DE93431C42FF10036",
    "AFE448DD95494CD14438F04F0C5F6B384664A3B7": "D3B6065EB001D169421FCD146F64B087055DADEBD973D8D69AE2BF97FBF288E2",
    "4A65040646E354303F067D47AA1C953D467F65CB": "6119D25AE51D04264384F5D738C104E42596B0774609666B357A43608A48404C",
    "D1E17520A2435EDCDCC47F582381416FBDF75F94": "41164EB06ADC72B187EDAF90D73CA73BE729D4EBFDECF57D7398561136941651",
}

# Extra verified pairs discovered later (populated by resolve_batch)
EXTRA = ROOT / "iocs" / "vt-verified-extra.json"
if EXTRA.exists():
    extra = json.loads(EXTRA.read_text(encoding="utf-8"))
    for sha1, sha256 in extra.items():
        VERIFIED[sha1.upper()] = sha256.upper()


def main() -> None:
    doc = json.loads(IOC.read_text(encoding="utf-8-sig"))
    doc["source"] = (
        "ESET white paper: Exchange for breakfast - Turla Cereal tricks (2026-11-10); "
        "SHA-256 corpus from github.com/eset/malware-ioc turla/samples.sha256 (Cereal batch); "
        "SHA-1/SHA-256 pairs verified via VirusTotal UI where noted"
    )
    doc["updated"] = "2026-11-11"

    verified_sha256 = set(VERIFIED.values())
    for f in doc["files"]:
        s1 = f["sha1"].upper()
        if s1 in VERIFIED:
            s256 = VERIFIED[s1]
            f["sha256"] = s256
            f["sha256_verified"] = "virustotal"
            f["vt"] = f"https://www.virustotal.com/gui/file/{s256.lower()}"
            f["hybrid_analysis"] = f"https://hybrid-analysis.com/sample/{s256.lower()}"

    # Keep hunt set free of already-verified hashes
    hunt = []
    seen = set()
    for item in doc.get("additional_sha256_hunt_set") or []:
        h = (item.get("sha256") or "").upper()
        if not h or h in verified_sha256 or h in seen:
            continue
        seen.add(h)
        hunt.append(item)
    doc["additional_sha256_hunt_set"] = hunt

    IOC.write_text(json.dumps(doc, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    rows = []
    for f in doc["files"]:
        rows.append(
            {
                "Role": f.get("role"),
                "Filename": f.get("filename"),
                "SHA1": f.get("sha1"),
                "SHA256": f.get("sha256"),
                "Verified": f.get("sha256_verified"),
                "ESET": f.get("eset"),
                "VT": f.get("vt"),
                "HA": f.get("hybrid_analysis"),
            }
        )
    for a in hunt:
        h = a["sha256"]
        rows.append(
            {
                "Role": "ESET-batch-hunt",
                "Filename": None,
                "SHA1": None,
                "SHA256": h,
                "Verified": "hunt-set",
                "ESET": None,
                "VT": f"https://www.virustotal.com/gui/file/{h.lower()}",
                "HA": f"https://hybrid-analysis.com/sample/{h.lower()}",
            }
        )

    with CSV.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["Role", "Filename", "SHA1", "SHA256", "Verified", "ESET", "VT", "HA"],
        )
        w.writeheader()
        w.writerows(rows)

    paired = sum(1 for f in doc["files"] if f.get("sha256"))
    print(f"paired {paired}/{len(doc['files'])}; hunt_set {len(hunt)}; wrote {CSV}")


if __name__ == "__main__":
    main()
