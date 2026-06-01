#!/usr/bin/env python3
"""Fetch and cache CVE data for training sample generation.

Sources:
  1. CISA KEV (Known Exploited Vulnerabilities) — ~1100 actively exploited CVEs
  2. NVD GitHub mirror (optional, large) — full CVE database

Usage:
    python fetch_cves.py                  # fetch CISA KEV only (recommended)
    python fetch_cves.py --nvd-years 2025 2024   # also fetch NVD yearly feeds
"""

import argparse
import json
from pathlib import Path
from urllib.request import Request, urlopen

CACHE_DIR = Path(__file__).parent.parent / "cve_cache"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def download(url: str, dest: Path, headers: dict | None = None) -> Path:
    if dest.exists():
        print(f"  Cached: {dest.name}")
        return dest
    print(f"  Downloading {dest.name}...")
    req = Request(url, headers=headers or {})
    with urlopen(req, timeout=120) as resp:
        dest.write_bytes(resp.read())
    print(f"  Saved: {dest}")
    return dest


def fetch_kev() -> Path:
    """Fetch CISA Known Exploited Vulnerabilities catalog."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return download(KEV_URL, CACHE_DIR / "kev.json")


def parse_kev(path: Path) -> list[dict]:
    """Parse KEV into simplified records."""
    data = json.loads(path.read_text())
    vulns = data.get("vulnerabilities", [])
    results = []
    for v in vulns:
        results.append(
            {
                "cve_id": v.get("cveID", ""),
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "name": v.get("vulnerabilityName", ""),
                "description": v.get("shortDescription", ""),
                "date_added": v.get("dateAdded", ""),
                "due_date": v.get("dueDate", ""),
                "known_ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                "notes": v.get("notes", ""),
            }
        )
    return results


def kev_stats(records: list[dict]):
    """Print summary stats."""
    print(f"\n  Total KEV entries: {len(records)}")
    vendors = {}
    for r in records:
        vendors[r["vendor"]] = vendors.get(r["vendor"], 0) + 1
    top = sorted(vendors.items(), key=lambda x: -x[1])[:10]
    print("  Top vendors:")
    for vendor, count in top:
        print(f"    {vendor}: {count}")
    ransomware = sum(1 for r in records if r["known_ransomware"] == "Known")
    print(f"  Known ransomware use: {ransomware}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--nvd-years",
        nargs="*",
        type=int,
        default=[],
        help="Also fetch NVD yearly feeds (large downloads)",
    )
    parser.add_argument("--refresh", action="store_true", help="Re-download even if cached")
    args = parser.parse_args()

    if args.refresh:
        for f in CACHE_DIR.glob("*.json"):
            f.unlink()

    print("Fetching CISA KEV...")
    kev_path = fetch_kev()
    records = parse_kev(kev_path)
    kev_stats(records)

    # Write parsed records for easy consumption
    parsed_path = CACHE_DIR / "kev_parsed.jsonl"
    with open(parsed_path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"  Parsed records: {parsed_path}")

    if args.nvd_years:
        print("\nNote: NVD JSON feeds were deprecated in 2023.")
        print(
            "For full NVD data, clone: git clone https://github.com/fkie-cad/nvd-json-data-feeds.git"
        )
        print("Or use the NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0/")

    print(f"\nCVE cache ready at {CACHE_DIR}/")


if __name__ == "__main__":
    main()
