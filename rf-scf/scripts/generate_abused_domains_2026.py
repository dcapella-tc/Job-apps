"""Generate a 2026-only Potentially Abused Domains file and save to tests/.

Run from the project root (rf-scf):
  python scripts/generate_abused_domains_2026.py
  python scripts/generate_abused_domains_2026.py --count-only  # for testing: print count of 2026 records only
"""
import argparse
import json
import sys
from pathlib import Path

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from app import ABUSED_DOMAINS_YEAR, iter_potentially_abused_domains_by_year


def main() -> None:
    parser = argparse.ArgumentParser(description="Write 2026-only Potentially Abused Domains to tests/.")
    parser.add_argument(
        "--count-only",
        action="store_true",
        help="Only stream and print the count of 2026 records; do not write the JSON file.",
    )
    args = parser.parse_args()

    records = list(iter_potentially_abused_domains_by_year(year=ABUSED_DOMAINS_YEAR))
    count = len(records)

    if args.count_only:
        print(f"Records with timestamp in {ABUSED_DOMAINS_YEAR}: {count}")
        return

    out_path = _project_root / "tests" / "Potentially Abused Domains_2026.json"
    payload = {"count": count, "results": records}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"Wrote {count} records to tests/Potentially Abused Domains_2026.json")


if __name__ == "__main__":
    main()
