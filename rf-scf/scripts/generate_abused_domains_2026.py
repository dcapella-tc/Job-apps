"""Generate a 2026-only Potentially Abused Domains file and save to tests/.

Uses two-pass streaming so memory stays bounded; use --limit when 2026 is large.
Run from the project root (rf-scf):
  python scripts/generate_abused_domains_2026.py
  python scripts/generate_abused_domains_2026.py --count-only
  python scripts/generate_abused_domains_2026.py --limit 100000
  python scripts/generate_abused_domains_2026.py --pretty
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
    parser = argparse.ArgumentParser(
        description="Write 2026-only Potentially Abused Domains to tests/."
    )
    parser.add_argument(
        "--count-only",
        action="store_true",
        help="Only stream and print the count of 2026 records; do not write the JSON file.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Max number of 2026 records to write (default: no limit). Helps avoid huge files and OOM.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON with indent (default: compact). Best used with --limit for large outputs.",
    )
    args = parser.parse_args()

    limit = args.limit

    if args.count_only:
        count = sum(
            1
            for _ in iter_potentially_abused_domains_by_year(
                year=ABUSED_DOMAINS_YEAR, max_records=limit
            )
        )
        print(f"Records with timestamp in {ABUSED_DOMAINS_YEAR}: {count}")
        return

    # First pass: count (with optional limit)
    count = sum(
        1
        for _ in iter_potentially_abused_domains_by_year(
            year=ABUSED_DOMAINS_YEAR, max_records=limit
        )
    )

    # Second pass: stream-write JSON without holding all records in memory
    out_path = _project_root / "tests" / "Potentially Abused Domains_2026.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        f.write('{"count": ')
        f.write(str(count))
        f.write(', "results": [')
        first = True
        for record in iter_potentially_abused_domains_by_year(
            year=ABUSED_DOMAINS_YEAR, max_records=limit
        ):
            if not first:
                f.write(",")
            f.write(json.dumps(record, ensure_ascii=False))
            first = False
        f.write("]}")
    print(f"Wrote {count} records to tests/Potentially Abused Domains_2026.json")

    if args.pretty:
        with out_path.open("r", encoding="utf-8") as f:
            payload = json.load(f)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print("Reformatted with indent (--pretty).")


if __name__ == "__main__":
    main()
