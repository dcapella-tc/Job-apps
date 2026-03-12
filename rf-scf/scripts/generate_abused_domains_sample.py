"""Generate a sample of Potentially Abused Domains and save to tests/.

Run from the project root (rf-scf): python scripts/generate_abused_domains_sample.py
Or with PYTHONPATH: PYTHONPATH=. python scripts/generate_abused_domains_sample.py
"""
import json
import sys
from pathlib import Path

# Ensure app is importable when run from scripts/ or project root
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from app import load_potentially_abused_domains_sample


def main() -> None:
    sample = load_potentially_abused_domains_sample(sample_size=500)
    out_path = _project_root / "tests" / "Potentially Abused Domains_sample.json"
    payload = {"count": len(sample), "results": sample}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"Wrote {len(sample)} records to tests/Potentially Abused Domains_sample.json")


if __name__ == "__main__":
    main()
