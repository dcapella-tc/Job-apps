import argparse
import os
import re
import sys
from pathlib import Path

from .xray_client import XrayClient, XrayClientError
from .normalizer import normalize_cve_report
from .exporters import export_json, export_csv_sets


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Query JFrog Xray to see if a given CVE is present and list impacted artifacts/builds/repos."
    )
    parser.add_argument(
        "cve_id",
        help="CVE identifier (e.g. CVE-2024-12345)",
    )
    parser.add_argument(
        "--xray-url",
        default=os.getenv("XRAY_URL"),
        help="Base URL for JFrog Xray (env: XRAY_URL).",
    )
    parser.add_argument(
        "--access-token",
        default=os.getenv("JFROG_ACCESS_TOKEN"),
        help="JFrog access/bearer token (env: JFROG_ACCESS_TOKEN).",
    )
    parser.add_argument(
        "--username",
        default=os.getenv("JFROG_USERNAME"),
        help="JFrog username for basic auth (env: JFROG_USERNAME).",
    )
    parser.add_argument(
        "--password",
        default=os.getenv("JFROG_PASSWORD"),
        help="JFrog password/API key for basic auth (env: JFROG_PASSWORD).",
    )
    parser.add_argument(
        "--verify-ssl",
        default=os.getenv("XRAY_VERIFY_SSL", "true").lower() != "false",
        action=argparse.BooleanOptionalAction,
        help="Verify SSL certificates when talking to Xray (env: XRAY_VERIFY_SSL, default: true).",
    )
    parser.add_argument(
        "--output-dir",
        default="out",
        help="Directory to write output files into (default: ./out).",
    )
    parser.add_argument(
        "--json",
        dest="write_json",
        action="store_true",
        help="Write normalized results to a single JSON file.",
    )
    parser.add_argument(
        "--csv",
        dest="write_csv",
        action="store_true",
        help="Write artifacts/builds/repos CSVs.",
    )
    parser.add_argument(
        "--include-violations",
        action="store_true",
        help="Also query Xray violations API for the CVE and include in output when available.",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=int(os.getenv("XRAY_POLL_INTERVAL", "5")),
        help="Seconds between polling the report status (default: 5).",
    )
    parser.add_argument(
        "--poll-timeout",
        type=int,
        default=int(os.getenv("XRAY_POLL_TIMEOUT", "300")),
        help="Maximum seconds to wait for the report to complete (default: 300).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print additional diagnostic information.",
    )

    return parser.parse_args(argv)


def validate_cve(cve_id: str) -> None:
    if not CVE_PATTERN.match(cve_id):
        raise ValueError(f"Invalid CVE format: {cve_id!r}. Expected CVE-YYYY-NNNN.")


def build_client_from_args(args: argparse.Namespace) -> XrayClient:
    if not args.xray_url:
        raise ValueError("Xray base URL must be provided via --xray-url or XRAY_URL env var.")

    if not args.access_token and not (args.username and args.password):
        raise ValueError(
            "Authentication must be provided via --access-token (JFROG_ACCESS_TOKEN) or "
            "--username/--password (JFROG_USERNAME/JFROG_PASSWORD)."
        )

    return XrayClient(
        base_url=args.xray_url.rstrip("/"),
        access_token=args.access_token,
        username=args.username,
        password=args.password,
        verify_ssl=args.verify_ssl,
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        validate_cve(args.cve_id)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        client = build_client_from_args(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    out_dir = Path(args.output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.verbose:
        print(f"Creating CVE report for {args.cve_id} in {args.xray_url} ...")

    try:
        report = client.run_cve_report(
            cve_id=args.cve_id,
            poll_interval=args.poll_interval,
            timeout=args.poll_timeout,
            verbose=args.verbose,
        )
    except XrayClientError as exc:
        print(f"Error running CVE report: {exc}", file=sys.stderr)
        return 1

    if args.verbose:
        print("Normalizing report results ...")

    normalized = normalize_cve_report(
        cve_id=args.cve_id,
        report_json=report,
        client=client,
        include_violations=args.include_violations,
        verbose=args.verbose,
    )

    if not normalized.get("artifacts") and not normalized.get("builds") and not normalized.get("repos"):
        print(f"CVE {args.cve_id} does not appear to be present in the environment (no impacted items found).")
    else:
        print(
            f"CVE {args.cve_id} appears in the environment. "
            f"Artifacts: {len(normalized.get('artifacts', []))}, "
            f"builds: {len(normalized.get('builds', []))}, "
            f"repos: {len(normalized.get('repos', []))}."
        )

    json_path = None
    if args.write_json:
        json_path = out_dir / f"{args.cve_id.replace('-', '_').lower()}_report.json"
        export_json(normalized, json_path)
        if args.verbose:
            print(f"Wrote JSON report to {json_path}")

    csv_paths = {}
    if args.write_csv:
        csv_paths = export_csv_sets(normalized, out_dir)
        if args.verbose:
            for name, path in csv_paths.items():
                print(f"Wrote {name} CSV to {path}")

    if not args.write_json and not args.write_csv:
        # Default to JSON if no explicit output choice was made.
        json_path = out_dir / f"{args.cve_id.replace('-', '_').lower()}_report.json"
        export_json(normalized, json_path)
        if args.verbose:
            print(f"No --json/--csv specified; defaulted to JSON at {json_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

