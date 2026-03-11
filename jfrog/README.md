# JFrog Xray CVE Lookup Tool

This is a small Python CLI tool for querying an on-prem JFrog Xray instance (with SBOM disabled) to answer:

- Whether a given `CVE-YYYY-NNNN` is present in your environment.
- Which internal artifacts, builds, and repositories are impacted.

It uses Xray's **report-based** CVE search APIs:

- `POST /xray/api/v1/reports/cveSearch`
- `POST /xray/api/v1/reports/cveSearch/{id}`
- `POST /xray/api/v1/component/searchByCves`
- (Optional) `POST /xray/api/v1/violations`

## Quick start

1. Install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Set environment variables for your Xray instance (examples):

```bash
export XRAY_URL="https://xray.mycorp.internal"
export JFROG_ACCESS_TOKEN="xxxxxxxx"
# or:
# export JFROG_USERNAME="user"
# export JFROG_PASSWORD="pass"
```

3. Run a CVE lookup:

```bash
python -m cve_tool CVE-2024-12345 --output-dir ./out --json --csv
```

The tool will:

- Create and poll a CVE search report in Xray.
- Collect impacted artifacts, builds, and repos.
- Export normalized JSON and/or CSV data into the output directory.
