"""ThreatConnect Job App"""

import re
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Union
from uuid import uuid5, NAMESPACE_URL

from tcex import TcEx
from tcex.exit import ExitCode

from job_app import JobApp  # Import default Job App Class (Required)
from naics import naics_tags_for_keyword

# Match "N Days Ago" or "N Day Ago" (case-insensitive)
_DAYS_AGO_RE = re.compile(r'^\s*(\d+)\s+days?\s+ago\s*$', re.IGNORECASE)


def parse_last_run(value: str) -> datetime:
    """Convert last_run string to a UTC datetime.

    Accepts:
        - "N Days Ago" / "N Day Ago" (case-insensitive): relative to now (UTC).
        - ISO-like date strings (e.g. 2026-03-10, 2026-03-10T12:00:00Z): parsed and returned as UTC.

    Returns:
        Timezone-aware datetime in UTC.

    Raises:
        ValueError: If value is empty or does not match the expected formats.
    """
    if not value or not value.strip():
        raise ValueError(
            'last_run must be a non-empty string: either "N Days Ago" (e.g. "7 Days Ago") '
            'or an ISO date/time (e.g. 2026-03-10 or 2026-03-10T12:00:00Z).'
        )
    raw = value.strip()
    m = _DAYS_AGO_RE.match(raw)
    if m:
        n = int(m.group(1))
        return datetime.now(timezone.utc) - timedelta(days=n)
    # Treat as ISO-like
    iso = raw.rstrip('Zz').rstrip()
    if raw.upper().endswith('Z'):
        iso += '+00:00'
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError as e:
        raise ValueError(
            'last_run must be "N Days Ago" (e.g. "7 Days Ago") or an ISO date/time '
            '(e.g. 2026-03-10 or 2026-03-10T12:00:00Z).'
        ) from e
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def extract_pulse_ids(pulses_json: dict) -> List[str]:
    """Return a list of pulse IDs from an OTX response payload."""
    results = pulses_json.get('results', []) or []
    pulse_ids: List[str] = []
    for item in results:
        if 'id' in item:
            pulse_ids.append(str(item['id']))
    return pulse_ids


def extract_next_token(pulses_json: dict) -> Optional[str]:
    """Return the next page token (URL) from an OTX response payload."""
    next_token = pulses_json.get('next')
    return str(next_token) if next_token is not None else None

def list_to_html_table(
    rows: Union[List[str], List[List[str]]],
    header: Union[str, List[str]],
) -> str:
    """Build an HTML table. If header is a list, table has multiple columns; rows must be list of row lists."""
    if isinstance(header, list):
        header_html = "".join(f"<th>{h}</th>" for h in header)
        header_html = f"<tr>{header_html}</tr>"
        rows_html = "".join(
            "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
            for row in rows
        )
    else:
        header_html = f"<tr><th>{header}</th></tr>"
        rows_html = "".join(f"<tr><td>{row}</td></tr>" for row in rows)
    return f"<table>{header_html}{rows_html}</table>"

class App(JobApp):
    """Job App"""

    def __init__(self, _tcex: TcEx):
        """Initialize class properties."""
        super().__init__(_tcex)

        # properties
        self.batch = self.tcex.api.tc.v2.batch(self.in_.tc_owner)

    def setup(self):
        """Perform prep/setup logic."""
        # setting the base url allow for subsequent API call
        # to be made by only providing the API endpoint/path.
        self.tcex.session.external.base_url = 'https://otx.alienvault.com/api/v1'
        self.tcex.session.external.headers.update(
            {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'X-OTX-API-KEY': self.in_.otx_api_key,
            }
        )

    def _fetch_pulses_page(self, session, url: str, params: Optional[dict] = None) -> Optional[dict]:
        """Fetch a single pulses page and return the parsed JSON payload."""
        r = session.get(url, params=params)
        if not r.ok:
            self.tcex.exit.exit(ExitCode.FAILURE, 'Failed to download data.')
            return None

        try:
            payload = r.json()
        except Exception:  # pragma: no cover - defensive programming
            self.tcex.exit.exit(ExitCode.FAILURE, 'Failed to parse response JSON.')
            return None

        return payload

    def _fetch_pulse_detail(self, session, pulse_id: str) -> Optional[dict]:
        """Fetch details for a single pulse ID."""
        url = f'/pulses/{pulse_id}'
        r = session.get(url)
        if not r.ok:
            self.tcex.log.error(f'Response Code: {r.status_code}\nResponse Text: {r.text}')
            self.tcex.exit.exit(ExitCode.FAILURE, f'Failed to download details for pulse {pulse_id}.')
            return None

        try:
            payload = r.json()
        except Exception:  # pragma: no cover - defensive programming
            self.tcex.log.error(f'Failed to parse details JSON for pulse {pulse_id}.')
            return None

        return payload

    def _extract_pulse_detail_fields(self, detail: dict) -> dict:
        """Extract fields from a pulse detail payload.

        This helper pulls values into individual variables so they can be
        easily adjusted or remapped later.
        """
        # Core metadata
        pulse_id = detail.get('id')
        name = detail.get('name')
        xid = str(uuid5(NAMESPACE_URL, f'{self.in_.tc_owner}:Report:{name}'))
        description = detail.get('description')
        author_name = detail.get('author_name')
        modified = detail.get('modified')
        created = detail.get('created')
        tlp = detail.get('TLP')

        # High-level lists
        tags = detail.get('tags', [])
        references = detail.get('references', [])
        attack_ids = detail.get('attack_ids', [])
        targeted_countries = detail.get('targeted_countries', [])
        malware_families = detail.get('malware_families', [])
        industries = detail.get('industries', [])

        # Author object
        author = detail.get('author') or {}
        author_username = author.get('username')
        author_id = author.get('id')
        author_avatar_url = author.get('avatar_url')

        # Raw indicators
        indicators = detail.get('indicators', [])

        # Derived indicator groupings
        domain_indicators = [
            i.get('indicator')
            for i in indicators
            if (i.get('type') or '').lower() == 'domain'
        ]
        filehash_md5_indicators = [
            i.get('indicator')
            for i in indicators
            if i.get('type') == 'FileHash-MD5'
        ]
        filehash_sha256_indicators = [
            i.get('indicator')
            for i in indicators
            if i.get('type') == 'FileHash-SHA256'
        ]

        all_tags: set[str] = set()
        all_tags.update(tags)
        all_tags.update(attack_ids)
        all_tags.update(targeted_countries)
        all_tags.update(malware_families)
        all_tags.update(naics_tags_for_keyword(industries))

        attributes = [
            {"type": "Description", "value": description, "displayed": True},
            {"type": "Author", "value": author_name},
            {"type": "External Date Last Modified", "value": modified},
            {"type": "External Date Created", "value": created},
            {"type": "TLP", "value": tlp},
            {"type": "Tags", "value": all_tags},
            {"type": "References", "value": list_to_html_table(references, "Reference")},
            {"type": "Author Username", "value": author_username},
            {"type": "Author ID", "value": author_id},
            {"type": "Author Avatar URL", "value": author_avatar_url},
            {"type": "External ID", "value": pulse_id},
            {"type": "External Reference", "value": references}
        ]
        for country in targeted_countries:
            attributes.append({"type": "GeoCountry Targeted", "value": country})

        group = {
            'xid': xid,
            'name': name,
            'description': description,
            'tags': all_tags
        }

        # Return structure is intentionally simple; adjust keys as needed.
        return {
            'id': pulse_id,
            'name': name,
            'description': description,
            'author_name': author_name,
            'modified': modified,
            'created': created,
            'tlp': tlp,
            'tags': tags,
            'references': references,
            'attack_ids': attack_ids,
            'targeted_countries': targeted_countries,
            'malware_families': malware_families,
            'industries': industries,
            'author_username': author_username,
            'author_id': author_id,
            'author_avatar_url': author_avatar_url,
            'domains': domain_indicators,
            'filehash_md5': filehash_md5_indicators,
            'filehash_sha256': filehash_sha256_indicators,
            'indicators_raw': indicators,
        }

    def run(self):
        """Run main App logic."""
        last_run_raw = (self.in_.last_run or '').strip() or '30 Days Ago'
        try:
            last_run_dt = parse_last_run(last_run_raw)
        except ValueError as e:
            self.tcex.exit.exit(ExitCode.FAILURE, str(e))
            return
        modified_since_iso = last_run_dt.isoformat().replace('+00:00', 'Z')

        all_pulse_ids: List[str] = []
        next_url: Optional[str] = '/pulses/subscribed'
        params: Optional[dict] = {'page': 1, 'modified_since': modified_since_iso}

        with self.tcex.session.external as s:
            first_page = True
            while next_url:
                # If next_url is absolute, rely on it entirely; otherwise treat as relative path.
                if next_url.startswith('http'):
                    url = next_url
                    page_params = None
                else:
                    url = next_url
                    page_params = params

                payload = self._fetch_pulses_page(s, url, page_params)
                if payload is None:
                    return

                if first_page:
                    self.tcex.log.info('Data downloaded successfully.')
                    first_page = False

                page_pulse_ids = extract_pulse_ids(payload)
                all_pulse_ids.extend(page_pulse_ids)

                next_url = extract_next_token(payload)
                if next_url:
                    self.tcex.log.info(f'Next page token: {next_url}')

                # After the first request, rely on the next URL for pagination.
                params = None

                # DEBUG: For testing purposes, break after the first page
                break

            self.tcex.log.info(f'Extracted {len(all_pulse_ids)} pulses across all pages.')

            pulse_details: List[dict] = []
            for pulse_id in all_pulse_ids:
                detail = self._fetch_pulse_detail(s, pulse_id)
                if detail is not None:
                    fields = self._extract_pulse_detail_fields(detail)
                    pulse_details.append(fields)
                
                # DEBUG: For testing purposes, break after the first pulse
                break


            if pulse_details:
                self.tcex.log.debug(f'First pulse detail payload: {pulse_details[0]!r}')
            self.tcex.log.info(f'Fetched details for {len(pulse_details)} pulses.')
