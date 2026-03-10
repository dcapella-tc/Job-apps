"""ThreatConnect Job App"""

import re
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from tcex import TcEx
from tcex.exit import ExitCode

from job_app import JobApp  # Import default Job App Class (Required)

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

    def run(self):
        """Run main App logic."""
        last_run_raw = (self.in_.last_run or '').strip() or '30 Days Ago'
        try:
            last_run_dt = parse_last_run(last_run_raw)
        except ValueError as e:
            self.tcex.exit.exit(ExitCode.FAILURE, str(e))
            return
        modified_since_iso = last_run_dt.isoformat().replace('+00:00', 'Z')

        with self.tcex.session.external as s:
            r = s.get(
                '/pulses/subscribed',
                params={'page': 1, 'modified_since': modified_since_iso},
            )
            if not r.ok:
                self.tcex.exit.exit(ExitCode.FAILURE, 'Failed to download data.')
                return

            self.tcex.log.info('Data downloaded successfully.')

            try:
                payload = r.json()
            except Exception:  # pragma: no cover - defensive programming
                self.tcex.exit.exit(ExitCode.FAILURE, 'Failed to parse response JSON.')
                return

            pulse_ids = extract_pulse_ids(payload)
            next_token = extract_next_token(payload)

            self.tcex.log.info(f'Extracted {len(pulse_ids)} pulses.')
            if next_token:
                self.tcex.log.info(f'Next page token: {next_token}')
