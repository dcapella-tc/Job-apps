"""ThreatConnect Job App"""

from typing import List, Optional

from tcex import TcEx
from tcex.exit import ExitCode

from job_app import JobApp  # Import default Job App Class (Required)


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
        with self.tcex.session.external as s:
            r = s.get('/pulses/subscribed', params={'page': 1})
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
