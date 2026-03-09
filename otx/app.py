"""ThreatConnect Job App"""

from tcex import TcEx
from tcex.exit import ExitCode

from job_app import JobApp  # Import default Job App Class (Required)


class App(JobApp):
    """Job App"""

    def __init__(self, _tcex: TcEx):
        """Initialize class properties."""
        super().__init__(_tcex)

    def setup(self):
        """Perform prep/setup logic."""
        # Configure the external session for OTX.
        self.tcex.session.external.base_url = 'https://otx.alienvault.com/api/v1'
        self.tcex.session.external.headers.update(
            {
                'X-OTX-API-KEY': self.in_.otx_api_key,
                'Accept': 'application/json',
            }
        )

    def run(self):
        """Run main App logic."""
        with self.tcex.session.external as s:
            # Simple authenticated OTX connection test.
            r = s.get('/users/me')

            if r.ok:
                user_data = r.json()
                username = user_data.get('username', 'unknown')
                self.log.info(f'Successfully connected to OTX as {username}.')
                self.exit_message = f'Successfully connected to OTX as {username}.'
                self.tcex.exit.exit(ExitCode.SUCCESS, self.exit_message)

            error_text = r.text[:500] if r.text else 'No response body returned.'
            self.log.error(f'OTX connection failed ({r.status_code}): {error_text}')
            self.tcex.exit.exit(
                ExitCode.FAILURE,
                f'OTX connection failed with status {r.status_code}.',
            )
