"""ThreatConnect Job App"""

import json
from pathlib import Path

from tcex import TcEx
from tcex.exit import Exit, ExitCode

from job_app import JobApp  # Import default Job App Class (Required)


def load_potentially_undetectable_malware() -> list:
    """Load entities from tests/Potentially Undetectable Malware.json."""
    base_dir = Path(__file__).parent
    json_path = base_dir / "tests" / "Potentially Undetectable Malware.json"

    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    # The file is a top-level list of entities.
    return data


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
        self.tcex.session.external.base_url = 'https://feodotracker.abuse.ch'

    def run(self):
        """Run main App logic."""
        entities = load_potentially_undetectable_malware()

        for entity in entities:
            # Placeholder for future processing logic.
            pass

