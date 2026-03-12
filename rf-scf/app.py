"""ThreatConnect Job App"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tcex import TcEx
from tcex.exit import Exit, ExitCode

from job_app import JobApp  # Import default Job App Class (Required)


INVALID_TIMESTAMP_MESSAGE = (
    'Please enter a valid timestamp in ISO 8601 format with the trailing Z. '
    'Example: "2017-05-03T14:38:02Z"'
)


def normalize_timestamp_to_iso8601_utc(value: Any) -> str:
    """Normalize a timestamp to an ISO 8601 UTC string with trailing Z.

    Accepts:
    - An ISO 8601 string with trailing Z (e.g. "2017-05-03T14:38:02Z").
    - A numeric value representing milliseconds since Unix epoch (int, float, or digit-only string).

    Returns:
        A normalized ISO 8601 UTC string with trailing Z.

    Raises:
        ValueError: If the input cannot be interpreted as a valid timestamp.
    """
    if value is None:
        raise ValueError(INVALID_TIMESTAMP_MESSAGE)

    # Handle strings (either digit-only milliseconds or ISO 8601 Z format).
    if isinstance(value, str):
        v = value.strip()
        if not v:
            raise ValueError(INVALID_TIMESTAMP_MESSAGE)

        if v.isdigit():
            try:
                ms = int(v)
            except (TypeError, ValueError):
                raise ValueError(INVALID_TIMESTAMP_MESSAGE)
            return _ms_to_iso8601_utc(ms)

        # Attempt to parse strict ISO 8601 with trailing Z.
        try:
            dt = datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            raise ValueError(INVALID_TIMESTAMP_MESSAGE)
        # Ensure the result is canonicalized and explicitly UTC with Z.
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Handle numeric milliseconds.
    if isinstance(value, (int, float)):
        try:
            ms = int(value)
        except (TypeError, ValueError):
            raise ValueError(INVALID_TIMESTAMP_MESSAGE)
        return _ms_to_iso8601_utc(ms)

    raise ValueError(INVALID_TIMESTAMP_MESSAGE)


def _ms_to_iso8601_utc(ms: int) -> str:
    """Convert milliseconds since epoch to ISO 8601 UTC string with trailing Z."""
    try:
        dt = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        raise ValueError(INVALID_TIMESTAMP_MESSAGE)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


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
        self.tcex.log.info(
            'App.setup: configured external base URL to %s',
            self.tcex.session.external.base_url,
        )

    def run(self):
        """Run main App logic."""
        entities = load_potentially_undetectable_malware()
        total_entities = len(entities)
        candidate_entities = 0
        indicators_added = 0

        self.tcex.log.info(
            'App.run: starting processing for owner %s with %d entities.',
            self.in_.tc_owner,
            total_entities,
        )

        for entity in entities:
            # Placeholder for future processing logic.
            if entity.get('algorithm', '').lower() in ['sha-256', 'sha-1', 'md5']:
                candidate_entities += 1

                indicator = {
                    "xid": self.batch.generate_xid([self.in_.tc_owner, 'file', entity["hash"]]),
                    "type": "file",
                    "summary": entity["hash"],
                }
                if entity.get('lastSeen',''):
                    try:
                        last_seen_iso = normalize_timestamp_to_iso8601_utc(entity.get("lastSeen"))
                    except ValueError as ex:
                        self.tcex.log.error(
                            'App.run: invalid lastSeen for hash %s: %r (%s)',
                            entity.get("hash"),
                            entity.get("lastSeen"),
                            ex,
                        )
                        raise
                    indicator["attribute"] = [{
                        "type": "Last Seen",
                        "value": last_seen_iso,
                    }]
                self.batch.add_indicator(indicator)
                indicators_added += 1
        self.tcex.log.info(
            'App.run: finished loop. total_entities=%d, candidate_entities=%d, indicators_added=%d',
            total_entities,
            candidate_entities,
            indicators_added,
        )
        self.batch.submit_all()
        self.tcex.log.info('App.run: batch submission complete.')

        