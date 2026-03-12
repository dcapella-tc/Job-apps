"""ThreatConnect Job App"""

import json
from pathlib import Path
from typing import Iterable, List, Mapping

from tcex import TcEx
from tcex.exit import Exit, ExitCode

from job_app import JobApp  # Import default Job App Class (Required)

ALLOWED_ALGORITHMS = {"MD5", "SHA-1", "SHA-256"}


def load_potentially_undetectable_malware() -> list:
    """Load entities from tests/Potentially Undetectable Malware.json."""
    base_dir = Path(__file__).parent
    json_path = base_dir / "tests" / "Potentially Undetectable Malware.json"

    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    # The file is a top-level list of entities.
    return data


def filter_entities_by_algorithm(
    entities: Iterable[object], allowed_algorithms: Iterable[str] | None = None
) -> List[Mapping[str, object]]:
    """Filter entities to those whose algorithm is in the allowed set."""
    allowed = set(allowed_algorithms) if allowed_algorithms is not None else ALLOWED_ALGORITHMS

    filtered: List[Mapping[str, object]] = []
    for entity in entities:
        if not isinstance(entity, dict):
            continue

        algorithm = entity.get("algorithm")
        if algorithm not in allowed:
            continue

        filtered.append(entity)

    return filtered


def process_malware_entities() -> List[Mapping[str, object]]:
    """Load entities and filter them by allowed algorithms, no-op on each for now."""
    entities = load_potentially_undetectable_malware()
    filtered_entities = filter_entities_by_algorithm(entities)

    for entity in filtered_entities:
        # Placeholder for future processing logic.
        pass

    return filtered_entities


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
        _ = process_malware_entities()

