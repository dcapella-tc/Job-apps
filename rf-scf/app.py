"""ThreatConnect Job App"""

import gzip
import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import ijson

from tcex import TcEx
from tcex.exit import Exit, ExitCode

from job_app import JobApp  # Import default Job App Class (Required)


INVALID_TIMESTAMP_MESSAGE = (
    'Please enter a valid timestamp in ISO 8601 format with the trailing Z. '
    'Example: "2017-05-03T14:38:02Z"'
)

# Algorithm name (lowercase) -> ioc_file attribute for hash
ALGORITHM_HASH_ATTR = {'sha-256': 'sha256', 'sha-1': 'sha1', 'md5': 'md5'}

# Year used for "this year" when filtering Potentially Abused Domains
ABUSED_DOMAINS_YEAR = 2026

# Target number of recent Potentially Abused Domain IOCs to process
RECENT_ABUSED_DOMAINS_TARGET = 200_000


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


def load_potentially_abused_domains_sample(
    sample_size: int = 500,
    path: Path | None = None,
) -> list:
    """Load a sample of domain records from tests/Potentially Abused Domains.gz.

    The .gz file contains a single JSON object with "count" and "results".
    Returns the first sample_size items from results. The full file is loaded
    into memory (~4.6M records); suitable for one-off sample generation.
    """
    if path is None:
        path = Path(__file__).parent / "tests" / "Potentially Abused Domains.gz"
    with gzip.open(path, "rt", encoding="utf-8") as f:
        data = json.load(f)
    return data["results"][:sample_size]


def iter_potentially_abused_domains(
    path: Path | None = None,
) -> Iterator[dict]:
    """Stream all Potentially Abused Domain records from the .gz file.

    This iterator does not filter by year or date; callers can layer any
    additional filtering they need on top.
    """
    if path is None:
        path = Path(__file__).parent / "tests" / "Potentially Abused Domains.gz"
    with gzip.open(path, "rb") as f:
        for record in ijson.items(f, "results.item"):
            yield record


def iter_potentially_abused_domains_by_year(
    year: int = ABUSED_DOMAINS_YEAR,
    path: Path | None = None,
    max_records: int | None = None,
    min_timestamp: datetime | None = None,
) -> Iterator[dict]:
    """Stream domain records from the .gz file that have timestamp in the given year.

    Does not load the full array into memory; yields one record at a time.
    Year defaults to ABUSED_DOMAINS_YEAR (2026).
    max_records caps output for memory safety; None means no limit.
    min_timestamp restricts to records on or after that time (e.g. for "last N days"); use UTC.
    """
    if path is None:
        path = Path(__file__).parent / "tests" / "Potentially Abused Domains.gz"
    year_prefix = str(year)
    n = 0
    with gzip.open(path, "rb") as f:
        for record in ijson.items(f, "results.item"):
            ts_str = record.get("timestamp", "")
            if not ts_str.startswith(year_prefix):
                continue
            if min_timestamp is not None:
                try:
                    parsed = datetime.fromisoformat(
                        ts_str.replace("Z", "+00:00")
                    )
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    if parsed < min_timestamp:
                        continue
                except (ValueError, TypeError):
                    continue
            yield record
            n += 1
            if max_records is not None and n >= max_records:
                return


def load_potentially_abused_domains_for_year(
    year: int = ABUSED_DOMAINS_YEAR,
    path: Path | None = None,
    max_records: int | None = None,
    min_timestamp: datetime | None = None,
) -> list:
    """Load domain records from the .gz file for the given year into a list.

    Consumes the streaming iterator; without max_records the list can be very
    large. Year defaults to ABUSED_DOMAINS_YEAR (2026).
    """
    return list(
        iter_potentially_abused_domains_by_year(
            year=year,
            path=path,
            max_records=max_records,
            min_timestamp=min_timestamp,
        )
    )


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

    def _process_abused_domain(self, record: dict) -> None:
        """Hook for per-domain processing of Potentially Abused Domains IOCs."""
        # Placeholder: implement indicator creation or other logic here.
        pass

    def _select_recent_abused_domain_dates(
        self,
        target_count: int,
        year: int | None = ABUSED_DOMAINS_YEAR,
    ) -> set[str]:
        """Select recent dates (YYYY-MM-DD) until cumulative count reaches target_count.

        Streams the dataset once to build counts per date, then walks dates from
        most recent to oldest until the cumulative total meets or exceeds the target.
        """
        counts: dict[str, int] = {}

        # First pass: build per-day counts within the given year.
        for record in iter_potentially_abused_domains_by_year(year=year):
            ts = record.get("timestamp", "")
            if len(ts) < 10:
                continue
            date_str = ts[:10]  # YYYY-MM-DD
            counts[date_str] = counts.get(date_str, 0) + 1

        if not counts:
            return set()

        today_utc = datetime.now(timezone.utc).date()

        # Convert to date objects and drop any future dates.
        date_objs: list[tuple[date, str]] = []
        for ds in counts:
            try:
                d = datetime.strptime(ds, "%Y-%m-%d").date()
            except ValueError:
                continue
            if d <= today_utc:
                date_objs.append((d, ds))

        if not date_objs:
            return set()

        # Sort by date descending (most recent first).
        date_objs.sort(reverse=True, key=lambda item: item[0])

        selected: set[str] = set()
        cumulative = 0
        for d, ds in date_objs:
            selected.add(ds)
            cumulative += counts.get(ds, 0)
            if cumulative >= target_count:
                break

        self.tcex.log.info(
            "Selected %d dates for recent abused domains (target=%d, cumulative=%d).",
            len(selected),
            target_count,
            cumulative,
        )
        return selected

    def _process_recent_abused_domains(
        self,
        target_count: int = RECENT_ABUSED_DOMAINS_TARGET,
        year: int | None = ABUSED_DOMAINS_YEAR,
    ) -> None:
        """Process the most recent Potentially Abused Domain IOCs up to target_count.

        Goes day by day backwards from today (UTC) by selecting dates with the
        latest timestamps first until the cumulative IOC count reaches or exceeds
        target_count, then streams the dataset again and processes records whose
        dates fall within that selected set.
        """
        selected_dates = self._select_recent_abused_domain_dates(
            target_count=target_count,
            year=year,
        )
        if not selected_dates:
            self.tcex.log.info(
                "No Potentially Abused Domains selected for recent processing."
            )
            return

        processed = 0
        for record in iter_potentially_abused_domains_by_year(year=year):
            ts = record.get("timestamp", "")
            if len(ts) < 10:
                continue
            date_str = ts[:10]
            if date_str in selected_dates:
                self._process_abused_domain(record)
                processed += 1

        self.tcex.log.info(
            "Processed %d Potentially Abused Domains records across %d recent dates.",
            processed,
            len(selected_dates),
        )

    def _process_entities(self, entities: list) -> tuple[int, int, int]:
        """Process entities into batch file indicators. Returns (total, candidates, indicators_added)."""
        total_entities = len(entities)
        candidate_entities = 0
        indicators_added = 0

        for entity in entities:
            if entity.get('algorithm', '').lower() in ALGORITHM_HASH_ATTR:
                candidate_entities += 1
                ioc_file = self.batch.file()

                algo = entity.get('algorithm', '').lower()
                hash_value = entity.get('hash')
                if algo in ALGORITHM_HASH_ATTR:
                    setattr(ioc_file, ALGORITHM_HASH_ATTR[algo], hash_value)
                if entity.get('lastSeen'):
                    last_seen_iso = normalize_timestamp_to_iso8601_utc(entity.get("lastSeen"))
                    ioc_file.attribute('Last Seen', last_seen_iso)

                self.batch.save(ioc_file)
                indicators_added += 1

        return total_entities, candidate_entities, indicators_added

    def run(self):
        """Run main App logic."""
        entities = load_potentially_undetectable_malware()
        self.tcex.log.info(
            'App.run: starting processing for owner %s with %d entities.',
            self.in_.tc_owner,
            len(entities),
        )

        total_entities, candidate_entities, indicators_added = self._process_entities(entities)
        self.tcex.log.info(
            'App.run: finished loop. total_entities=%d, candidate_entities=%d, indicators_added=%d',
            total_entities,
            candidate_entities,
            indicators_added,
        )

        # Optionally process recent Potentially Abused Domains IOCs.
        self._process_recent_abused_domains(
            target_count=RECENT_ABUSED_DOMAINS_TARGET,
            year=ABUSED_DOMAINS_YEAR,
        )

        batch_response = self.batch.submit_all()
        self.batch.close()

        errors = []
        for item in batch_response:
            errors.extend(item.get('errors', []))
        if errors:
            self.tcex.log.error('App.run: batch submission failed with %d errors', len(errors))
            self.tcex.log.error('App.run: batch submission error: %s', errors[0])
        self.tcex.log.info('App.run: batch submission complete.')
        self.tcex.exit.exit(0, 'Batch submission complete.')