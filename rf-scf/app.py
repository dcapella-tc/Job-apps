"""ThreatConnect Job App"""

from tcex import TcEx
from tcex.exit import ExitCode

from job_app import JobApp  # Import default Job App Class (Required)

import csv
import json
import os
import re
import types

# testing: testing data
test_csv_file = 'Threat Actor Retro-Hunts - Sample Set 100.csv'


def _sanitize_key(key: str) -> str:
    """Return a valid Python identifier from a CSV header key."""
    s = re.sub(r'[^a-zA-Z0-9_]', '_', key.strip())
    return s if s else '_'


def _parse_json(s, default=None):
    """Parse JSON string; return default on empty or error."""
    if s is None or (isinstance(s, str) and not s.strip()):
        return default
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return default


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
        base_dir = os.path.dirname(__file__)
        csv_path = os.path.join(base_dir, test_csv_file)
        all_rows = []

        try:
            with open(csv_path, newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    all_rows.append(row)
                    row_vars = types.SimpleNamespace()
                    for k, v in row.items():
                        setattr(row_vars, _sanitize_key(k), v)

                    risk_val = int(row_vars.Risk) if getattr(row_vars, 'Risk', None) else 0
                    indicator = {
                        'summary': row_vars.Name,
                        'confidence': risk_val,
                        'threat': round(risk_val / 20),
                    }

                    indicator_notes_raw = getattr(row_vars, 'IndicatorNotes', None)
                    indicator_attributes = _parse_json(indicator_notes_raw) if indicator_notes_raw else None

                    ta_ids = _parse_json(getattr(row_vars, 'ThreatActorIDs', None), []) or []
                    ta_names = _parse_json(getattr(row_vars, 'ThreatActorNames', None), {}) or {}
                    ta_aliases = _parse_json(getattr(row_vars, 'ThreatActorAliases', None), {}) or {}
                    ta_categories = _parse_json(getattr(row_vars, 'ThreatActorCategories', None), {}) or {}
                    ta_notes = _parse_json(getattr(row_vars, 'ThreatActorNotes', None), {}) or {}

                    for ta_id in ta_ids:
                        name = ta_names.get(ta_id)
                        aliases = ta_aliases.get(ta_id)
                        tags = ta_categories.get(ta_id)
                        attributes = ta_notes.get(ta_id)
                        threat_actor = {
                            'name': name,
                            'aliases': aliases,
                            'tags': tags,
                            'attributes': attributes,
                        }
                        # indicator, indicator_attributes, threat_actor available for downstream use
        except FileNotFoundError:
            self.tcex.log.error(f'CSV file not found: {csv_path}')
            return
        except Exception as e:
            self.tcex.log.error(f'Error reading CSV file {csv_path}: {e}')
            return

        if not all_rows:
            self.tcex.log.warning('CSV file appears to be empty; no rows to write.')
            return

        tests_dir = os.path.join(base_dir, 'tests')
        os.makedirs(tests_dir, exist_ok=True)
        json_path = os.path.join(tests_dir, 'all_rows.json')

        try:
            with open(json_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(all_rows, jsonfile, indent=2)
        except Exception as e:
            self.tcex.log.error(f'Error writing JSON file {json_path}: {e}')
            return

        self.tcex.log.info(f'Wrote {len(all_rows)} rows to {json_path}')

        with self.tcex.session.external as s:
            # https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json
            # r = s.get('/someendpoint.csv')

            # if not r.ok:
            #     self.tcex.exit.exit(ExitCode.FAILURE, 'Failed to download data.')
            pass
