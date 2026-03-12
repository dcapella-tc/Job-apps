"""ThreatConnect Job App"""

from tcex import TcEx
from tcex.exit import ExitCode

from job_app import JobApp  # Import default Job App Class (Required)

import csv
import json
import os

# testing: testing data
test_csv_file = 'Threat Actor Retro-Hunts - Sample Set 100.csv'


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
        first_row = None

        try:
            with open(csv_path, newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    first_row = row
                    break
        except FileNotFoundError:
            self.tcex.log.error(f'CSV file not found: {csv_path}')
            return
        except Exception as e:
            self.tcex.log.error(f'Error reading CSV file {csv_path}: {e}')
            return

        if first_row is None:
            self.tcex.log.warning('CSV file appears to be empty; no rows to write.')
            return

        tests_dir = os.path.join(base_dir, 'tests')
        os.makedirs(tests_dir, exist_ok=True)
        json_path = os.path.join(tests_dir, 'test_row.json')

        try:
            with open(json_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(first_row, jsonfile, indent=2)
        except Exception as e:
            self.tcex.log.error(f'Error writing JSON file {json_path}: {e}')
            return

        self.tcex.log.info(f'Wrote first CSV row to {json_path}')

        with self.tcex.session.external as s:
            # https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json
            # r = s.get('/someendpoint.csv')

            # if not r.ok:
            #     self.tcex.exit.exit(ExitCode.FAILURE, 'Failed to download data.')
            pass
