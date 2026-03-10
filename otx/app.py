"""ThreatConnect Job App"""
from datetime import datetime, timedelta, timezone

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

    def parse_otx_datetime(self, value: str | datetime | None) -> datetime | None:
        """Parse an OTX datetime string into a timezone-aware datetime."""
        if isinstance(value, datetime):
            parsed = value
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        if not isinstance(value, str) or not value:
            return None

        normalized_value = value.replace('Z', '+00:00')
        try:
            parsed = datetime.fromisoformat(normalized_value)
        except ValueError:
            return None

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed

    def get_pulse_timestamp(self, pulse: dict) -> datetime | None:
        """Return the best available timestamp for a pulse."""
        for field_name in ('modified', 'modified_text', 'created', 'created_text'):
            parsed = self.parse_otx_datetime(pulse.get(field_name))
            if parsed:
                return parsed
        return None

    def map_indicator_type(self, otx_type: str) -> str | None:
        """Map OTX indicator types to ThreatConnect indicator types."""
        mapping = {
            'IPv4': 'Address',
            'IPv6': 'Address',
            'domain': 'Host',
            'hostname': 'Host',
            'URL': 'URL',
            'FileHash-MD5': 'File',
            'FileHash-SHA1': 'File',
            'FileHash-SHA256': 'File',
            'email': 'EmailAddress',
        }
        return mapping.get(otx_type)

    def normalize_indicator(self, indicator: dict) -> dict | None:
        """Normalize one OTX indicator into a ThreatConnect-friendly structure."""
        indicator_value = indicator.get('indicator')
        otx_type = indicator.get('type')

        if not indicator_value or not isinstance(otx_type, str):
            return None

        tc_type = self.map_indicator_type(otx_type)
        if not tc_type:
            return None

        return {
            'value': indicator_value,
            'source_type': otx_type,
            'tc_type': tc_type,
        }

    def normalize_pulse(self, pulse: dict) -> dict:
        """Normalize one OTX pulse into a report-like structure for later TC ingest."""
        pulse_id = pulse.get('id')
        pulse_name = pulse.get('name') or pulse.get('title') or f'OTX Pulse {pulse_id}'
        pulse_description = pulse.get('description')
        pulse_tags = pulse.get('tags') or []
        pulse_created = pulse.get('created') or pulse.get('created_text')
        pulse_modified = pulse.get('modified') or pulse.get('modified_text')
        pulse_references = pulse.get('references') or []
        pulse_author = pulse.get('author_name') or pulse.get('author')

        return {
            'pulse_id': pulse_id,
            'report_name': pulse_name,
            'report_xid': f'otx-pulse-{pulse_id}' if pulse_id else None,
            'description': pulse_description,
            'tags': pulse_tags,
            'created': pulse_created,
            'modified': pulse_modified,
            'references': pulse_references,
            'author': pulse_author,
            'indicators': [],
        }

    def run(self):
        """Run main App logic."""
        last_run_raw = self.in_.last_run
        last_run_dt = self.parse_otx_datetime(last_run_raw)
        effective_start_dt = last_run_dt
        lookback_days = getattr(self.in_, 'lookback_days', None)
        if last_run_dt and isinstance(lookback_days, int) and lookback_days > 0:
            effective_start_dt = last_run_dt - timedelta(days=lookback_days)
        newest_processed_dt: datetime | None = last_run_dt

        with self.tcex.session.external as s:
            # Download subscribed pulses and pull all IOC types newer than the last run.
            r = s.get('/pulses/subscribed', params={'page': 1})

            if r.ok:
                data = r.json()
                pulses = data.get('results', [])
                pulse_reports = []
                all_indicators = []
                seen_indicators = set()
                new_pulse_count = 0

                for pulse in pulses:
                    pulse_dt = self.get_pulse_timestamp(pulse)
                    if effective_start_dt and pulse_dt and pulse_dt <= effective_start_dt:
                        continue

                    new_pulse_count += 1
                    if pulse_dt and (newest_processed_dt is None or pulse_dt > newest_processed_dt):
                        newest_processed_dt = pulse_dt

                    normalized_pulse = self.normalize_pulse(pulse)
                    pulse_seen_indicators = set()

                    for indicator in pulse.get('indicators', []):
                        normalized_indicator = self.normalize_indicator(indicator)
                        if not normalized_indicator:
                            continue

                        dedupe_key = (
                            normalized_indicator['value'],
                            normalized_indicator['tc_type'],
                        )
                        if dedupe_key in seen_indicators:
                            continue

                        seen_indicators.add(dedupe_key)
                        all_indicators.append(normalized_indicator)

                        if dedupe_key in pulse_seen_indicators:
                            continue

                        pulse_seen_indicators.add(dedupe_key)
                        normalized_pulse['indicators'].append(normalized_indicator)

                    if normalized_pulse['indicators']:
                        pulse_reports.append(normalized_pulse)

                if newest_processed_dt and newest_processed_dt != last_run_dt:
                    new_last_run = newest_processed_dt.astimezone(timezone.utc).isoformat()
                    self.tcex.app.results_tc('last_run', new_last_run)
                    self.log.info(f'Updated last_run to {new_last_run}.')
                elif last_run_raw:
                    self.log.info(f'last_run unchanged at {last_run_raw}.')
                else:
                    self.log.info('No last_run saved because no pulse timestamp was found.')

                if effective_start_dt:
                    self.log.info(
                        f'Using effective start time {effective_start_dt.astimezone(timezone.utc).isoformat()} '
                        f'with lookback_days={lookback_days}.'
                    )

                self.log.info(
                    f'Successfully connected to OTX. Retrieved {len(pulses)} pulses, '
                    f'{new_pulse_count} new pulses, {len(pulse_reports)} normalized pulse '
                    f'reports, and {len(all_indicators)} deduplicated indicators from page 1.'
                )

                if pulse_reports:
                    self.log.info(f'Sample pulse reports: {pulse_reports[:3]}')

                if all_indicators:
                    self.log.info(f'Sample indicators: {all_indicators[:10]}')

                self.exit_message = (
                    f'Successfully connected to OTX. Retrieved {len(all_indicators)} '
                    f'indicators from {len(pulse_reports)} normalized pulses.'
                )
                self.tcex.exit.exit(ExitCode.SUCCESS, self.exit_message)

            error_text = r.text[:500] if r.text else 'No response body returned.'
            self.log.error(f'OTX connection failed ({r.status_code}): {error_text}')
            self.tcex.exit.exit(
                ExitCode.FAILURE,
                f'OTX connection failed with status {r.status_code}.',
            )
