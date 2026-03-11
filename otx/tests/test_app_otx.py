"""Tests for OTX app helpers."""

from datetime import datetime, timezone
from unittest.mock import MagicMock
import types

import pytest

from app import App, parse_last_run
from naics import naics_tags_for_keyword


def test_parse_last_run_days_ago():
    """Parse_last_run with '7 Days Ago' returns now minus 7 days (UTC)."""
    result = parse_last_run('7 Days Ago')
    now = datetime.now(timezone.utc)
    delta = (now - result).total_seconds()
    # Between 6.9 and 7.1 days in seconds
    assert 7 * 86400 - 3600 <= delta <= 7 * 86400 + 3600
    assert result.tzinfo is not None


def test_parse_last_run_one_day_ago():
    """Parse_last_run with '1 Day Ago' is accepted."""
    result = parse_last_run('1 Day Ago')
    now = datetime.now(timezone.utc)
    delta = (now - result).total_seconds()
    assert 86400 - 60 <= delta <= 86400 + 60


def test_parse_last_run_iso_date_only():
    """Parse_last_run with ISO date string returns that date at midnight UTC."""
    result = parse_last_run('2026-03-10')
    assert result.year == 2026
    assert result.month == 3
    assert result.day == 10
    assert result.tzinfo == timezone.utc


def test_parse_last_run_iso_datetime_z():
    """Parse_last_run with ISO datetime ending in Z returns correct UTC."""
    result = parse_last_run('2026-03-10T12:00:00Z')
    assert result.year == 2026
    assert result.month == 3
    assert result.day == 10
    assert result.hour == 12
    assert result.minute == 0
    assert result.second == 0
    assert result.tzinfo == timezone.utc


def test_parse_last_run_invalid_raises():
    """Parse_last_run with invalid string raises ValueError with expected message."""
    with pytest.raises(ValueError) as exc_info:
        parse_last_run('foo')
    assert 'last_run must be' in str(exc_info.value)
    assert 'N Days Ago' in str(exc_info.value)
    assert 'ISO' in str(exc_info.value)


def test_parse_last_run_empty_raises():
    """Parse_last_run with empty string raises ValueError."""
    with pytest.raises(ValueError) as exc_info:
        parse_last_run('')
    assert 'last_run must be' in str(exc_info.value)


def test_fetch_pulse_detail_calls_correct_url_and_exposes_payload():
    """App.run should fetch per-pulse details for each extracted pulse ID."""
    tcex = MagicMock()

    # Mock external session as context manager
    external_session = MagicMock()
    external_session.__enter__.return_value = external_session
    external_session.__exit__.return_value = False
    tcex.session.external = external_session

    tcex.exit.exit = MagicMock()
    tcex.log.info = MagicMock()
    tcex.log.debug = MagicMock()

    # Minimal inputs expected by App
    in_ = types.SimpleNamespace(tc_owner='Org', otx_api_key='API_KEY', last_run='7 Days Ago')

    # First response: list pulses (one pulse with id '123', no next)
    list_response = MagicMock()
    list_response.ok = True
    list_response.json.return_value = {'results': [{'id': '123'}], 'next': None}

    # Second response: detail for pulse 123
    detail_payload = {'id': '123', 'name': 'Example Pulse', 'indicators': []}
    detail_response = MagicMock()
    detail_response.ok = True
    detail_response.json.return_value = detail_payload

    external_session.get.side_effect = [list_response, detail_response]

    app = App(tcex)
    app.in_ = in_

    app.run()

    # Verify list and detail endpoints were called
    assert external_session.get.call_args_list[0][0][0] == '/pulses/subscribed'
    assert external_session.get.call_args_list[1][0][0] == '/pulses/subscribed/123'

    # Verify the detail payload was surfaced in debug logging
    debug_calls = [str(call.args[0]) for call in tcex.log.debug.call_args_list]
    assert any('Example Pulse' in msg for msg in debug_calls)


def test_naics_tags_for_keyword_finance():
    """naics_tags_for_keyword('finance') returns at least one tag containing 52 and Finance."""
    tags = naics_tags_for_keyword('finance')
    assert len(tags) >= 1
    assert any('52' in t and 'Finance' in t for t in tags)


def test_naics_tags_for_keyword_empty_returns_empty():
    """naics_tags_for_keyword with empty or whitespace returns []."""
    assert naics_tags_for_keyword('') == []
    assert naics_tags_for_keyword('   ') == []
