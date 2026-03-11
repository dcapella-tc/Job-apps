"""Tests for OTX app helpers."""

from datetime import datetime, timezone
from unittest.mock import MagicMock
import types

import pytest

from app import (
    App,
    extract_next_token,
    extract_pulse_ids,
    indicator_type_mapping,
    list_to_html_list,
    list_to_html_table,
    parse_last_run,
)
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
    assert external_session.get.call_args_list[1][0][0] == '/pulses/123'

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


def test_extract_pulse_ids_mixed():
    """extract_pulse_ids returns string ids from results; skips items without id."""
    payload = {'results': [{'id': '1'}, {'id': 2}, {'name': 'x'}]}
    assert extract_pulse_ids(payload) == ['1', '2']


def test_extract_pulse_ids_empty_or_missing():
    """extract_pulse_ids returns [] for empty or missing results."""
    assert extract_pulse_ids({'results': []}) == []
    assert extract_pulse_ids({}) == []


def test_extract_next_token_present():
    """extract_next_token returns the next URL when present."""
    payload = {'next': 'https://example.com?page=2'}
    assert extract_next_token(payload) == 'https://example.com?page=2'


def test_extract_next_token_absent():
    """extract_next_token returns None when next is missing."""
    assert extract_next_token({}) is None
    assert extract_next_token({'results': []}) is None


def test_list_to_html_list():
    """list_to_html_list produces header and list items."""
    out = list_to_html_list('Header', ['a', 'b'])
    assert '<b>Header</b>' in out
    assert '<ul>' in out
    assert '<li>a</li>' in out
    assert '<li>b</li>' in out


def test_list_to_html_table_single_column():
    """list_to_html_table with str header produces one column."""
    out = list_to_html_table('Col', ['a', 'b'])
    assert '<th>Col</th>' in out
    assert '<td>a</td>' in out
    assert '<td>b</td>' in out
    assert out.startswith('<table>')


def test_list_to_html_table_two_columns():
    """list_to_html_table with list header produces multiple columns."""
    out = list_to_html_table(['A', 'B'], [['1', '2'], ['3', '4']])
    assert '<th>A</th>' in out
    assert '<th>B</th>' in out
    assert '<td>1</td>' in out and '<td>2</td>' in out
    assert '<td>3</td>' in out and '<td>4</td>' in out


def test_indicator_type_mapping_known():
    """indicator_type_mapping maps known types to TC types."""
    assert indicator_type_mapping('domain') == 'Host'
    assert indicator_type_mapping('filehash-md5') == 'File'
    assert indicator_type_mapping('ipv4') == 'Address'
    assert indicator_type_mapping('url') == 'URL'


def test_indicator_type_mapping_unknown():
    """indicator_type_mapping returns original for unknown (case-insensitive)."""
    assert indicator_type_mapping('unknown') == 'unknown'
    assert indicator_type_mapping('URL') == 'URL'


@pytest.fixture
def app_with_batch():
    """App instance with mocked tcex and batch for method tests."""
    tcex = MagicMock()
    tcex.log.info = MagicMock()
    tcex.log.error = MagicMock()
    tcex.log.debug = MagicMock()
    tcex.exit.exit = MagicMock()
    in_ = types.SimpleNamespace(tc_owner='MyOrg', otx_api_key='key', last_run='7 Days Ago')
    batch = MagicMock()
    batch.generate_xid.return_value = 'MyOrg::Report::TestName'
    app = App(tcex)
    app.in_ = in_
    app.batch = batch
    return app


def test_generate_xid_calls_batch_with_owner_type_name(app_with_batch):
    """_generate_xid calls batch.generate_xid with [tc_owner, type, name] and returns value."""
    result = app_with_batch._generate_xid({'type': 'Report', 'name': 'TestName'})
    app_with_batch.batch.generate_xid.assert_called_once_with(
        ['MyOrg', 'Report', 'TestName']
    )
    assert result == 'MyOrg::Report::TestName'


def test_normalize_group_batch(app_with_batch):
    """_normalize_group_batch produces batch dict with xid, name, type, optional attribute/tag."""
    group = {
        'name': 'G1',
        'type': 'Report',
        'attributes': [{'type': 'Description', 'value': 'd'}],
        'tags': {'tag1'},
        'associatedGroupXid': ['xid2'],
    }
    out = app_with_batch._normalize_group_batch(group)
    assert out['xid'] == 'MyOrg::Report::TestName'
    assert out['name'] == 'G1'
    assert out['type'] == 'Report'
    assert out['attribute'] == [{'type': 'Description', 'value': 'd'}]
    assert out['tag'] == {'tag1'}
    assert out['associatedGroupXid'] == ['xid2']


def test_normalize_indicator_batch(app_with_batch):
    """_normalize_indicator_batch produces batch dict with type, summary, xid."""
    indicator = {'type': 'Host', 'summary': 'example.com', 'name': 'example.com'}
    out = app_with_batch._normalize_indicator_batch(indicator)
    assert out['type'] == 'Host'
    assert out['summary'] == 'example.com'
    assert out['xid'] == 'MyOrg::Report::TestName'
    app_with_batch.batch.generate_xid.assert_called_with(
        ['MyOrg', 'Host', 'example.com']
    )


def test_extract_pulse_detail_fields_returns_group_with_attributes_and_indicators(
    app_with_batch,
):
    """_extract_pulse_detail_fields returns group with name, description, tags, attributes, associated_indicators."""
    detail = {
        'id': 'pid1',
        'name': 'Pulse Name',
        'description': 'Desc',
        'author_name': 'Author',
        'modified': '2026-01-01',
        'created': '2026-01-02',
        'TLP': 'white',
        'tags': ['t1'],
        'references': ['https://ref'],
        'attack_ids': [],
        'targeted_countries': [],
        'malware_families': [],
        'industries': [],
        'author': {'username': 'u', 'id': '2', 'avatar_url': '/url'},
        'indicators': [{'type': 'domain', 'indicator': 'example.com'}],
    }
    group = app_with_batch._extract_pulse_detail_fields(detail)
    assert group['name'] == 'Pulse Name'
    assert group['description'] == 'Desc'
    assert 't1' in group['tags']
    assert group['associated_indicators'] == [
        {'type': 'Host', 'summary': 'example.com'}
    ]
    attr_types = [a['type'] for a in group['attributes']]
    assert 'Description' in attr_types
    assert 'Author' in attr_types
    assert 'External ID' in attr_types
