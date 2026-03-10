"""Tests for OTX app helpers."""

from datetime import datetime, timezone

import pytest

from app import parse_last_run


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
