import pytest

from app import INVALID_TIMESTAMP_MESSAGE, normalize_timestamp_to_iso8601_utc


def test_normalize_timestamp_from_iso_string_round_trip():
    iso = "2017-05-03T14:38:02Z"
    assert normalize_timestamp_to_iso8601_utc(iso) == iso


def test_normalize_timestamp_from_milliseconds_int():
    # 1725525666332 ms since epoch -> 2024-09-05T08:41:06Z (UTC)
    ms = 1725525666332
    assert normalize_timestamp_to_iso8601_utc(ms) == "2024-09-05T08:41:06Z"


def test_normalize_timestamp_from_milliseconds_string():
    ms_str = "1725525666332"
    assert normalize_timestamp_to_iso8601_utc(ms_str) == "2024-09-05T08:41:06Z"


@pytest.mark.parametrize("value", ["", None, "not-a-timestamp", "2024-01-01T00:00:00", "2024-13-01T00:00:00Z"])
def test_normalize_timestamp_invalid_values(value):
    with pytest.raises(ValueError) as excinfo:
        normalize_timestamp_to_iso8601_utc(value)
    assert str(excinfo.value) == INVALID_TIMESTAMP_MESSAGE

