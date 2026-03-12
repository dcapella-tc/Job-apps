from app import filter_entities_by_algorithm, load_potentially_undetectable_malware


def test_load_potentially_undetectable_malware_non_empty():
    """Basic sanity check that the JSON loader returns at least one entity."""
    entities = load_potentially_undetectable_malware()

    assert isinstance(entities, list)
    assert len(entities) > 0


def test_filter_entities_by_algorithm_allows_only_specific_algorithms():
    """Verify that only MD5, SHA-1, and SHA-256 algorithms are kept."""
    entities = [
        {"hash": "md5-hash", "algorithm": "MD5"},
        {"hash": "sha1-hash", "algorithm": "SHA-1"},
        {"hash": "sha256-hash", "algorithm": "SHA-256"},
        {"hash": "sha512-hash", "algorithm": "SHA-512"},
        {"hash": "no-algorithm"},
        "not-a-dict",
    ]

    filtered = filter_entities_by_algorithm(entities)

    assert len(filtered) == 3
    assert all(e["algorithm"] in {"MD5", "SHA-1", "SHA-256"} for e in filtered)
