from app import load_potentially_undetectable_malware


def test_load_potentially_undetectable_malware_non_empty():
    """Basic sanity check that the JSON loader returns at least one entity."""
    entities = load_potentially_undetectable_malware()

    assert isinstance(entities, list)
    assert len(entities) > 0
