import uuid

import pytest

from securechat.identity import Identity


def test_identity_create():
    identity = Identity.create("Alice")

    uuid.UUID(identity.identity_id)

    assert identity.display_name == "Alice"


def test_identity_ids_are_unique():
    first = Identity.create("Alice")
    second = Identity.create("Alice")

    assert first.identity_id != second.identity_id


def test_identity_normalizes_values():
    identity = Identity(
        " 550E8400-E29B-41D4-A716-446655440000 ",
        "  Alice  ",
    )

    assert identity.identity_id == "550e8400-e29b-41d4-a716-446655440000"
    assert identity.display_name == "Alice"


def test_empty_display_name_rejected():
    with pytest.raises(ValueError, match="display_name"):
        Identity.create("")


def test_whitespace_display_name_rejected():
    with pytest.raises(ValueError, match="display_name"):
        Identity.create("   ")


def test_display_name_length_rejected():
    with pytest.raises(ValueError, match="too long"):
        Identity.create("A" * 129)


def test_invalid_identity_id_rejected():
    with pytest.raises(ValueError, match="UUID"):
        Identity("not-a-uuid", "Alice")


def test_identity_round_trip():
    original = Identity.create("Alice")

    restored = Identity.from_dict(original.to_dict())

    assert restored == original


def test_missing_field_rejected():
    with pytest.raises(ValueError, match="missing identity fields"):
        Identity.from_dict({
            "identity_id": str(uuid.uuid4()),
        })


def test_identity_id_must_be_string():
    with pytest.raises(ValueError, match="identity_id"):
        Identity.from_dict({
            "identity_id": 123,
            "display_name": "Alice",
        })


def test_display_name_must_be_string():
    with pytest.raises(ValueError, match="display_name"):
        Identity.from_dict({
            "identity_id": str(uuid.uuid4()),
            "display_name": 123,
        })


def test_to_dict_contains_public_fields_only():
    identity = Identity.create("Alice")

    assert identity.to_dict() == {
        "identity_id": identity.identity_id,
        "display_name": "Alice",
    }
