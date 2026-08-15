import pytest

from securechat.swarm.audit_binding import (
    AuditBinding,
    hash_audit_binding,
    verify_audit_binding,
)


def make_binding(**overrides):
    values = {
        "swarm_id": "swarm-1",
        "rotation_id": "rotation-1",
        "event_type": "piece_assigned",
        "event_id": "event-1",
        "actor_id": "peer-1",
        "created_at": 1000,
        "details": {
            "piece_index": "7",
            "reason": "rotation",
        },
    }
    values.update(overrides)
    return AuditBinding.create(**values)


def test_audit_binding_creation():
    binding = make_binding()

    assert binding.swarm_id == "swarm-1"
    assert binding.rotation_id == "rotation-1"
    assert binding.event_type == "piece_assigned"
    assert binding.event_id == "event-1"
    assert binding.actor_id == "peer-1"
    assert binding.created_at == 1000


def test_empty_swarm_id_rejected():
    with pytest.raises(ValueError, match="swarm_id"):
        make_binding(swarm_id="")


def test_empty_rotation_id_rejected():
    with pytest.raises(ValueError, match="rotation_id"):
        make_binding(rotation_id="")


def test_empty_event_type_rejected():
    with pytest.raises(ValueError, match="event_type"):
        make_binding(event_type="")


def test_empty_event_id_rejected():
    with pytest.raises(ValueError, match="event_id"):
        make_binding(event_id="")


def test_empty_actor_id_rejected():
    with pytest.raises(ValueError, match="actor_id"):
        make_binding(actor_id="")


def test_negative_created_at_rejected():
    with pytest.raises(ValueError, match="created_at"):
        make_binding(created_at=-1)


def test_details_are_canonicalized():
    first = make_binding(
        details={
            "z": "last",
            "a": "first",
        }
    )
    second = make_binding(
        details={
            "a": "first",
            "z": "last",
        }
    )

    assert first.details == second.details
    assert first.to_canonical_bytes() == second.to_canonical_bytes()
    assert first.binding_hash() == second.binding_hash()


def test_canonical_bytes_are_deterministic():
    first = make_binding()
    second = make_binding()

    assert first.to_canonical_bytes() == second.to_canonical_bytes()


def test_binding_hash_is_deterministic():
    first = make_binding()
    second = make_binding()

    assert first.binding_hash() == second.binding_hash()


def test_binding_hash_is_sha256_length():
    binding = make_binding()

    assert len(binding.binding_hash()) == 64
    assert all(
        character in "0123456789abcdef"
        for character in binding.binding_hash()
    )


def test_different_event_id_changes_hash():
    first = make_binding(event_id="event-1")
    second = make_binding(event_id="event-2")

    assert first.binding_hash() != second.binding_hash()


def test_different_rotation_changes_hash():
    first = make_binding(rotation_id="rotation-1")
    second = make_binding(rotation_id="rotation-2")

    assert first.binding_hash() != second.binding_hash()


def test_different_details_change_hash():
    first = make_binding(details={"piece_index": "7"})
    second = make_binding(details={"piece_index": "8"})

    assert first.binding_hash() != second.binding_hash()


def test_hash_helper_matches_binding():
    binding = make_binding()

    assert hash_audit_binding(binding) == binding.binding_hash()


def test_verify_audit_binding_accepts_valid_hash():
    binding = make_binding()
    expected = binding.binding_hash()

    assert verify_audit_binding(binding, expected) is True


def test_verify_audit_binding_rejects_wrong_hash():
    binding = make_binding()

    assert verify_audit_binding(binding, "0" * 64) is False


def test_verify_audit_binding_rejects_empty_hash():
    binding = make_binding()

    assert verify_audit_binding(binding, "") is False


def test_details_values_are_normalized_to_strings():
    binding = make_binding(
        details={
            "piece_index": 7,
            "attempt": 2,
        }
    )

    assert binding.details == (
        ("attempt", "2"),
        ("piece_index", "7"),
    )


def test_empty_details_are_supported():
    binding = make_binding(details=None)

    assert binding.details == ()
    assert binding.binding_hash()


def test_binding_is_immutable():
    binding = make_binding()

    with pytest.raises(AttributeError):
        binding.event_id = "changed"
