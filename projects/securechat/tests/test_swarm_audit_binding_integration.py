import pytest

from securechat.swarm.audit_binding import AuditBinding
from securechat.swarm.manifest_builder import build_manifest
from securechat.swarm.piece import MessagePiece
from securechat.swarm.rotation import SwarmRotation
from securechat.swarm.transition import SwarmTransition


def make_manifest():
    pieces = tuple(
        MessagePiece.create(
            swarm_id="swarm-1",
            piece_index=index,
            ciphertext=bytes([index]) * 32,
        )
        for index in range(20)
    )

    return build_manifest(
        swarm_id="swarm-1",
        message_id="message-1",
        recipient_id="bob",
        pieces=pieces,
        piece_size=32,
        expires_at=3000,
    )


def make_assignments(offset=0):
    return {
        f"peer-{index}": ((index + offset) % 20,)
        for index in range(20)
    }


def make_rotations():
    manifest = make_manifest()

    first = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-1",
        assignments=make_assignments(),
        created_at=1000,
        expires_at=1500,
    )

    second = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-2",
        assignments=make_assignments(1),
        created_at=1500,
        expires_at=2000,
        previous_rotation_id="rotation-1",
    )

    return first, second


def test_audit_binding_can_reference_transition():
    first, second = make_rotations()

    transition = SwarmTransition.create(
        previous_rotation=first,
        next_rotation=second,
        created_at=1500,
    )

    binding = AuditBinding.create(
        swarm_id=transition.swarm_id,
        rotation_id=transition.next_rotation_id,
        event_type="rotation_transition",
        event_id=transition.transition_hash(),
        actor_id="peer-0",
        created_at=transition.created_at,
    )

    assert binding.swarm_id == transition.swarm_id
    assert binding.rotation_id == transition.next_rotation_id
    assert binding.event_type == "rotation_transition"
    assert binding.event_id == transition.transition_hash()


def test_audit_binding_can_detect_wrong_swarm_reference():
    first, second = make_rotations()

    transition = SwarmTransition.create(
        previous_rotation=first,
        next_rotation=second,
        created_at=1500,
    )

    binding = AuditBinding.create(
        swarm_id="different-swarm",
        rotation_id=transition.next_rotation_id,
        event_type="rotation_transition",
        event_id=transition.transition_hash(),
        actor_id="peer-0",
        created_at=1500,
    )

    assert binding.swarm_id != transition.swarm_id


def test_transition_hash_can_be_used_as_audit_event_id():
    first, second = make_rotations()

    transition = SwarmTransition.create(
        previous_rotation=first,
        next_rotation=second,
        created_at=1500,
    )

    binding = AuditBinding.create(
        swarm_id=transition.swarm_id,
        rotation_id=transition.next_rotation_id,
        event_type="rotation_transition",
        event_id=transition.transition_hash(),
        actor_id="system",
        created_at=1500,
    )

    assert binding.event_id == transition.transition_hash()
    assert len(binding.event_id) == 64


def test_audit_binding_changes_when_transition_changes():
    first, second = make_rotations()

    transition = SwarmTransition.create(
        previous_rotation=first,
        next_rotation=second,
        created_at=1500,
    )

    first_binding = AuditBinding.create(
        swarm_id=transition.swarm_id,
        rotation_id=transition.next_rotation_id,
        event_type="rotation_transition",
        event_id=transition.transition_hash(),
        actor_id="peer-0",
        created_at=1500,
    )

    second_binding = AuditBinding.create(
        swarm_id=transition.swarm_id,
        rotation_id=transition.next_rotation_id,
        event_type="rotation_transition",
        event_id=transition.transition_hash(),
        actor_id="peer-1",
        created_at=1500,
    )

    assert first_binding.binding_hash() != second_binding.binding_hash()


def test_audit_binding_is_deterministic_for_same_transition():
    first, second = make_rotations()

    transition = SwarmTransition.create(
        previous_rotation=first,
        next_rotation=second,
        created_at=1500,
    )

    details = {
        "transition_hash": transition.transition_hash(),
        "previous_rotation": transition.previous_rotation_id,
        "next_rotation": transition.next_rotation_id,
    }

    first_binding = AuditBinding.create(
        swarm_id=transition.swarm_id,
        rotation_id=transition.next_rotation_id,
        event_type="rotation_transition",
        event_id=transition.transition_hash(),
        actor_id="system",
        created_at=1500,
        details=details,
    )

    second_binding = AuditBinding.create(
        swarm_id=transition.swarm_id,
        rotation_id=transition.next_rotation_id,
        event_type="rotation_transition",
        event_id=transition.transition_hash(),
        actor_id="system",
        created_at=1500,
        details=details,
    )

    assert first_binding.binding_hash() == second_binding.binding_hash()
