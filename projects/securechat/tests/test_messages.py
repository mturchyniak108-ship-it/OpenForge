import pytest

from securechat.protocol.messages import Message, PROTOCOL_VERSION


def test_message_round_trip():
    original = Message.create(
        sender="alice",
        recipient="bob",
        sequence=1,
        timestamp=1750000000,
        message_type="text",
        payload=b"Hello Bob",
    )

    restored = Message.from_bytes(original.to_bytes())

    assert restored == original
    assert restored.payload == b"Hello Bob"
    assert restored.version == PROTOCOL_VERSION


def test_message_has_unique_id():
    a = Message.create("alice", "bob", 1, 1, "text", b"a")
    b = Message.create("alice", "bob", 2, 2, "text", b"b")

    assert a.message_id != b.message_id


def test_missing_field_rejected():
    message = {
        "version": 1,
        "message_id": "test",
    }

    with pytest.raises(ValueError):
        Message.from_dict(message)


def test_wrong_protocol_version_rejected():
    message = {
        "version": 999,
        "message_id": "test",
        "sender": "alice",
        "recipient": "bob",
        "sequence": 1,
        "timestamp": 1,
        "message_type": "text",
        "payload": "SGVsbG8=",
    }

    with pytest.raises(ValueError):
        Message.from_dict(message)
