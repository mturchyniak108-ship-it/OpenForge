"""SecureChat protocol message definitions."""

from __future__ import annotations

from dataclasses import dataclass
import base64
import json
import uuid


PROTOCOL_VERSION = 1


@dataclass(frozen=True)
class Message:
    """A transport-independent SecureChat protocol message."""

    message_id: str
    sender: str
    recipient: str
    sequence: int
    timestamp: int
    message_type: str
    payload: bytes
    version: int = PROTOCOL_VERSION

    @classmethod
    def create(
        cls,
        sender: str,
        recipient: str,
        sequence: int,
        timestamp: int,
        message_type: str,
        payload: bytes,
    ) -> "Message":
        return cls(
            message_id=str(uuid.uuid4()),
            sender=sender,
            recipient=recipient,
            sequence=sequence,
            timestamp=timestamp,
            message_type=message_type,
            payload=payload,
        )

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "message_id": self.message_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "message_type": self.message_type,
            "payload": base64.b64encode(self.payload).decode("ascii"),
        }

    def to_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def from_dict(cls, value: dict) -> "Message":
        required = {
            "version",
            "message_id",
            "sender",
            "recipient",
            "sequence",
            "timestamp",
            "message_type",
            "payload",
        }

        missing = required - value.keys()
        if missing:
            raise ValueError(f"missing message fields: {sorted(missing)}")

        if value["version"] != PROTOCOL_VERSION:
            raise ValueError(
                f"unsupported protocol version: {value['version']}"
            )

        return cls(
            version=value["version"],
            message_id=value["message_id"],
            sender=value["sender"],
            recipient=value["recipient"],
            sequence=int(value["sequence"]),
            timestamp=int(value["timestamp"]),
            message_type=value["message_type"],
            payload=base64.b64decode(value["payload"], validate=True),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "Message":
        try:
            value = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid message encoding") from exc

        if not isinstance(value, dict):
            raise ValueError("message must be a JSON object")

        return cls.from_dict(value)
