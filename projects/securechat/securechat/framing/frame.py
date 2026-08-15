"""Transport-independent SecureChat wire frames.

Frames carry authenticated encrypted application payloads.
This layer performs serialization and structural validation only.

Tor, SOCKS5, sockets, handshakes, and cryptographic primitives
remain in their respective layers.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum


FRAME_VERSION = 1


class FrameType(str, Enum):
    DATA = "data"
    CLOSE = "close"


@dataclass(frozen=True)
class Frame:
    """A serialized SecureChat wire frame."""

    version: int
    frame_type: FrameType
    peer_id: str
    sequence: int
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        """Serialize the frame deterministically."""

        if not isinstance(self.version, int):
            raise TypeError("version must be an integer")

        if not isinstance(self.peer_id, str):
            raise TypeError("peer_id must be a string")

        if not isinstance(self.sequence, int):
            raise TypeError("sequence must be an integer")

        if self.sequence < 0:
            raise ValueError("sequence cannot be negative")

        if not isinstance(self.ciphertext, bytes):
            raise TypeError("ciphertext must be bytes")

        value = {
            "version": self.version,
            "frame_type": self.frame_type.value,
            "peer_id": self.peer_id,
            "sequence": self.sequence,
            "ciphertext": self.ciphertext.hex(),
        }

        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "Frame":
        """Deserialize and validate a wire frame."""

        if not isinstance(data, bytes):
            raise TypeError("frame data must be bytes")

        try:
            value = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid frame encoding") from exc

        if not isinstance(value, dict):
            raise ValueError("frame must be an object")

        required = {
            "version",
            "frame_type",
            "peer_id",
            "sequence",
            "ciphertext",
        }

        missing = required - value.keys()

        if missing:
            raise ValueError(
                f"missing frame fields: {sorted(missing)}"
            )

        if not isinstance(value["version"], int):
            raise ValueError("frame version must be an integer")

        if not isinstance(value["peer_id"], str):
            raise ValueError("peer_id must be a string")

        if not isinstance(value["sequence"], int):
            raise ValueError("sequence must be an integer")

        if value["sequence"] < 0:
            raise ValueError("sequence cannot be negative")

        try:
            frame_type = FrameType(value["frame_type"])
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid frame type") from exc

        try:
            ciphertext = bytes.fromhex(value["ciphertext"])
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid ciphertext encoding") from exc

        return cls(
            version=value["version"],
            frame_type=frame_type,
            peer_id=value["peer_id"],
            sequence=value["sequence"],
            ciphertext=ciphertext,
        )
