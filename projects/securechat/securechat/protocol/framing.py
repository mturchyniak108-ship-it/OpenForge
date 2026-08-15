"""Length-prefixed framing for SecureChat messages."""

from __future__ import annotations

import struct

from .messages import Message


HEADER_SIZE = 4
MAX_FRAME_SIZE = 1024 * 1024


def encode_frame(message: Message) -> bytes:
    """Encode a message as a 4-byte big-endian length-prefixed frame."""
    payload = message.to_bytes()

    if len(payload) > MAX_FRAME_SIZE:
        raise ValueError("message exceeds maximum frame size")

    return struct.pack(">I", len(payload)) + payload


def decode_frame(frame: bytes) -> Message:
    """Decode exactly one complete frame."""
    if len(frame) < HEADER_SIZE:
        raise ValueError("incomplete frame header")

    length = struct.unpack(">I", frame[:HEADER_SIZE])[0]

    if length > MAX_FRAME_SIZE:
        raise ValueError("frame exceeds maximum size")

    if len(frame) != HEADER_SIZE + length:
        raise ValueError("incomplete or extra frame data")

    return Message.from_bytes(frame[HEADER_SIZE:])
