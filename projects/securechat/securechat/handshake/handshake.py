"""Versioned authenticated SecureChat wire handshake."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum

from nacl.signing import SigningKey, VerifyKey

from securechat.identity import Identity
from securechat.kex import generate_private_key, public_key
from securechat.kex_auth import KEX_CONTEXT


HANDSHAKE_VERSION = 1


class HandshakeRole(str, Enum):
    INITIATOR = "initiator"
    RESPONDER = "responder"


@dataclass(frozen=True)
class HandshakeMessage:
    """Public authenticated handshake message."""

    version: int
    role: HandshakeRole
    identity_id: str
    ephemeral_public_key: bytes
    signature: bytes
    nonce: bytes

    def to_bytes(self) -> bytes:
        value = {
            "version": self.version,
            "role": self.role.value,
            "identity_id": self.identity_id,
            "ephemeral_public_key": self.ephemeral_public_key.hex(),
            "signature": self.signature.hex(),
            "nonce": self.nonce.hex(),
        }

        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "HandshakeMessage":
        if not isinstance(data, bytes):
            raise TypeError("handshake data must be bytes")

        try:
            value = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid handshake encoding") from exc

        if not isinstance(value, dict):
            raise ValueError("handshake must be an object")

        required = {
            "version",
            "role",
            "identity_id",
            "ephemeral_public_key",
            "signature",
            "nonce",
        }

        missing = required - value.keys()

        if missing:
            raise ValueError(
                f"missing handshake fields: {sorted(missing)}"
            )

        try:
            role = HandshakeRole(value["role"])
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid handshake role") from exc

        try:
            ephemeral_public_key = bytes.fromhex(
                value["ephemeral_public_key"]
            )
            signature = bytes.fromhex(value["signature"])
            nonce = bytes.fromhex(value["nonce"])
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid handshake binary field") from exc

        if not isinstance(value["version"], int):
            raise ValueError("handshake version must be an integer")

        if not isinstance(value["identity_id"], str):
            raise ValueError("identity_id must be a string")

        if len(ephemeral_public_key) != 32:
            raise ValueError(
                "ephemeral public key must be exactly 32 bytes"
            )

        if len(signature) != 64:
            raise ValueError(
                "signature must be exactly 64 bytes"
            )

        if len(nonce) != 32:
            raise ValueError(
                "nonce must be exactly 32 bytes"
            )

        return cls(
            version=value["version"],
            role=role,
            identity_id=value["identity_id"],
            ephemeral_public_key=ephemeral_public_key,
            signature=signature,
            nonce=nonce,
        )


def create_handshake(
    identity: Identity,
    signing_key: SigningKey,
    *,
    role: HandshakeRole,
    nonce: bytes,
    ephemeral_private_key: bytes | None = None,
) -> tuple[HandshakeMessage, bytes]:
    """Create a signed handshake and return its ephemeral private key."""

    if not isinstance(nonce, bytes):
        raise TypeError("nonce must be bytes")

    if len(nonce) != 32:
        raise ValueError("nonce must be exactly 32 bytes")

    if ephemeral_private_key is None:
        ephemeral_private_key = generate_private_key()

    ephemeral_public_key = public_key(ephemeral_private_key)

    transcript = _transcript(
        version=HANDSHAKE_VERSION,
        role=role,
        identity_id=identity.identity_id,
        ephemeral_public_key=ephemeral_public_key,
        nonce=nonce,
    )

    signature = signing_key.sign(transcript).signature

    return (
        HandshakeMessage(
            version=HANDSHAKE_VERSION,
            role=role,
            identity_id=identity.identity_id,
            ephemeral_public_key=ephemeral_public_key,
            signature=signature,
            nonce=nonce,
        ),
        ephemeral_private_key,
    )


def verify_handshake(
    message: HandshakeMessage,
    identity: Identity,
    verify_key: VerifyKey,
    *,
    expected_role: HandshakeRole | None = None,
    expected_nonce: bytes | None = None,
) -> bool:
    """Verify an authenticated handshake message."""

    if message.version != HANDSHAKE_VERSION:
        return False

    if message.identity_id != identity.identity_id:
        return False

    if expected_role is not None and message.role != expected_role:
        return False

    if expected_nonce is not None and message.nonce != expected_nonce:
        return False

    transcript = _transcript(
        version=message.version,
        role=message.role,
        identity_id=message.identity_id,
        ephemeral_public_key=message.ephemeral_public_key,
        nonce=message.nonce,
    )

    try:
        verify_key.verify(transcript, message.signature)
    except Exception:
        return False

    return True


def _transcript(
    *,
    version: int,
    role: HandshakeRole,
    identity_id: str,
    ephemeral_public_key: bytes,
    nonce: bytes,
) -> bytes:
    """Build the canonical signed handshake transcript."""

    value = {
        "context": KEX_CONTEXT.hex(),
        "version": version,
        "role": role.value,
        "identity_id": identity_id,
        "ephemeral_public_key": ephemeral_public_key.hex(),
        "nonce": nonce.hex(),
    }

    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(encoded).digest()
