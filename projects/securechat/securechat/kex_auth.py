"""SecureChat authenticated ephemeral key exchange."""

from __future__ import annotations

import hashlib

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from securechat.kex import (
    establish_session_key,
    public_key,
)

KEX_CONTEXT = b"SecureChat authenticated session v1"


def generate_signed_ephemeral_key(
    signing_key: SigningKey,
    ephemeral_private_key: bytes,
) -> tuple[bytes, bytes]:
    """Create an ephemeral X25519 public key and sign its transcript."""

    ephemeral_public_key = public_key(ephemeral_private_key)

    transcript = hashlib.sha256(
        KEX_CONTEXT + ephemeral_public_key
    ).digest()

    signature = signing_key.sign(transcript).signature

    return ephemeral_public_key, signature


def verify_signed_ephemeral_key(
    verify_key: VerifyKey,
    ephemeral_public_key: bytes,
    signature: bytes,
) -> bool:
    """Verify that an ephemeral public key belongs to the identity."""

    transcript = hashlib.sha256(
        KEX_CONTEXT + ephemeral_public_key
    ).digest()

    try:
        verify_key.verify(transcript, signature)
    except BadSignatureError:
        return False

    return True


def establish_authenticated_session_key(
    ephemeral_private_key: bytes,
    peer_ephemeral_public_key: bytes,
    peer_verify_key: VerifyKey,
    peer_signature: bytes,
) -> bytes:
    """Verify the peer's ephemeral key and derive the session key."""

    if not verify_signed_ephemeral_key(
        peer_verify_key,
        peer_ephemeral_public_key,
        peer_signature,
    ):
        raise ValueError(
            "peer ephemeral key authentication failed"
        )

    return establish_session_key(
        ephemeral_private_key,
        peer_ephemeral_public_key,
        context=KEX_CONTEXT,
    )
