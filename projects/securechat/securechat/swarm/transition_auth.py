"""Cryptographic authentication for SecureChat swarm transitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .transition import SwarmTransition


class TransitionSigner(Protocol):
    """Minimal signing interface required by the swarm layer."""

    def sign(self, data: bytes) -> bytes:
        """Return a cryptographic signature for data."""
        ...


class TransitionVerifier(Protocol):
    """Minimal verification interface required by the swarm layer."""

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Return True when signature authenticates data."""
        ...


@dataclass(frozen=True)
class AuthenticatedTransition:
    """A swarm transition authenticated by a signing authority."""

    transition: SwarmTransition
    signer_id: str
    signature: bytes

    def __post_init__(self) -> None:
        if not self.signer_id:
            raise ValueError("signer_id cannot be empty")

        if not isinstance(self.signature, bytes):
            raise TypeError("signature must be bytes")

    @property
    def transition_hash(self) -> str:
        """Return the deterministic hash of the underlying transition."""
        return self.transition.transition_hash()

    def signing_bytes(self) -> bytes:
        """
        Return the domain-separated canonical bytes that are signed.

        The transition itself contains all security-sensitive rotation
        metadata. The domain separator prevents accidental cross-protocol
        signature reuse.
        """
        return (
            b"securechat-swarm-transition-v1:"
            + self.transition.to_canonical_bytes()
        )

    @classmethod
    def sign(
        cls,
        *,
        transition: SwarmTransition,
        signer_id: str,
        signer: TransitionSigner,
    ) -> "AuthenticatedTransition":
        """Create an authenticated transition using an existing signer."""
        if not signer_id:
            raise ValueError("signer_id cannot be empty")

        signing_bytes = (
            b"securechat-swarm-transition-v1:"
            + transition.to_canonical_bytes()
        )

        signature = signer.sign(signing_bytes)

        if not isinstance(signature, bytes):
            raise TypeError("signer must return bytes")

        return cls(
            transition=transition,
            signer_id=signer_id,
            signature=signature,
        )

    def verify(self, verifier: TransitionVerifier) -> bool:
        """
        Verify the transition signature.

        Returns False for an invalid signature rather than raising, allowing
        callers to treat unauthenticated swarm metadata as untrusted input.
        """
        try:
            return bool(
                verifier.verify(
                    self.signing_bytes(),
                    self.signature,
                )
            )
        except Exception:
            return False


def sign_transition(
    *,
    transition: SwarmTransition,
    signer_id: str,
    signer: TransitionSigner,
) -> AuthenticatedTransition:
    """Sign a swarm transition with an existing SecureChat signer."""
    return AuthenticatedTransition.sign(
        transition=transition,
        signer_id=signer_id,
        signer=signer,
    )


def verify_transition(
    authenticated: AuthenticatedTransition,
    verifier: TransitionVerifier,
) -> bool:
    """Verify an authenticated swarm transition."""
    return authenticated.verify(verifier)
