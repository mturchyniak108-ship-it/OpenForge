"""Authenticated encrypted peer model for SecureChat.

This layer binds a remote application identity to its expected onion
endpoint and manages an authenticated ephemeral encryption session.

Networking remains outside this layer. Tor, SOCKS5, sockets, and
transport implementations are deliberately not handled here.
"""

from __future__ import annotations

from enum import Enum

from nacl.exceptions import CryptoError
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey

from securechat.crypto import decrypt, encrypt
from securechat.framing import FRAME_VERSION, Frame, FrameType
from securechat.identity import Identity
from securechat.kex import generate_private_key
from securechat.kex_auth import (
    establish_authenticated_session_key,
    generate_signed_ephemeral_key,
)
from securechat.transport import OnionEndpoint


class PeerState(str, Enum):
    UNKNOWN = "unknown"
    CONNECTED = "connected"
    CLOSED = "closed"
    REVOKED = "revoked"


class EncryptedPeer:
    """Application-level representation of an authenticated peer."""

    def __init__(
        self,
        identity: Identity,
        endpoint: OnionEndpoint,
        *,
        local_identity: Identity | None = None,
        signing_key: SigningKey | None = None,
    ) -> None:
        # ``identity`` is the remote identity this peer binding expects.
        # ``local_identity`` is the identity that owns outbound frames.
        #
        # When omitted, preserve the original single-peer behavior where
        # the supplied identity is also treated as the local identity.
        self.identity = identity
        self.local_identity = local_identity or identity
        self.endpoint = endpoint
        self.state = PeerState.UNKNOWN

        self._last_received_sequence = -1
        self._next_outbound_sequence = 0

        self._signing_key = signing_key
        self._session_key: bytes | None = None
        self._ephemeral_private_key: bytes | None = None
        self._ephemeral_public_key: bytes | None = None

    @property
    def peer_id(self) -> str:
        """Return the stable remote identity identifier."""
        return self.identity.identity_id

    @property
    def display_name(self) -> str:
        """Return the remote display name."""
        return self.identity.display_name

    @property
    def next_outbound_sequence(self) -> int:
        """Return the next sequence number available for sending."""
        return self._next_outbound_sequence

    @property
    def last_received_sequence(self) -> int:
        """Return the highest accepted inbound sequence number."""
        return self._last_received_sequence

    @property
    def authenticated(self) -> bool:
        """Return whether an authenticated encryption session exists."""
        return self._session_key is not None

    def mark_connected(self) -> None:
        """Mark the peer as connected."""
        if self.state == PeerState.REVOKED:
            raise RuntimeError("revoked peer cannot connect")

        self.state = PeerState.CONNECTED

    def mark_closed(self) -> None:
        """Mark the peer as closed and discard session key material."""
        if self.state != PeerState.REVOKED:
            self.state = PeerState.CLOSED

        self._session_key = None
        self._ephemeral_private_key = None
        self._ephemeral_public_key = None

    def revoke(self) -> None:
        """Permanently revoke this peer object."""
        self.state = PeerState.REVOKED
        self._session_key = None
        self._ephemeral_private_key = None
        self._ephemeral_public_key = None

    def allocate_outbound_sequence(self) -> int:
        """Allocate the next outbound sequence number."""
        if self.state == PeerState.REVOKED:
            raise RuntimeError("revoked peer cannot send")

        sequence = self._next_outbound_sequence
        self._next_outbound_sequence += 1
        return sequence

    def accept_inbound_sequence(self, sequence: int) -> None:
        """Accept a strictly newer inbound sequence number."""
        if not isinstance(sequence, int):
            raise TypeError("sequence must be an integer")

        if sequence < 0:
            raise ValueError("sequence cannot be negative")

        if sequence <= self._last_received_sequence:
            raise ValueError("replayed or out-of-order sequence")

        self._last_received_sequence = sequence

    def begin_key_exchange(
        self,
        signing_key: SigningKey,
    ) -> tuple[bytes, bytes]:
        """Create this peer's fresh signed ephemeral X25519 key."""

        if self.state == PeerState.REVOKED:
            raise RuntimeError("revoked peer cannot perform key exchange")

        self._signing_key = signing_key
        self._ephemeral_private_key = generate_private_key()

        public_key, signature = generate_signed_ephemeral_key(
            signing_key,
            self._ephemeral_private_key,
        )

        self._ephemeral_public_key = public_key

        return public_key, signature

    def complete_key_exchange(
        self,
        peer_ephemeral_public_key: bytes,
        peer_signature: bytes,
        peer_verify_key: VerifyKey,
    ) -> bytes:
        """Authenticate the remote ephemeral key and derive a session key."""

        if self.state == PeerState.REVOKED:
            raise RuntimeError("revoked peer cannot perform key exchange")

        if self._ephemeral_private_key is None:
            raise RuntimeError(
                "local key exchange has not been started"
            )

        session_key = establish_authenticated_session_key(
            self._ephemeral_private_key,
            peer_ephemeral_public_key,
            peer_verify_key,
            peer_signature,
        )

        self._session_key = session_key
        self.state = PeerState.CONNECTED

        return session_key

    def authenticate(
        self,
        signing_key: SigningKey,
        peer_ephemeral_public_key: bytes,
        peer_signature: bytes,
        peer_verify_key: VerifyKey,
    ) -> bytes:
        """Authenticate a peer's ephemeral key and establish a session.

        The local ephemeral key exchange must be started first with
        ``begin_key_exchange``. Authentication succeeds only when the
        remote ephemeral public key is signed by the expected identity.
        """
        return self.complete_key_exchange(
            peer_ephemeral_public_key,
            peer_signature,
            peer_verify_key,
        )

    def frame_message(
        self,
        plaintext: bytes,
        *,
        frame_type: FrameType = FrameType.DATA,
    ) -> Frame:
        """Encrypt plaintext and wrap it in an authenticated wire frame."""

        if not self.authenticated:
            raise RuntimeError(
                "peer does not have an authenticated session"
            )

        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")

        if not isinstance(frame_type, FrameType):
            raise TypeError("frame_type must be a FrameType")

        sequence = self.allocate_outbound_sequence()
        ciphertext = self.encrypt(plaintext)

        return Frame(
            version=FRAME_VERSION,
            frame_type=frame_type,
            peer_id=self.local_identity.identity_id,
            sequence=sequence,
            ciphertext=ciphertext,
        )

    def receive_frame(self, frame: Frame) -> bytes:
        """Validate, sequence-check, and decrypt an inbound wire frame."""

        if not self.authenticated:
            raise RuntimeError(
                "peer does not have an authenticated session"
            )

        if not isinstance(frame, Frame):
            raise TypeError("frame must be a Frame")

        if frame.version != FRAME_VERSION:
            raise ValueError("unsupported frame version")

        if frame.peer_id != self.peer_id:
            raise ValueError("frame peer identity mismatch")

        self.accept_inbound_sequence(frame.sequence)

        return self.decrypt(frame.ciphertext)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext using the authenticated session key."""

        if self.state != PeerState.CONNECTED:
            raise RuntimeError("peer does not have an authenticated session")

        if self._session_key is None:
            raise RuntimeError(
                "peer has no authenticated session key"
            )

        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")

        return encrypt(self._session_key, plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt and authenticate ciphertext."""

        if self.state != PeerState.CONNECTED:
            raise RuntimeError("peer does not have an authenticated session")

        if self._session_key is None:
            raise RuntimeError(
                "peer has no authenticated session key"
            )

        if not isinstance(ciphertext, bytes):
            raise TypeError("ciphertext must be bytes")

        return decrypt(self._session_key, ciphertext)

    def to_dict(self) -> dict[str, object]:
        """Return non-secret peer metadata."""

        return {
            "identity": self.identity.to_dict(),
            "endpoint": {
                "host": self.endpoint.host,
                "port": self.endpoint.port,
            },
            "state": self.state.value,
            "authenticated": self.authenticated,
            "last_received_sequence": (
                self._last_received_sequence
            ),
            "next_outbound_sequence": (
                self._next_outbound_sequence
            ),
        }
