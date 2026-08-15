import pytest

from nacl.exceptions import CryptoError
from nacl.signing import SigningKey

from securechat.identity import Identity
from securechat.framing import FRAME_VERSION, Frame, FrameType
from securechat.kex import generate_private_key
from securechat.kex_auth import generate_signed_ephemeral_key
from securechat.peer import EncryptedPeer, PeerState
from securechat.transport import OnionEndpoint


ONION = (
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
)


def make_peer():
    identity = Identity.create("Bob")
    endpoint = OnionEndpoint(ONION, 9000)
    return EncryptedPeer(identity, endpoint)


def test_peer_initial_state():
    peer = make_peer()

    assert peer.state == PeerState.UNKNOWN
    assert peer.display_name == "Bob"
    assert peer.endpoint.address == (ONION, 9000)
    assert not peer.authenticated


def test_peer_id_matches_identity():
    peer = make_peer()

    assert peer.peer_id == peer.identity.identity_id


def test_mark_connected():
    peer = make_peer()

    peer.mark_connected()

    assert peer.state == PeerState.CONNECTED


def test_mark_closed():
    peer = make_peer()

    peer.mark_connected()
    peer.mark_closed()

    assert peer.state == PeerState.CLOSED
    assert not peer.authenticated


def test_revoke():
    peer = make_peer()

    peer.revoke()

    assert peer.state == PeerState.REVOKED
    assert not peer.authenticated


def test_revoked_peer_cannot_connect():
    peer = make_peer()

    peer.revoke()

    with pytest.raises(RuntimeError, match="revoked"):
        peer.mark_connected()


def test_outbound_sequences_increment():
    peer = make_peer()

    assert peer.next_outbound_sequence == 0
    assert peer.allocate_outbound_sequence() == 0
    assert peer.allocate_outbound_sequence() == 1
    assert peer.allocate_outbound_sequence() == 2
    assert peer.next_outbound_sequence == 3


def test_revoked_peer_cannot_allocate_sequence():
    peer = make_peer()

    peer.revoke()

    with pytest.raises(RuntimeError, match="revoked"):
        peer.allocate_outbound_sequence()


def test_inbound_sequence_accepts_newer_values():
    peer = make_peer()

    peer.accept_inbound_sequence(0)
    peer.accept_inbound_sequence(1)
    peer.accept_inbound_sequence(5)

    assert peer.last_received_sequence == 5


def test_inbound_sequence_rejects_replay():
    peer = make_peer()

    peer.accept_inbound_sequence(3)

    with pytest.raises(ValueError, match="replayed"):
        peer.accept_inbound_sequence(3)


def test_inbound_sequence_rejects_old_sequence():
    peer = make_peer()

    peer.accept_inbound_sequence(5)

    with pytest.raises(ValueError, match="replayed"):
        peer.accept_inbound_sequence(2)


def test_inbound_sequence_rejects_negative():
    peer = make_peer()

    with pytest.raises(ValueError, match="negative"):
        peer.accept_inbound_sequence(-1)


def test_inbound_sequence_requires_integer():
    peer = make_peer()

    with pytest.raises(TypeError, match="integer"):
        peer.accept_inbound_sequence("1")


def test_authenticated_key_exchange():
    alice_identity_key = SigningKey.generate()
    bob_identity_key = SigningKey.generate()

    alice = EncryptedPeer(
        Identity.create("Alice"),
        OnionEndpoint(ONION, 9000),
        signing_key=alice_identity_key,
    )

    bob = EncryptedPeer(
        Identity.create("Bob"),
        OnionEndpoint(ONION, 9001),
        signing_key=bob_identity_key,
    )

    alice_public, alice_signature = alice.begin_key_exchange(
        alice_identity_key
    )

    bob_public, bob_signature = bob.begin_key_exchange(
        bob_identity_key
    )

    alice_key = alice.complete_key_exchange(
        bob_public,
        bob_signature,
        bob_identity_key.verify_key,
    )

    bob_key = bob.complete_key_exchange(
        alice_public,
        alice_signature,
        alice_identity_key.verify_key,
    )

    assert alice_key == bob_key
    assert alice.authenticated
    assert bob.authenticated
    assert alice.state == PeerState.CONNECTED
    assert bob.state == PeerState.CONNECTED


def test_authenticated_peer_can_encrypt_and_decrypt():
    alice_identity_key = SigningKey.generate()
    bob_identity_key = SigningKey.generate()

    alice = EncryptedPeer(
        Identity.create("Alice"),
        OnionEndpoint(ONION, 9000),
    )

    bob = EncryptedPeer(
        Identity.create("Bob"),
        OnionEndpoint(ONION, 9001),
    )

    alice_public, alice_signature = (
        alice.begin_key_exchange(alice_identity_key)
    )

    bob_public, bob_signature = (
        bob.begin_key_exchange(bob_identity_key)
    )

    alice.complete_key_exchange(
        bob_public,
        bob_signature,
        bob_identity_key.verify_key,
    )

    bob.complete_key_exchange(
        alice_public,
        alice_signature,
        alice_identity_key.verify_key,
    )

    ciphertext = alice.encrypt(b"hello through authenticated peer")

    assert ciphertext != b"hello through authenticated peer"
    assert bob.decrypt(ciphertext) == (
        b"hello through authenticated peer"
    )


def test_tampered_ciphertext_is_rejected():
    alice_identity_key = SigningKey.generate()
    bob_identity_key = SigningKey.generate()

    alice = EncryptedPeer(
        Identity.create("Alice"),
        OnionEndpoint(ONION, 9000),
    )

    bob = EncryptedPeer(
        Identity.create("Bob"),
        OnionEndpoint(ONION, 9001),
    )

    alice_public, alice_signature = (
        alice.begin_key_exchange(alice_identity_key)
    )

    bob_public, bob_signature = (
        bob.begin_key_exchange(bob_identity_key)
    )

    alice.complete_key_exchange(
        bob_public,
        bob_signature,
        bob_identity_key.verify_key,
    )

    bob.complete_key_exchange(
        alice_public,
        alice_signature,
        alice_identity_key.verify_key,
    )

    ciphertext = bytearray(alice.encrypt(b"authenticated"))

    ciphertext[-1] ^= 1

    with pytest.raises(CryptoError):
        bob.decrypt(bytes(ciphertext))


def test_wrong_identity_cannot_complete_key_exchange():
    alice_identity_key = SigningKey.generate()
    bob_identity_key = SigningKey.generate()
    mallory_identity_key = SigningKey.generate()

    alice = make_peer()

    bob_private = generate_private_key()

    bob_public, bob_signature = generate_signed_ephemeral_key(
        bob_identity_key,
        bob_private,
    )

    alice.begin_key_exchange(alice_identity_key)

    with pytest.raises(
        ValueError,
        match="authentication failed",
    ):
        alice.complete_key_exchange(
            bob_public,
            bob_signature,
            mallory_identity_key.verify_key,
        )


def test_encrypt_requires_authenticated_session():
    peer = make_peer()

    with pytest.raises(RuntimeError, match="authenticated"):
        peer.encrypt(b"secret")


def test_decrypt_requires_authenticated_session():
    peer = make_peer()

    with pytest.raises(RuntimeError, match="authenticated"):
        peer.decrypt(b"ciphertext")


def test_peer_metadata_contains_no_private_material():
    peer = make_peer()

    metadata = peer.to_dict()

    assert metadata["identity"]["identity_id"] == peer.peer_id
    assert metadata["identity"]["display_name"] == "Bob"
    assert metadata["endpoint"]["host"] == ONION
    assert metadata["endpoint"]["port"] == 9000
    assert "private_key" not in str(metadata).lower()
    assert "secret_key" not in str(metadata).lower()
    assert "session_key" not in str(metadata).lower()


def test_peer_is_independent_of_transport_implementation():
    peer = make_peer()

    assert not hasattr(peer, "sock")
    assert not hasattr(peer, "socket")
    assert not hasattr(peer, "tor")
    assert not hasattr(peer, "socks5")


def test_frame_message_requires_authentication():
    peer = make_peer()

    with pytest.raises(RuntimeError, match="authenticated"):
        peer.frame_message(b"hello")


def test_receive_frame_requires_authentication():
    peer = make_peer()
    frame = Frame(
        version=FRAME_VERSION,
        frame_type=FrameType.DATA,
        peer_id=peer.peer_id,
        sequence=0,
        ciphertext=b"x",
    )

    with pytest.raises(RuntimeError, match="authenticated"):
        peer.receive_frame(frame)


def test_authenticated_peer_frames_message():
    alice_identity_key = SigningKey.generate()
    bob_identity_key = SigningKey.generate()

    alice_identity = Identity.create("Alice")
    bob_identity = Identity.create("Bob")

    alice = EncryptedPeer(
        alice_identity,
        OnionEndpoint(ONION, 9000),
    )
    bob = EncryptedPeer(
        bob_identity,
        OnionEndpoint(ONION, 9001),
    )

    alice_public, alice_signature = alice.begin_key_exchange(
        alice_identity_key
    )
    bob_public, bob_signature = bob.begin_key_exchange(
        bob_identity_key
    )

    alice.authenticate(
        alice_identity_key,
        bob_public,
        bob_signature,
        bob_identity_key.verify_key,
    )
    bob.authenticate(
        bob_identity_key,
        alice_public,
        alice_signature,
        alice_identity_key.verify_key,
    )

    frame = alice.frame_message(b"hello framed world")

    assert isinstance(frame, Frame)
    assert frame.version == FRAME_VERSION
    assert frame.frame_type == FrameType.DATA
    assert frame.peer_id == alice.peer_id
    assert frame.sequence == 0
    assert frame.ciphertext != b"hello framed world"


def test_authenticated_frame_round_trip():
    alice_identity_key = SigningKey.generate()
    bob_identity_key = SigningKey.generate()

    alice = EncryptedPeer(
        Identity.create("Alice"),
        OnionEndpoint(ONION, 9000),
    )
    bob = EncryptedPeer(
        Identity.create("Bob"),
        OnionEndpoint(ONION, 9001),
    )

    alice_public, alice_signature = alice.begin_key_exchange(
        alice_identity_key
    )
    bob_public, bob_signature = bob.begin_key_exchange(
        bob_identity_key
    )

    alice.authenticate(
        alice_identity_key,
        bob_public,
        bob_signature,
        bob_identity_key.verify_key,
    )
    bob.authenticate(
        bob_identity_key,
        alice_public,
        alice_signature,
        alice_identity_key.verify_key,
    )

    # The peer model represents the remote identity. For a real
    # bidirectional connection, construct the corresponding peer
    # bindings in each direction.
    frame = alice.frame_message(b"hello")

    assert frame.peer_id == alice.peer_id

    wire = frame.to_bytes()
    restored = Frame.from_bytes(wire)

    assert restored == frame


def test_frame_sequences_increment():
    identity_key = SigningKey.generate()
    peer = EncryptedPeer(
        Identity.create("Bob"),
        OnionEndpoint(ONION, 9000),
    )

    remote_key = SigningKey.generate()
    remote_public, remote_signature = peer.begin_key_exchange(
        identity_key
    )

    peer.authenticate(
        identity_key,
        remote_public,
        remote_signature,
        identity_key.verify_key,
    )

    first = peer.frame_message(b"one")
    second = peer.frame_message(b"two")

    assert first.sequence == 0
    assert second.sequence == 1
    assert peer.next_outbound_sequence == 2


def test_receive_frame_rejects_wrong_peer_identity():
    alice_identity_key = SigningKey.generate()
    bob_identity_key = SigningKey.generate()

    alice = EncryptedPeer(
        Identity.create("Alice"),
        OnionEndpoint(ONION, 9000),
    )
    bob = EncryptedPeer(
        Identity.create("Bob"),
        OnionEndpoint(ONION, 9001),
    )

    alice_public, alice_signature = alice.begin_key_exchange(
        alice_identity_key
    )
    bob_public, bob_signature = bob.begin_key_exchange(
        bob_identity_key
    )

    alice.authenticate(
        alice_identity_key,
        bob_public,
        bob_signature,
        bob_identity_key.verify_key,
    )
    bob.authenticate(
        bob_identity_key,
        alice_public,
        alice_signature,
        alice_identity_key.verify_key,
    )

    frame = alice.frame_message(b"hello")

    tampered = Frame(
        version=frame.version,
        frame_type=frame.frame_type,
        peer_id=bob.peer_id,
        sequence=frame.sequence,
        ciphertext=frame.ciphertext,
    )

    with pytest.raises(ValueError, match="identity mismatch"):
        alice.receive_frame(tampered)


def test_receive_frame_rejects_replay():
    alice_identity_key = SigningKey.generate()
    bob_identity_key = SigningKey.generate()

    alice_identity = Identity.create("Alice")
    bob_identity = Identity.create("Bob")

    # Each EncryptedPeer represents the remote identity it expects.
    # Therefore Alice's peer binding represents Bob, and Bob's
    # peer binding represents Alice.
    alice = EncryptedPeer(
        bob_identity,
        OnionEndpoint(ONION, 9001),
        local_identity=alice_identity,
    )
    bob = EncryptedPeer(
        alice_identity,
        OnionEndpoint(ONION, 9000),
        local_identity=bob_identity,
    )

    alice_public, alice_signature = alice.begin_key_exchange(
        alice_identity_key
    )
    bob_public, bob_signature = bob.begin_key_exchange(
        bob_identity_key
    )

    alice.authenticate(
        bob_identity_key,
        bob_public,
        bob_signature,
        bob_identity_key.verify_key,
    )
    bob.authenticate(
        alice_identity_key,
        alice_public,
        alice_signature,
        alice_identity_key.verify_key,
    )

    frame = bob.frame_message(b"hello")

    # First delivery is valid.
    assert alice.receive_frame(frame) == b"hello"

    # Replaying the exact same frame must be rejected.
    with pytest.raises(ValueError, match="replayed"):
        alice.receive_frame(frame)

def test_receive_frame_rejects_wrong_version():
    identity_key = SigningKey.generate()
    peer = EncryptedPeer(
        Identity.create("Bob"),
        OnionEndpoint(ONION, 9000),
    )

    remote_key = SigningKey.generate()
    public_key, signature = peer.begin_key_exchange(identity_key)

    peer.authenticate(
        identity_key,
        public_key,
        signature,
        identity_key.verify_key,
    )

    frame = peer.frame_message(b"hello")

    tampered = Frame(
        version=FRAME_VERSION + 1,
        frame_type=frame.frame_type,
        peer_id=frame.peer_id,
        sequence=frame.sequence,
        ciphertext=frame.ciphertext,
    )

    with pytest.raises(ValueError, match="version"):
        peer.receive_frame(tampered)


def test_receive_frame_decrypts_authenticated_ciphertext():
    identity_key = SigningKey.generate()
    peer = EncryptedPeer(
        Identity.create("Bob"),
        OnionEndpoint(ONION, 9000),
    )

    remote_key = SigningKey.generate()
    public_key, signature = peer.begin_key_exchange(identity_key)

    peer.authenticate(
        identity_key,
        public_key,
        signature,
        identity_key.verify_key,
    )

    frame = peer.frame_message(b"secret framed message")

    # This exercises the frame -> sequence validation -> decrypt path.
    assert peer.receive_frame(frame) == b"secret framed message"
