# SecureChat Peer Layer

The peer layer binds a remote application identity to its expected onion endpoint.

## Architecture

```text
Application / ChatService
          |
          v
+------------------------+
| EncryptedPeer          |
|------------------------|
| Identity               |
| OnionEndpoint          |
| PeerState              |
| outbound sequence      |
| inbound replay state   |
+-----------+------------+
            |
            v
     SecureChatSession
            |
            v
      OnionTransport
            |
          SOCKS5
            |
           Tor
```

## Security Boundary

The peer layer does not implement cryptographic primitives or network transport.

Authenticated encryption must be performed by the cryptographic/session layer before inbound sequence numbers are accepted.

The peer layer provides identity-to-endpoint binding and basic replay/order protection.

Authenticated peer integration tests:
- binds the wire handshake to EncryptedPeer
- verifies the expected remote identity
- verifies the responder role
- verifies the shared handshake nonce
- verifies the remote identity signature
- derives the X25519 session key only after authentication
- exposes the session key only in AUTHENTICATED state
- keeps Tor, SOCKS5, sockets, and transport code outside the peer layer
