# SecureChat Authenticated Wire Handshake

The handshake layer defines the public protocol exchanged before
encrypted application data is accepted.

```text
SecureChatSession
       |
       v
+----------------------+
| HandshakeMessage     |
|----------------------|
| version              |
| role                 |
| identity_id          |
| ephemeral X25519 key |
| identity signature   |
| nonce                |
+----------+-----------+
           |
           v
Authenticated KEX
           |
           v
EncryptedPeer
           |
           v
SecretBox session
```

## Security Properties

- The identity signs the ephemeral X25519 public key.
- The signature is bound to the handshake role and nonce.
- The nonce prevents reuse of an old handshake transcript.
- The protocol version is authenticated.
- The ephemeral private key is never serialized into the wire message.
- Transport implementations remain outside this layer.

## Layer Boundary

```text
Application
    |
ChatService
    |
SecureChatSession
    |
Authenticated Handshake
    |
EncryptedPeer
    |
Authenticated KEX
    |
SecretBox
    |
OnionTransport
    |
SOCKS5 / Tor
```

The handshake layer does not implement Tor, SOCKS5, sockets, framing,
HTML, CSS, or browser-specific behavior.
