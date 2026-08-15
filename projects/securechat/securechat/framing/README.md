# SecureChat Wire Framing

The framing layer defines the transport-independent representation of
encrypted application messages.

A frame contains:

- protocol version
- frame type
- remote peer identity
- monotonically increasing sequence number
- authenticated ciphertext

The framing layer does **not** implement:

- Tor
- SOCKS5
- sockets
- network transport
- key exchange
- encryption primitives
- application routing

Those responsibilities remain in their respective layers.
