# SecureChat Session Layer

The SecureChat session layer provides the application-level connection lifecycle above the transport layer.

## Architecture

```text
Application / UI
       |
       v
+----------------------+
| SecureChatSession    |
|----------------------|
| connect()            |
| send()               |
| receive()            |
| close()              |
| SessionState         |
+----------+-----------+
           |
           v
+----------------------+
| Transport API        |
+----------+-----------+
           |
     +-----+------+
     |            |
     v            v
 LocalTransport  OnionTransport
                    |
                    v
                 SOCKS5
                    |
                    v
                   Tor
                    |
                    v
              .onion service
```

## Purpose

SecureChatSession separates application-level messaging from network transport.

The application does not need to know whether the connection uses local TCP, SOCKS5, Tor, or an onion service.

## Session States

```text
DISCONNECTED -> CONNECTED -> CLOSED
```

### DISCONNECTED

Initial state. No transport connection exists. send() and receive() are rejected.

### CONNECTED

The underlying transport connection is active. Messages may be sent and received.

### CLOSED

The transport connection has been released. Sending and receiving are rejected.

## API

```python
await session.connect()
await session.send(message)
message = await session.receive()
await session.close()
```

## Security Boundary

The session layer is not itself an encryption protocol.

End-to-end confidentiality and authentication belong to the SecureChat cryptographic layer.

Tor provides onion routing and network-path privacy. Tor does not replace end-to-end encryption.

## Transport Independence

The same session API can operate over LocalTransport or OnionTransport.

```python
local_session = SecureChatSession(local_transport)
onion_session = SecureChatSession(onion_transport)
```

## Current Responsibilities

- Session lifecycle
- Connection state
- Connect
- Send
- Receive
- Close
- Transport-independent message flow

## Future Work

- Peer authentication
- Session keys
- Replay protection
- Message sequencing
- Connection timeouts
- Transport failure handling
- Reconnection policy
- Graceful shutdown
- Peer identity
- Encrypted application messaging
- Real Tor onion session integration
- Local HTML/CSS interface

## UI Architecture

The browser should not connect directly to Tor or SOCKS5.

```text
Browser
  |
  | localhost HTTP/WebSocket
  v
SecureChat UI/API
  |
  v
SecureChatSession
  |
  v
Transport
  |
  +-- Local TCP
  |
  +-- Tor SOCKS5
          |
          v
         Tor
          |
          v
     .onion service
```

## Design Principle

The session layer coordinates state and message flow.

It should not contain Tor implementation, SOCKS5 implementation, HTML, CSS, browser-specific code, or cryptographic primitives.
