# SecureChat Identity Layer

The identity layer represents a SecureChat participant at the application level.

## Responsibilities

- Generate stable public identity IDs.
- Store a validated display name.
- Serialize and restore public identity information.
- Provide an identity object independent of networking and transports.

## Architecture

```text
Application / UI
       |
       v
+------------------+
| Identity         |
|------------------|
| identity_id      |
| display_name     |
| create()         |
| to_dict()        |
| from_dict()      |
+------------------+
       |
       v
 ChatService
       |
       v
 SecureChatSession
```

## Security Boundary

This layer does not contain private keys, cryptographic primitives, Tor configuration, SOCKS5 configuration, or network code.
