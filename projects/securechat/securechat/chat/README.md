# SecureChat Chat Service

The chat service is the application-level API above SecureChatSession.

```text
Browser UI / Application
          |
          v
     ChatService
          |
          v
  SecureChatSession
          |
          v
    Transport API
       /       \
      v         v
   Local      Onion
                  |
                SOCKS5
                  |
                 Tor
                  |
             .onion service
```

## Responsibilities

- sender identity
- recipient identity
- outbound sequence numbers
- text message construction
- UTF-8 encoding and decoding
- application-level message validation

## Non-responsibilities

The service does not implement TCP, SOCKS5, Tor, onion routing, cryptographic primitives, HTML, CSS, or browser APIs.
