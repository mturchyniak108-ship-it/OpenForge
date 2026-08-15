"""Real Tor onion-service integration test.

This test is intentionally opt-in and is not part of the normal pytest suite.
It verifies:

SecureChat client
    -> Tor SOCKS5
    -> real .onion service
    -> local TCP listener
    -> SecureChat framing
    -> echoed message
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow direct execution with: python tests/test_real_onion.py
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import os
import socket
import threading
import time

from securechat.protocol import Message, encode_frame, decode_frame
from securechat.transport import OnionEndpoint, OnionTransport, TorProxy


ONION_DIR = os.environ.get(
    "SECURECHAT_ONION_DIR",
    os.path.expanduser(
        "~/../usr/var/lib/tor/securechat"
    ),
)

# Termux absolute fallback.
if not os.path.isdir(ONION_DIR):
    ONION_DIR = "/data/data/com.termux/files/usr/var/lib/tor/securechat"

HOSTNAME_FILE = os.path.join(ONION_DIR, "hostname")

with open(HOSTNAME_FILE, "r", encoding="utf-8") as f:
    ONION = f.read().strip()


def read_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()

    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("connection closed while reading frame")

        data.extend(chunk)

    return bytes(data)


def local_server(ready: threading.Event, result: dict) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 9000))
    server.listen(1)

    result["port"] = 9000
    ready.set()

    conn, address = server.accept()

    try:
        result["peer"] = address

        header = read_exact(conn, 4)
        length = int.from_bytes(header, "big")

        if length > 1024 * 1024:
            raise RuntimeError("frame too large")

        payload = read_exact(conn, length)
        frame = header + payload

        message = decode_frame(frame)

        result["message"] = message

        # Echo the exact SecureChat frame back.
        conn.sendall(frame)

    finally:
        conn.close()
        server.close()


print("===== REAL TOR ONION TEST =====")
print(f"Onion: {ONION}")
print("Local service: 127.0.0.1:9000")
print("SOCKS5: 127.0.0.1:9050")
print()

ready = threading.Event()
result: dict = {}

thread = threading.Thread(
    target=local_server,
    args=(ready, result),
    daemon=True,
)

thread.start()

if not ready.wait(timeout=3):
    raise RuntimeError("local onion service listener did not start")

# Give Tor's hidden-service listener a moment to be usable.
time.sleep(1)

endpoint = OnionEndpoint(ONION, 9000)
transport = OnionTransport(
    endpoint,
    TorProxy("127.0.0.1", 9050),
)

message = Message.create(
    sender="securechat-test-client",
    recipient="securechat-test-service",
    sequence=1,
    timestamp=int(time.time()),
    message_type="chat",
    payload=b"real onion transport test",
)

print("Connecting through Tor...")
sock = transport.connect()

try:
    print("Connected.")

    transport.send(sock, message)
    print("Frame sent.")

    received = transport.receive(sock)
    print("Frame received.")

    assert received == message
    assert received.payload == b"real onion transport test"

    assert result.get("message") == message

    print()
    print("===== RESULT =====")
    print("Tor SOCKS5: OK")
    print("Onion routing: OK")
    print("Hidden service: OK")
    print("TCP forwarding: OK")
    print("SecureChat framing: OK")
    print("Message round-trip: OK")
    print()
    print("REAL TOR ONION END-TO-END: PASS")

finally:
    transport.close()
    thread.join(timeout=3)
