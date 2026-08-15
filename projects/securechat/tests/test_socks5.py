import socket
import threading

import pytest

from securechat.transport.socks5 import Socks5Connection, Socks5Error


class FakeSocks5Server:
    def __init__(self, reply=b"\x00"):
        self.reply = reply
        self.ready = threading.Event()
        self.received_host = None
        self.received_port = None
        self.error = None

        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]

        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self.ready.wait(timeout=2)

    def _read_exact(self, sock, size):
        data = b""
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise RuntimeError("client closed connection")
            data += chunk
        return data

    def _run(self):
        try:
            conn, _ = self.listener.accept()

            with conn:
                # Greeting.
                greeting = self._read_exact(conn, 3)
                assert greeting == b"\x05\x01\x00"

                # NO AUTH accepted.
                conn.sendall(b"\x05\x00")

                # CONNECT request.
                header = self._read_exact(conn, 4)
                assert header[:3] == b"\x05\x01\x00"

                address_type = header[3]

                if address_type != 0x03:
                    raise AssertionError("client did not use DOMAINNAME")

                length = self._read_exact(conn, 1)[0]
                self.received_host = self._read_exact(conn, length).decode()

                self.received_port = int.from_bytes(
                    self._read_exact(conn, 2),
                    "big",
                )

                if self.reply != b"\x00":
                    conn.sendall(b"\x05" + self.reply + b"\x00\x01")
                    conn.sendall(b"\x7f\x00\x00\x01\x00\x00")
                    return

                # Successful CONNECT response:
                # IPv4 address 127.0.0.1, port 9999.
                conn.sendall(
                    b"\x05\x00\x00\x01"
                    b"\x7f\x00\x00\x01"
                    b"\x27\x0f"
                )

                # Keep connection alive briefly.
                self.ready.set()
                conn.settimeout(1)
                try:
                    conn.recv(1)
                except socket.timeout:
                    pass

        except Exception as exc:
            self.error = exc
        finally:
            self.listener.close()

    def close(self):
        self.listener.close()
        self.thread.join(timeout=2)


def test_socks5_sends_domain_without_local_dns():
    server = FakeSocks5Server()

    client = Socks5Connection("127.0.0.1", server.port)

    try:
        sock = client.connect(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
            9000,
        )

        assert server.received_host == (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
        )
        assert server.received_port == 9000
        assert server.error is None

        sock.close()
    finally:
        client.close()
        server.close()


def test_socks5_rejects_invalid_port():
    client = Socks5Connection("127.0.0.1", 9050)

    with pytest.raises(ValueError):
        client.connect("example.onion", 0)


def test_socks5_rejects_empty_host():
    client = Socks5Connection("127.0.0.1", 9050)

    with pytest.raises(ValueError):
        client.connect("", 9000)


def test_socks5_reports_proxy_failure():
    server = FakeSocks5Server(reply=b"\x05")

    client = Socks5Connection("127.0.0.1", server.port)

    try:
        with pytest.raises(Socks5Error):
            client.connect("example.onion", 9000)

        assert server.received_host == "example.onion"
        assert server.received_port == 9000
    finally:
        client.close()
        server.close()
