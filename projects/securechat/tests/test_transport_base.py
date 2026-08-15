from securechat.transport.base import Transport, TransportAddress


def test_transport_address():
    address = TransportAddress("127.0.0.1", 9000)

    assert address.host == "127.0.0.1"
    assert address.port == 9000


def test_transport_is_abstract():
    assert Transport.__abstractmethods__ == {
        "connect",
        "close",
        "send",
        "receive",
    }
