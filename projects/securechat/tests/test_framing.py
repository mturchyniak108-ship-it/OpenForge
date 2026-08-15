import pytest

from securechat.framing import FRAME_VERSION, Frame, FrameType


PEER_ID = "12345678-1234-1234-1234-123456789abc"


def make_frame(sequence=0):
    return Frame(
        version=FRAME_VERSION,
        frame_type=FrameType.DATA,
        peer_id=PEER_ID,
        sequence=sequence,
        ciphertext=b"encrypted payload",
    )


def test_frame_creation():
    frame = make_frame()

    assert frame.version == FRAME_VERSION
    assert frame.frame_type == FrameType.DATA
    assert frame.peer_id == PEER_ID
    assert frame.sequence == 0
    assert frame.ciphertext == b"encrypted payload"


def test_frame_round_trip():
    frame = make_frame(7)

    restored = Frame.from_bytes(frame.to_bytes())

    assert restored == frame


def test_serialization_is_deterministic():
    frame = make_frame(3)

    assert frame.to_bytes() == frame.to_bytes()


def test_close_frame_round_trip():
    frame = Frame(
        version=FRAME_VERSION,
        frame_type=FrameType.CLOSE,
        peer_id=PEER_ID,
        sequence=4,
        ciphertext=b"",
    )

    assert Frame.from_bytes(frame.to_bytes()) == frame


def test_negative_sequence_rejected():
    frame = Frame(
        version=FRAME_VERSION,
        frame_type=FrameType.DATA,
        peer_id=PEER_ID,
        sequence=-1,
        ciphertext=b"x",
    )

    with pytest.raises(ValueError, match="negative"):
        frame.to_bytes()


def test_non_integer_sequence_rejected():
    frame = Frame(
        version=FRAME_VERSION,
        frame_type=FrameType.DATA,
        peer_id=PEER_ID,
        sequence="1",
        ciphertext=b"x",
    )

    with pytest.raises(TypeError, match="integer"):
        frame.to_bytes()


def test_non_bytes_ciphertext_rejected():
    frame = Frame(
        version=FRAME_VERSION,
        frame_type=FrameType.DATA,
        peer_id=PEER_ID,
        sequence=0,
        ciphertext="encrypted",
    )

    with pytest.raises(TypeError, match="bytes"):
        frame.to_bytes()


def test_malformed_frame_rejected():
    with pytest.raises(ValueError, match="encoding"):
        Frame.from_bytes(b"not json")


def test_missing_field_rejected():
    data = (
        b'{"version":1,"frame_type":"data",'
        b'"peer_id":"' + PEER_ID.encode() + b'"}'
    )

    with pytest.raises(ValueError, match="missing"):
        Frame.from_bytes(data)


def test_invalid_frame_type_rejected():
    data = (
        b'{"version":1,"frame_type":"bogus",'
        b'"peer_id":"' + PEER_ID.encode() + b'",'
        b'"sequence":0,"ciphertext":""}'
    )

    with pytest.raises(ValueError, match="frame type"):
        Frame.from_bytes(data)


def test_invalid_ciphertext_rejected():
    data = (
        b'{"version":1,"frame_type":"data",'
        b'"peer_id":"' + PEER_ID.encode() + b'",'
        b'"sequence":0,"ciphertext":"not-hex"}'
    )

    with pytest.raises(ValueError, match="ciphertext"):
        Frame.from_bytes(data)


def test_negative_wire_sequence_rejected():
    data = (
        b'{"version":1,"frame_type":"data",'
        b'"peer_id":"' + PEER_ID.encode() + b'",'
        b'"sequence":-1,"ciphertext":""}'
    )

    with pytest.raises(ValueError, match="negative"):
        Frame.from_bytes(data)


def test_non_bytes_wire_data_rejected():
    with pytest.raises(TypeError, match="bytes"):
        Frame.from_bytes("not bytes")


def test_version_is_preserved():
    frame = Frame(
        version=99,
        frame_type=FrameType.DATA,
        peer_id=PEER_ID,
        sequence=1,
        ciphertext=b"x",
    )

    restored = Frame.from_bytes(frame.to_bytes())

    assert restored.version == 99


def test_ciphertext_is_binary_safe():
    payload = bytes(range(256))

    frame = Frame(
        version=FRAME_VERSION,
        frame_type=FrameType.DATA,
        peer_id=PEER_ID,
        sequence=9,
        ciphertext=payload,
    )

    assert Frame.from_bytes(frame.to_bytes()).ciphertext == payload
