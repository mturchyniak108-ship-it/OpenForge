"""SecureChat authenticated wire framing."""

from .frame import (
    FRAME_VERSION,
    Frame,
    FrameType,
)

__all__ = [
    "FRAME_VERSION",
    "Frame",
    "FrameType",
]
