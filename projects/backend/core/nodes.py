"""OpenForge compute-node contracts."""

from dataclasses import dataclass, field


@dataclass
class NodeCapabilities:
    """Capabilities advertised by an OpenForge node."""

    ai: bool = False
    vision: bool = False
    blender: bool = False
    rendering: bool = False
    simulation: bool = False
    video_encoding: bool = False
    gpu: bool = False
    capabilities: set[str] = field(default_factory=set)


@dataclass
class Node:
    """A device capable of executing OpenForge jobs."""

    id: str
    name: str
    platform: str
    capabilities: NodeCapabilities
    address: str | None = None
    status: str = "offline"
