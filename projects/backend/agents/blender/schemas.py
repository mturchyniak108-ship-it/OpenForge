"""Device-independent scene contracts for OpenForge."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ModelSpec:
    """Declarative description of a model to create."""

    name: str
    model_type: str
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class SceneSpec:
    """Declarative scene description consumed by the Blender worker."""

    name: str
    models: list[ModelSpec] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
