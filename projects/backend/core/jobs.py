"""Device-independent OpenForge job contracts."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class JobSpec:
    """A declarative unit of work submitted to an OpenForge node."""

    job_type: str
    payload: dict[str, Any] = field(default_factory=dict)
    target_node: str | None = None
    priority: int = 0


@dataclass
class Job:
    """Runtime state for a submitted job."""

    id: str
    spec: JobSpec
    status: JobStatus = JobStatus.QUEUED
    result: dict[str, Any] | None = None
    error: str | None = None
