"""OpenForge Blender worker.

Executes Blender jobs on a machine where bpy is available.
"""

from __future__ import annotations

from typing import Any

from core.jobs import JobSpec

from .job import execute_scene_job


def execute_job(job: JobSpec) -> dict[str, Any]:
    """Dispatch an OpenForge job to the appropriate Blender executor."""

    if job.job_type == "scene.generate":
        return execute_scene_job(job)

    raise ValueError(
        f"Unsupported Blender job type: {job.job_type}"
    )
