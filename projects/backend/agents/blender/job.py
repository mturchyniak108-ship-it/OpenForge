"""OpenForge Blender job adapter.

This module bridges the device-independent OpenForge JobSpec contract
and the Blender-specific SceneSpec contract.

The API/planner creates jobs.
The Blender worker executes those jobs.
"""

from __future__ import annotations

from typing import Any

from core.jobs import JobSpec

from .scene import construct_scene
from .schemas import ModelSpec, SceneSpec


SUPPORTED_JOB_TYPE = "scene.generate"


def scene_spec_from_payload(payload: dict[str, Any]) -> SceneSpec:
    """Convert a declarative job payload into a SceneSpec."""

    name = str(payload.get("name", "OpenForgeScene"))

    raw_models = payload.get("models", [])

    if not isinstance(raw_models, list):
        raise ValueError("Scene payload 'models' must be a list.")

    models: list[ModelSpec] = []

    for index, raw_model in enumerate(raw_models):
        if not isinstance(raw_model, dict):
            raise ValueError(
                f"Scene model {index} must be an object."
            )

        model_name = str(
            raw_model.get("name", f"Model_{index:03d}")
        )

        model_type = str(
            raw_model.get("model_type", "cube")
        )

        parameters = raw_model.get("parameters", {})

        if not isinstance(parameters, dict):
            raise ValueError(
                f"Model '{model_name}' parameters must be an object."
            )

        models.append(
            ModelSpec(
                name=model_name,
                model_type=model_type,
                parameters=parameters,
            )
        )

    metadata = payload.get("metadata", {})

    if not isinstance(metadata, dict):
        raise ValueError(
            "Scene payload 'metadata' must be an object."
        )

    return SceneSpec(
        name=name,
        models=models,
        metadata=metadata,
    )


def generate_blender_job(spec: SceneSpec) -> JobSpec:
    """Create a device-independent JobSpec for Blender."""

    return JobSpec(
        job_type=SUPPORTED_JOB_TYPE,
        payload={
            "name": spec.name,
            "models": [
                {
                    "name": model.name,
                    "model_type": model.model_type,
                    "parameters": model.parameters,
                }
                for model in spec.models
            ],
            "metadata": spec.metadata,
        },
        target_node="vivobook-blender",
        priority=0,
    )


def execute_scene_job(job: JobSpec) -> dict[str, Any]:
    """Execute a scene-generation JobSpec inside Blender."""

    if job.job_type != SUPPORTED_JOB_TYPE:
        raise ValueError(
            f"Unsupported Blender job type: {job.job_type}"
        )

    scene_spec = scene_spec_from_payload(job.payload)

    return construct_scene(scene_spec)
