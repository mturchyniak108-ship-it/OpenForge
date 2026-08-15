"""Blender scene construction from OpenForge SceneSpec.

The AI/planner produces SceneSpec data.
This module converts that declarative specification into Blender objects.

Blender-specific implementation stays behind this boundary.
"""

from __future__ import annotations

from typing import Any

from .schemas import SceneSpec


def require_blender():
    """Import Blender only when running inside Blender."""
    try:
        import bpy
    except ImportError as exc:
        raise RuntimeError(
            "Blender Python (bpy) is required to construct a scene."
        ) from exc

    return bpy


def clear_scene() -> None:
    """Remove existing objects and unused common datablocks."""
    bpy = require_blender()

    bpy.ops.object.select_all(action="SELECT")
    bpy.ops.object.delete(use_global=False)

    for datablocks in (
        bpy.data.meshes,
        bpy.data.curves,
        bpy.data.materials,
        bpy.data.cameras,
        bpy.data.lights,
        bpy.data.armatures,
    ):
        for datablock in list(datablocks):
            if datablock.users == 0:
                datablocks.remove(datablock)


def create_primitive_model(spec: Any):
    """Create a basic procedural model from ModelSpec."""
    bpy = require_blender()

    model_type = spec.model_type.lower()
    params = spec.parameters

    location = tuple(params.get("location", (0.0, 0.0, 0.0)))
    scale = tuple(params.get("scale", (1.0, 1.0, 1.0)))

    if model_type == "cube":
        bpy.ops.mesh.primitive_cube_add(
            size=float(params.get("size", 1.0)),
            location=location,
        )

    elif model_type == "sphere":
        bpy.ops.mesh.primitive_uv_sphere_add(
            radius=float(params.get("radius", 1.0)),
            location=location,
        )

    elif model_type == "cylinder":
        bpy.ops.mesh.primitive_cylinder_add(
            radius=float(params.get("radius", 1.0)),
            depth=float(params.get("depth", 2.0)),
            location=location,
        )

    elif model_type == "plane":
        bpy.ops.mesh.primitive_plane_add(
            size=float(params.get("size", 2.0)),
            location=location,
        )

    else:
        raise ValueError(
            f"Unsupported primitive model type: {spec.model_type}"
        )

    obj = bpy.context.object
    obj.name = spec.name
    obj.scale = scale

    return obj


def construct_scene(spec: SceneSpec) -> dict[str, Any]:
    """Construct a Blender scene from a device-independent SceneSpec."""
    bpy = require_blender()

    clear_scene()

    scene = bpy.context.scene
    scene.name = spec.name

    created_models = []

    for model_spec in spec.models:
        if model_spec.model_type.lower() in {
            "cube",
            "sphere",
            "cylinder",
            "plane",
        }:
            created_models.append(
                create_primitive_model(model_spec)
            )
        else:
            raise ValueError(
                f"Model generator not implemented: "
                f"{model_spec.model_type}"
            )

    return {
        "scene": scene.name,
        "models_created": [obj.name for obj in created_models],
        "model_count": len(created_models),
    }
