"""OpenForge Blender worker API routes."""

from fastapi import APIRouter

from .job import generate_blender_job
from .schemas import SceneSpec

router = APIRouter()


@router.post("/scene")
def generate_scene(spec: SceneSpec):
    """Generate a Blender scene execution job from a SceneSpec."""
    return generate_blender_job(spec)
