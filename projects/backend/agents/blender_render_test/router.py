from fastapi import APIRouter
from .render_test import generate_render_test

router = APIRouter()

@router.post("/generate")
def generate(payload: dict):
    return generate_render_test(payload)
