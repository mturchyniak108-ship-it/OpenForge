from fastapi import FastAPI

from agents.blender.router import router as blender_router

app = FastAPI(title="OpenForge")

app.include_router(
    blender_router,
    prefix="/agent/blender",
)
