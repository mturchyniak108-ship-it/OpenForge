from agents.blender_render_test import router as blender_render_test_router
app.include_router(blender_render_test_router, prefix="/agent/blender/render/test")
