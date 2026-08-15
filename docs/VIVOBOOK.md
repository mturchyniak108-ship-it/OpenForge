# Vivobook Worker

The Vivobook is the OpenForge Blender production node.

## Primary purpose

Execute graphics-heavy jobs delegated by the S26 Ultra.

## Blender responsibilities

- Procedural scene creation
- Model generation
- Mesh manipulation
- Materials
- Armatures
- Bones
- Rigging
- Animation
- Cameras
- Lighting
- Volumetrics
- Ray tracing
- Frame rendering
- Video output

## Important rule

Do not turn the Vivobook into the primary AI orchestration node.

AI planning belongs on the S26 Ultra.

The Vivobook should expose reliable production capabilities that can be invoked by OpenForge jobs.

## Development rule

Before changing Blender code:

1. Read `AI_CONTEXT.md`.
2. Read `ARCHITECTURE.md`.
3. Read this file.
4. Inspect existing Blender code.
5. Preserve existing interfaces.
6. Add tests where practical.
7. Document new capabilities.

## Git

All meaningful changes must be committed and pushed to OpenForge.

The next machine can then pull the exact implementation.
