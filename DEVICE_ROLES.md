# OpenForge Device Roles

## Samsung S26 Ultra

The S26 Ultra is the primary AI and orchestration device.

Responsibilities:

- Local AI inference
- LQL interpretation
- Prompt interpretation
- Job planning
- Pipeline orchestration
- Semantic scene planning
- Task decomposition
- Git coordination
- Lightweight validation

The S26 should NOT perform heavy Blender rendering when the Vivobook is available.

## Vivobook

The Vivobook is the graphics and production workstation.

Responsibilities:

- Blender
- Procedural model generation
- Mesh generation
- Materials
- Armatures
- Bones
- Animation
- Camera construction
- Lighting
- Volumetric effects
- Cycles/Eevee rendering
- Frame generation
- Video encoding
- Blender-specific validation

The Vivobook receives work through Git.

## Core principle

The S26 decides WHAT should happen.

The Vivobook performs the Blender-heavy HOW.

GitHub/OpenForge is the shared source of truth.
