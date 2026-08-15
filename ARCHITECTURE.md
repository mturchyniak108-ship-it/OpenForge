# OpenForge Architecture

OpenForge is a distributed AI-assisted creative production system.

The system separates planning from heavy production.

## Pipeline

Prompt
  ->
AI interpretation
  ->
LQL / semantic scene description
  ->
Job specification
  ->
Capability selection
  ->
Vivobook Blender worker
  ->
Scene generation
  ->
Animation
  ->
Rendering
  ->
Video assets

## Design principles

1. Keep jobs declarative.
2. Keep device-specific implementation behind capability boundaries.
3. Prefer deterministic generation.
4. Keep Blender automation scriptable.
5. Preserve provenance.
6. Keep intermediate assets inspectable.
7. Keep Git as the source of truth.
8. Never make the Vivobook dependent on undocumented conversational context.

## Device separation

S26 Ultra:
AI + planning + orchestration.

Vivobook:
Blender + rendering + production.

## Future architecture

The Blender worker will eventually expose capabilities such as:

- scene_generation
- model_generation
- material_generation
- armature_generation
- animation_generation
- camera_generation
- lighting_generation
- volumetric_generation
- rendering
- video_encoding

The scheduler will select workers according to these capabilities.
