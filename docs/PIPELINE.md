# OpenForge Production Pipeline

## High-level flow

Prompt
-> semantic interpretation
-> LQL representation
-> scene/job specification
-> capability matching
-> Blender worker
-> scene
-> assets
-> animation
-> render
-> encoded video

## Blender scene pipeline

Scene specification
-> environment
-> models
-> materials
-> armatures
-> animation
-> camera
-> lighting
-> volumetrics
-> render settings
-> frame output
-> video

## Key-frame generation

AI should describe the desired key frames and actions.

Blender should construct the actual:

- objects
- meshes
- armatures
- bones
- constraints
- keyframes
- interpolation
- cameras
- lighting
- render configuration

This keeps AI planning separate from Blender execution.
