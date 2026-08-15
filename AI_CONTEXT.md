# OpenForge AI Context

## Purpose

OpenForge is a distributed AI-assisted creative production system.

This file is the primary orientation document for AI agents working inside the OpenForge repository.

The repository is the source of truth. Do not rely on stale conversational context when the repository contains newer information.

## Required Reading Order

Before modifying OpenForge, read these files:

1. AI_CONTEXT.md
2. ARCHITECTURE.md
3. DEVICE_ROLES.md
4. DEVELOPMENT_WORKFLOW.md
5. docs/PIPELINE.md
6. docs/S26_ULTRA.md or docs/VIVOBOOK.md, depending on the assigned device

Then inspect the relevant implementation under projects/.

## Git State

Before making changes, inspect:

    git status --short --branch
    git log --oneline --decorate -10
    git remote -v

Always pull before beginning work:

    git pull --ff-only

After completing meaningful work:

    git status
    git add .
    git commit -m "Describe the change"
    git push

Never use git push --force unless explicitly authorized and understood.

## Device Architecture

### Samsung S26 Ultra

The S26 Ultra is the primary AI reasoning and orchestration node.

Responsibilities include:
- Local AI inference
- Prompt interpretation
- LQL interpretation
- Semantic scene planning
- Job specification
- Task decomposition
- Capability selection
- Pipeline orchestration
- Git coordination
- Lightweight validation

The S26 should describe WHAT needs to happen rather than duplicating Blender implementation.

### Vivobook

The Vivobook is the graphics and production node.

Responsibilities include:
- Blender execution
- Procedural geometry
- Model generation
- Mesh manipulation
- Materials
- Armatures
- Bones
- Rigging
- Animation
- Keyframes
- Cameras
- Lighting
- Volumetric effects
- Ray tracing
- Frame rendering
- Video encoding
- Heavy compilation

The Vivobook should execute declarative jobs produced by the OpenForge planning system.

## Core Architecture

The intended production flow is:

Prompt
-> AI interpretation
-> LQL / semantic representation
-> Job specification
-> Capability selection
-> Vivobook worker
-> Blender scene generation
-> Models / materials / rigs
-> Animation / keyframes
-> Camera / lighting / volumetrics
-> Rendering
-> Video assets

Keep jobs declarative.

Keep device-specific implementation behind capability boundaries.

Prefer deterministic generation where practical.

Keep Blender automation scriptable and inspectable.

Preserve provenance.

Keep intermediate assets inspectable.

## Blender Agent Direction

The Blender subsystem is intended to evolve into a master Blender production agent.

Potential capabilities include:
- scene_generation
- model_generation
- material_generation
- armature_generation
- rig_generation
- animation_generation
- keyframe_generation
- camera_generation
- lighting_generation
- volumetric_generation
- render_configuration
- rendering
- video_encoding

AI should specify desired results, scene intent, actions, and key frames.

Blender should perform the concrete implementation of objects, meshes, armatures, bones, constraints, keyframes, interpolation, cameras, lights, materials, render settings, and frame generation.

## Implementation Rules

Before writing new code:

- Inspect existing implementation.
- Reuse working interfaces where practical.
- Avoid duplicate systems.
- Preserve backwards compatibility when practical.
- Add tests for new behavior.
- Document significant architectural changes.

Do not replace working code merely because a different implementation is possible.

## LQL

LQL and semantic representations should describe intent, relationships, classifications, provenance, and traversal rather than becoming tightly coupled to Blender internals.

Blender-specific execution belongs behind the appropriate worker/capability boundary.

## Job System

Jobs should be explicit, inspectable, deterministic where possible, and suitable for transfer between devices.

A job should contain enough information for the receiving worker to execute it without requiring undocumented conversational context.

## Security

Never commit:
- API keys
- GitHub tokens
- passwords
- private keys
- authentication cookies
- credentials
- secret .env files
- model-provider secrets

Run security checks before publishing significant changes.

## AI Behavior

When uncertain, inspect the repository before guessing.

When an implementation appears incomplete, determine whether it is intentionally staged before replacing it.

When changing architecture, document the reason.

When working on the Vivobook, prioritize reliable Blender execution over unnecessary AI complexity.

When working on the S26, prioritize planning, orchestration, semantic interpretation, and job generation.

## Golden Rule

The Samsung decides WHAT should happen.

The Vivobook determines HOW Blender should execute it.

GitHub synchronizes the work.

The repository is the source of truth.
