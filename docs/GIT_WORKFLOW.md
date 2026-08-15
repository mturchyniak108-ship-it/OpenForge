# OpenForge Git Workflow

## Repository

https://github.com/mturchyniak108-ship-it/OpenForge

## Source of Truth

GitHub is the synchronization mechanism between the Samsung S26 Ultra and Vivobook.

The repository is the source of truth. Do not assume previous conversation state represents the current codebase.
## Samsung S26 Ultra

Primary responsibilities:

- AI inference
- prompt processing
- scene planning
- semantic/LQL processing
- generation orchestration
- lightweight development
- pipeline coordination
- architecture decisions

Before work:

    git pull --ff-only

After work:

    git add .
    git commit -m "Describe the change"
    git push
## Vivobook

Primary responsibilities:

- Blender
- procedural 3D generation
- models
- armatures
- bones
- rigging
- animation
- keyframes
- materials
- lighting
- ray tracing
- volumetric effects
- rendering
- video encoding
- Windows builds
- heavy compilation

Before work:

    git pull --ff-only

After work:

    git add .
    git commit -m "Describe the change"
    git push
## Development Rules

Always inspect the repository before modifying it.

Run:

    git status --short --branch
    git log --oneline --decorate -10
    git remote -v

Inspect README.md, docs/, and projects/ before making architectural changes.

Extend existing systems whenever practical instead of creating duplicate implementations.

Add tests for new functionality.

Document major architectural decisions in docs/.
## Blender Agent Direction

The Blender subsystem should evolve into a capable Blender agent supporting:

1. Prompt-to-scene planning
2. Prompt-to-model generation
3. Procedural geometry
4. Materials
5. Armatures
6. Bones
7. Rigging
8. Animation
9. Keyframes
10. Cameras
11. Lighting
12. Volumetric effects
13. Ray tracing
14. Render configuration
15. Frame validation
16. Video assembly

The Samsung provides AI reasoning and orchestration.

The Vivobook executes the heavy Blender workload.
## Two-Machine Rule

The Samsung and Vivobook must never silently diverge.

Before starting work:

    git pull --ff-only

After completing work:

    git add .
    git commit -m "Describe the change"
    git push

Samsung thinks, plans, orchestrates, and performs AI-heavy work.

Vivobook builds, renders, compiles, and performs heavy workstation workloads.

GitHub synchronizes both environments.

## Git Safety

Never use git push --force unless explicitly required and understood.

Never commit API keys, GitHub tokens, passwords, private keys, authentication cookies, credentials, or secret .env files.
