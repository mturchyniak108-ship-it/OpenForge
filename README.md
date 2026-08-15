# OpenForge

**OpenForge** is an open-source local computing ecosystem by **Mitchell
Turchyniak**.

It brings together experimental software, security research, local AI
infrastructure, developer tools, and edge-computing components into a
coordinated local platform.

## Projects

### SecureChat

An experimental secure peer-to-peer communication system featuring:

- cryptographic identities
- authenticated key exchange
- encrypted sessions
- peer state management
- replay protection
- onion/SOCKS5 transport
- swarm integrity and binding mechanisms
- revocation and rotation
- audit structures

### Backend

Local service and experimental backend components.

### Qrrune

A separate project incorporated into the OpenForge ecosystem while retaining
its own licensing information.

## Architecture

OpenForge is intended to operate across multiple local devices:

- Android / Termux
- Debian / WSL
- Raspberry Pi
- embedded microcontrollers
- local AI inference systems

The goal is to make these systems cooperate without requiring cloud
infrastructure for core functionality.

## Third-Party Integrations

OpenForge may integrate with external projects such as:

- llama.cpp
- stable-diffusion.cpp
- Ollama
- Termux packages
- Blender
- other open-source software

These projects remain separate works and retain their original licenses.

## Licensing

Original OpenForge code is released under the MIT License.

See `LICENSE` and `NOTICE.md`.

## Attribution

OpenForge applications are expected to display the OpenForge attribution
notice during startup.

Copyright (c) 2026 Mitchell Turchyniak.
