# Architecture Diagrams

This directory contains Mermaid diagrams for the current local implementation of NexusFlow.

## Related Documentation

- [README](../../README.md)
- [Local Setup Guide](../setup.md)
- [Architecture](../architecture.md)
- [API Documentation](../api.md)
- [Testing Guide](../testing.md)

## Diagram Index

| Diagram | Purpose |
| --- | --- |
| [Backend Pipeline](backend-pipeline.md) | End-to-end scan execution flow from frontend request to PDF download. |
| [Component Diagram](component-diagram.md) | Backend package organization and runtime dependencies. |
| [Class Diagram](class-diagram.md) | Main Django, engine, scanner, model, correlation, and reporting classes. |
| [Sequence Diagram](sequence-diagram.md) | Scan lifecycle, WebSocket telemetry, report storage, and PDF download sequence. |
| [Deployment Diagram](deployment-diagram.md) | Local development deployment across frontend, backend, Playwright, SQLite, and vulnerable app processes. |

These diagrams describe the current local development architecture only. Redis, Celery, PostgreSQL, user authentication, scan history, and distributed workers are future roadmap items and are not represented as implemented components.
