# Automated DAST Platform

This repository contains a modular Dynamic Application Security Testing (DAST) platform developed as part of the **Digital Egypt Pioneers Initiative (DEPI)**.

The project was built to explore how **Dynamic Application Security Testing (DAST)** platforms are designed and engineered. Instead of focusing on individual vulnerability scanners, we designed a modular assessment pipeline to understand how the different stages of a security assessment integrate through shared infrastructure into a single platform.

The platform follows an end-to-end assessment workflow:

**Target → Crawl → Discover → Extract → Scan → Analyze → Correlate → Live Dashboard → Assessment Report**

The current implementation represents a **Minimum Viable Product (MVP)** that validates the platform architecture and assessment workflow. It targets **local deployment** and provides a foundation for future enhancements rather than a production-ready deployment.

This repository documents the platform architecture, implementation, and the technologies behind each stage of the assessment workflow.


## Project Overview

The repository contains three main applications:

| Application | Purpose |
| --- | --- |
| `backend` | Django ASGI backend, scan orchestration, scanner engine, WebSocket telemetry, correlation, and reporting. |
| `frontend/nexusflow` | React frontend for starting scans, displaying live progress, reviewing findings, and opening reports. |
| `vulnerable_app` | Local Flask application intentionally built with vulnerabilities for repeatable scanner validation. |

## Objectives

- Build a modular DAST scanner for local web application assessment.
- Demonstrate automated crawling, endpoint extraction, payload-based testing, and finding generation.
- Stream live scan progress from the backend to the frontend.
- Produce consistent findings with proof-of-concept evidence.
- Generate a structured PDF report for completed scans.
- Provide a controlled vulnerable target for repeatable validation.

## Key Features

- Django REST API for starting scans and downloading completed reports.
- Django Channels WebSocket telemetry for live scan progress.
- Playwright-based crawling for links, forms, and browser-observed URLs.
- Structured endpoint and parameter extraction.
- Asynchronous scanner execution using `asyncio` and `httpx`.
- Static scanner registry for active scanner modules.
- JSON-based payload definitions.
- Shared response analysis helpers.
- In-memory finding collection during scan execution.
- Rule-based attack-chain correlation.
- HTML-to-PDF reporting through Jinja2, Matplotlib, and Playwright.
- React interface for scan progress, logs, findings, and report access.

## Supported Vulnerabilities

The current scanner registry supports:

- SQL Injection
- Reflected Cross-Site Scripting
- Stored Cross-Site Scripting
- Weak Password Policy
- Weak Session Cookie Configuration
- Missing Authentication Rate Limiting
- Broken Object Level Authorization / IDOR
- Sensitive File Disclosure
- Unrestricted File Upload
- Local File Inclusion
- Path Traversal / Arbitrary File Read

## Technology Stack

| Area | Technologies |
| --- | --- |
| Backend | Python, Django, Django REST Framework, Django Channels, Daphne / ASGI, SQLite |
| Scanner Engine | `asyncio`, `httpx`, Playwright, JSON payload definitions |
| Reporting | Jinja2, Matplotlib, Playwright PDF rendering |
| Frontend | React, TypeScript, Vite, React Router, Axios, Tailwind CSS |
| Vulnerable Target | Flask, Flask-SQLAlchemy, SQLite, Jinja templates |

## High-Level Architecture

```text
React Frontend
    |
    | HTTP + WebSocket
    v
Django API / Channels
    |
    | background scan thread
    v
Orchestrator
    |
    | crawler -> extractor -> scanners -> correlation -> report builder
    v
Stored JSON report + generated PDF report
```

For detailed architecture, design decisions, and trade-offs, see [docs/architecture.md](docs/architecture.md).

## Project Structure

```text
.
+-- backend/
|   +-- api/                 # Django API, models, views, and WebSocket consumer
|   +-- config/              # Django settings, URLs, and ASGI configuration
|   +-- engine/              # Crawler, extractor, scanners, correlation, and core models
|   +-- reporter/            # Report builder, HTML template, charts, and PDF generator
|   +-- tests/               # Local tests and legacy/manual validation scripts
+-- docs/                    # Project documentation
|   +-- diagrams/            # Mermaid architecture diagrams
+-- frontend/
|   +-- nexusflow/           # React frontend
+-- vulnerable_app/          # Local vulnerable Flask application
+-- README.md
```

## Quick Start

Run the project locally using three terminals:

```text
Terminal 1: vulnerable_app  -> http://127.0.0.1:5004
Terminal 2: backend         -> http://localhost:8000
Terminal 3: frontend        -> http://localhost:3000
```

Start a scan from the frontend against:

```text
http://127.0.0.1:5004
```

For complete setup instructions, see [docs/setup.md](docs/setup.md).

## Documentation

| Document | Description |
| --- | --- |
| [docs/setup.md](docs/setup.md) | Local installation, configuration, execution order, and troubleshooting. |
| [docs/architecture.md](docs/architecture.md) | Backend architecture, execution flow, package responsibilities, design decisions, and future improvements. |
| [docs/api.md](docs/api.md) | Implemented HTTP and WebSocket API reference. |
| [docs/testing.md](docs/testing.md) | Testing and validation strategy for the current local implementation. |
| [docs/diagrams/](docs/diagrams/) | Mermaid diagrams for pipeline, component, class, sequence, and local deployment views. |

## Current Status

- Local development and demonstration system.
- Functional scan workflow from frontend request to generated PDF report.
- Current backend API supports starting scans, WebSocket telemetry, and downloading completed reports.
- Scanner execution runs inside the Django process using a background Python thread.
- Final report JSON is stored on the local SQLite `Scan` record.

## Current Limitations

The current implementation is an MVP, so some capabilities are intentionally out of scope:

- No authentication or user management for the dashboard.
- No scan history API.
- No scan cancellation API.
- Assessment results are not persisted across sessions. Refreshing the application or restarting the backend clears previous scan results.
- Django Channels currently uses an in-memory channel layer.
- Active scan jobs are not recoverable if the backend process stops.

## Future Roadmap

The following items are planned improvements and are not implemented in the current version:

- Redis-backed Channel Layer.
- Celery background workers.
- PostgreSQL persistence.
- User authentication and role-based access.
- Scan history, scan detail, and report management APIs.
- Persistent finding storage per scan.
- Multi-user support.
- Distributed scanning.
- Additional scanner modules and payload libraries.
- Improved correlation logic.
- Authentication-aware scan workflows beyond raw cookie injection.
- Performance optimization and production hardening.

## Contributors

| Contributor | Role |
| --- | --- |
| Salma Khalil | Backend team lead, backend architecture, scan pipeline, orchestration, integration, and SQL Injection scanner. |
| Doha Mohamed | Frontend engineering, scan workflow UI, live progress, logs, findings, and report views. |
| Esraa Kamel | Reporting subsystem and file-security scanners for LFI, path traversal, and file upload. |
| Fatma Mohamed | XSS and authentication security scanners, including weak passwords, session flags, and rate limiting. |
| Mustafa Ayman | IDOR scanner and attack-chain correlation contribution. |
| Sara Yasser | Sensitive File Disclosure scanner and documentation support. |
