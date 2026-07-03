# Architecture

This document explains the current backend and application architecture of the NexusFlow DAST scanner. It describes how the implemented system is organized, why the main engineering choices were made, and what limitations exist in the current local-development version.

The project is a local demonstration system, not a production deployment.

## Related Documentation

- [README](../README.md)
- [Local Setup Guide](setup.md)
- [API Documentation](api.md)
- [Testing Guide](testing.md)
- [Architecture Diagrams](diagrams/)

## Overall Architecture

NexusFlow is split into three main applications:

- `backend`: Django ASGI application that exposes scan APIs, WebSocket telemetry, scan orchestration, scanner modules, correlation, and reporting.
- `frontend/nexusflow`: React application that starts scans and displays progress, logs, findings, and reports.
- `vulnerable_app`: Flask application intentionally built with vulnerabilities so the scanner can be tested safely.

At runtime, the main execution path is:

```text
React Frontend
    |
    | POST /api/scan/start/
    v
Django API
    |
    | creates Scan row
    | starts background thread
    v
Background Scan Thread
    |
    | creates ScanContext
    | creates AsyncSafeHttpClient
    | creates Orchestrator
    v
Orchestrator
    |
    | loads scanners from registry
    | runs Playwright crawler
    | extracts endpoints
    | executes scanners asynchronously
    | runs correlation rules
    | builds JSON report
    v
SQLite Scan Record
    |
    | stores status, threat level, report JSON
    v
PDF Report Endpoint
```

Live scan logs are sent through Django Channels to a scan-specific WebSocket group. The frontend subscribes to that WebSocket and converts backend telemetry into progress, activity feed entries, endpoint activity, findings, and report readiness.

## Backend Execution Flow

The current backend scan flow starts in `api.views.StartScanView`.

1. The frontend sends a target URL and optional raw cookie header.
2. The API parses cookies into a dictionary.
3. The API creates a `Scan` database row with status `Running`.
4. The API starts a Python `threading.Thread`.
5. The background thread creates a dedicated asyncio event loop.
6. A `ScanContext` is created to hold target URL, cookies, request budget, scan timeout, and abort state.
7. `AsyncSafeHttpClient` is created around `httpx.AsyncClient`.
8. `Orchestrator` loads all scanner classes from `SCANNER_REGISTRY`.
9. `PlaywrightSpider` crawls the target and extracts raw links and forms.
10. `ParamExtractor` converts crawler output into structured `Endpoint` objects.
11. The orchestrator runs scanners concurrently with `asyncio.gather`.
12. Scanner findings are saved into an in-memory `FindingRepository`.
13. `CorrelationEngine` adds attack-chain findings when rule requirements are met.
14. `ReportBuilder` produces the final structured JSON report.
15. The `Scan` row is updated to `Completed` or `Failed`.
16. `DownloadReportView` generates and returns a PDF using the stored report JSON.

## Why Django

Django is used for the backend because the project needs more than a simple script runner. It needs HTTP APIs, WebSocket integration, persistence, configuration, and a structure that can support future expansion.

The current implementation uses Django for:

- API routing through `api.urls`.
- Request handling through Django REST Framework `APIView`.
- Persistence through Django models and SQLite.
- ASGI support through `config.asgi`.
- WebSocket routing through Django Channels.
- A conventional project structure for separating API, configuration, and engine code.

Django is a reasonable fit because the scanner is not only a command-line engine. It is a web-backed application with a frontend, live telemetry, report downloading, and persisted scan state.

The current project does not implement production Django concerns such as dashboard authentication, user management, PostgreSQL, or deployment hardening. Those are future roadmap items.

## Why React

React is used for the frontend because the scanner interface is stateful and event-driven. A scan produces changing progress, live logs, parsed activities, endpoint updates, findings, and report readiness.

React is used for:

- Starting a new scan.
- Navigating between scan views.
- Maintaining live scan state from WebSocket messages.
- Rendering progress and phase transitions.
- Displaying logs and findings.
- Opening the generated report.

The frontend communicates with the backend through:

- `axios` for HTTP requests.
- Native `WebSocket` for live telemetry.

React is appropriate here because the interface needs to update continuously while a scan is running, without requiring full page reloads or manual refreshes.

## Package Responsibilities

### `backend/api`

Responsible for the Django-facing application layer.

Key responsibilities:

- Defines `Scan` and `ScanFinding` models.
- Starts scans through `StartScanView`.
- Parses raw cookie headers.
- Starts the background scan thread.
- Serves generated PDF reports through `DownloadReportView`.
- Defines WebSocket routing and the `ScanProgressConsumer`.

### `backend/config`

Responsible for Django project configuration.

Key responsibilities:

- Django settings.
- Installed apps.
- Middleware.
- SQLite database configuration.
- CORS configuration.
- ASGI application setup.
- HTTP and WebSocket protocol routing.
- In-memory Channels configuration.

### `backend/engine`

Responsible for the DAST scanning engine.

This package contains the core runtime pipeline and is the main backend domain layer.

### `backend/engine/core`

Responsible for shared core abstractions.

Key responsibilities:

- `BaseScanner` scanner interface.
- `AsyncSafeHttpClient` wrapper around `httpx.AsyncClient`.
- `ScanContext` request budget, cookies, headers, timeout, and abort state.
- Scanner exception types.

### `backend/engine/crawler`

Responsible for browser-based discovery.

Key responsibilities:

- Launches Playwright Chromium.
- Injects provided cookies.
- Crawls same-domain pages.
- Captures links from the DOM.
- Captures network response URLs.
- Extracts HTML form actions, methods, inputs, and file inputs.

### `backend/engine/extractor`

Responsible for converting raw crawl output into scanner-ready models.

Key responsibilities:

- Parses query parameters.
- Converts links and forms into `Endpoint` objects.
- Creates `Parameter` objects.
- Deduplicates structurally similar endpoints.
- Classifies endpoint types such as login, register, upload, and general.

### `backend/engine/models`

Responsible for internal engine data structures.

Key responsibilities:

- `Endpoint`
- `Parameter`
- `Finding`
- `Evidence`
- `ProofOfConcept`
- HTTP request/response context dataclasses

These are not Django models. They are scanner-domain dataclasses used during a scan.

### `backend/engine/scanners`

Responsible for vulnerability-specific detection modules.

Active scanner areas:

- `injection`: SQL Injection and XSS.
- `authentication`: weak passwords, session flags, and rate limiting.
- `authorization`: IDOR/BOLA.
- `file_security`: sensitive file disclosure, file upload, LFI, and path traversal.

Each scanner returns `Finding` objects and uses the shared HTTP client, payload manager, and response analyzer where needed.

### `backend/engine/payloads`

Responsible for scanner payload definitions.

Key responsibilities:

- Stores vulnerability test cases as JSON.
- Loads all payload definitions.
- Pre-compiles regex signatures.
- Provides payload data to scanners by vulnerability type.

### `backend/engine/analyzer`

Responsible for reusable response interpretation.

Key responsibilities:

- SQLi boolean variance checks.
- XSS reflection checks.
- Baseline-aware regex matching.
- Session cookie flag analysis.
- Authentication success heuristics.
- Basic framework and WAF fingerprint helpers.

### `backend/engine/registry`

Responsible for listing active scanner modules.

The orchestrator uses this package to instantiate the scanner pipeline.

### `backend/engine/storage`

Responsible for temporary finding storage during a scan.

The current `FindingRepository` is in-memory and deduplicates findings by title and affected path.

### `backend/engine/correlation`

Responsible for attack chain identification.

Key responsibilities:

- Loads correlation rules from JSON.
- Checks whether required findings are present.
- Creates synthetic chain findings.
- Saves chain findings back into the repository.

### `backend/reporter`

Responsible for report construction and rendering.

Key responsibilities:

- Builds structured report JSON from findings.
- Calculates severity distribution and overall threat level.
- Generates chart images.
- Renders HTML report templates.
- Converts HTML to PDF through Playwright.

### `frontend/nexusflow`

Responsible for the user interface.

Key responsibilities:

- Starts scans through the backend API.
- Connects to scan WebSocket telemetry.
- Parses live messages into frontend scan state.
- Displays scan phases, progress, logs, endpoint activity, findings, and reports.

### `vulnerable_app`

Responsible for local scanner demonstration.

It intentionally contains vulnerabilities so the scanner can detect and report them in a controlled environment.

## Engineering Tradeoffs

The current architecture favors clarity and demonstrability over production scalability.

Important tradeoffs:

- Threads are simpler than a worker queue, but not durable.
- SQLite is easy to run locally, but not intended for multi-user production workloads.
- In-memory Channels are simple, but do not work across multiple backend processes.
- In-memory finding storage is simple, but findings are not independently queryable after the scan except through the final report JSON.
- Static scanner registry is easy to understand, but does not support runtime scanner selection.
- JSON payload files are easy to maintain, but not editable through an admin interface.
- Playwright crawling gives realistic browser behavior, but adds browser installation and runtime overhead.
- HTML-to-PDF reporting gives strong layout control, but depends on Playwright.

These tradeoffs are acceptable for the current graduation demo scope.

## Architectural Limitations

The current implementation has the following limitations:

- It is a local development and demonstration system, not a production deployment.
- Scans run in background Python threads created by the Django process.
- Scan jobs are not durable if the backend process exits.
- There is no Celery worker queue.
- There is no Redis-backed task or channel infrastructure.
- There is no PostgreSQL database.
- There is no scanner dashboard authentication or user management.
- There is no implemented scan history API.
- Findings are not stored as normalized persistent records during the active scanner pipeline.
- WebSocket messages use an in-memory channel layer.
- Multiple backend processes would not share WebSocket channel state.
- The crawler is limited by its current same-domain crawling logic and does not perform complex user interaction workflows.
- The scanner coverage is limited to the implemented vulnerability classes.
- Response analysis is heuristic-based and can still produce false positives or false negatives.
- Correlation is rule-based and title-matching-based.
- Report generation requires Playwright browser binaries.
- Some test files are legacy/manual scripts and do not fully match the current active engine API.

These limitations are expected at this stage and inform the future roadmap.

## 7. Design Decisions

The current architecture was designed to support a local DAST scanning workflow that is understandable, extensible, and suitable for demonstration. The team prioritized clear execution flow, modular scanner development, and repeatable reporting over production-scale infrastructure.

### Asynchronous Networking

The scanner sends many HTTP requests while testing parameters, payloads, authentication behavior, file access patterns, and upload handling. These requests are I/O-bound: most of the time is spent waiting for the target application to respond.

The backend uses `httpx.AsyncClient` through `AsyncSafeHttpClient` so scanners can perform non-blocking request execution. The orchestrator runs scanner modules with `asyncio.gather`, allowing independent scanners to progress during the same assessment instead of waiting for each request sequence to complete serially.

The trade-off is that scanner implementations must be written using async functions and must share a controlled HTTP client. This adds some complexity, but it keeps the scanning phase responsive and prepares the engine for additional scanners without changing the overall execution model.

### Background Threading

A scan can take longer than a normal HTTP request-response cycle. The backend therefore starts the scan inside a Python background thread after creating the `Scan` record.

This decision allows `POST /api/scan/start/` to return a `scan_id` immediately while the assessment continues independently. It also lets the frontend connect to the scan WebSocket and display live progress while the background scan is running.

For the current local development scope, background threading is simpler than introducing a durable task queue. The trade-off is that scan execution is tied to the Django process. If the backend process exits, active scans are not recoverable. This is acceptable for the current demonstration system and is intentionally separated from future production worker infrastructure.

### WebSockets Instead of Polling

The scan engine produces continuous telemetry during crawling, scanner execution, correlation, and report building. WebSockets were selected so the backend can push log events to the frontend as soon as they occur.

Polling would require the frontend to repeatedly ask for scan status, increasing request noise and adding delay between backend events and UI updates. WebSockets provide a better fit for live scan progress because scan events are naturally event-driven.

The current implementation uses Django Channels with an in-memory channel layer. This keeps the local demo simple, but it also means WebSocket state is process-local and not suitable for multi-process deployment without a Redis-backed channel layer.

### Layered Architecture

The backend is organized into layers so that API handling, scan orchestration, crawling, scanning, analysis, correlation, storage, and reporting remain separate responsibilities.

This structure was chosen because DAST scanners grow by adding new vulnerability modules, payloads, analyzers, and report outputs. A flat structure would make those changes harder to control. The layered design keeps the API from depending on scanner internals and keeps scanners from depending on report formatting.

The trade-off is a larger number of modules and model objects, but the benefit is clearer ownership of each part of the scan pipeline.

### JSON Payload Definitions

Payload definitions are stored as JSON because payloads are data, not scanner control flow. Test strings, severity values, regex signatures, endpoint keywords, and vulnerability-specific cases can be changed without modifying scanner code.

This approach also makes payloads easier to review and organize by vulnerability family. `PayloadManager` loads the definitions once and pre-compiles regex signatures where applicable, so scanner modules consume a consistent payload interface.

The trade-off is that JSON definitions must match what each scanner expects. The current implementation accepts that constraint because it keeps scanner logic focused on execution and verification rather than hard-coded payload lists.

### BaseScanner Interface

All scanner modules inherit from `BaseScanner` to enforce one execution contract. Each scanner receives the target URL, shared HTTP client, and optional logging callback, then implements `run_scan(endpoints)`.

The base class provides an `execute()` wrapper that isolates scanner failures. If one scanner raises an exception, the orchestrator can continue processing the remaining modules instead of failing the whole assessment.

This decision reduces duplicated scanner boilerplate and gives the orchestrator one consistent way to execute every scanner type.

### Scanner Registry

The scanner registry provides a single static list of scanner classes used by the orchestrator. This keeps scanner loading explicit and easy to inspect.

The registry avoids hard-coding scanner construction throughout the orchestrator and provides a simple extension point for adding new modules. A new scanner can be added by implementing the `BaseScanner` contract and registering it in `SCANNER_REGISTRY`.

The trade-off is that runtime scanner selection is not implemented. For the current project scope, a static registry is easier to reason about and sufficient for the local demo.

### Common Finding Model

Every scanner returns the same `Finding` model. This decision was necessary because findings flow through multiple later stages: in-memory storage, correlation, JSON report building, and PDF rendering.

A common model lets the engine treat SQL injection, XSS, authentication flaws, IDOR, file disclosure, file upload issues, LFI, and path traversal findings uniformly. Each finding includes severity, affected path, description, impact, recommendations, references, and proof-of-concept evidence.

Without this shared model, each scanner would need custom report handling and the reporting system would become tightly coupled to vulnerability-specific code.

### Isolated Report Generation

Report generation is separated from scanning because vulnerability detection and document rendering solve different problems. Scanners produce technical findings. `ReportBuilder` converts those findings into a structured JSON report. `ReportGenerator` renders that JSON into an HTML template and exports it as a PDF.

This separation allows the report layout, charts, and static report wording to change without modifying scanner detection logic. It also keeps scanner modules smaller and easier to test conceptually.

The trade-off is an extra transformation step between findings and final PDF output, but that step creates a stable report schema and keeps the reporting system reusable.

### Modular Backend Packages

The backend is organized into modular packages because different parts of the scanner change for different reasons. Payloads may change when new test cases are added. Scanners may change when a new vulnerability class is implemented. The response analyzer may change to reduce false positives. The reporter may change when document formatting is updated.

Separating these concerns reduces accidental coupling and supports team development. It also makes the architecture easier to explain and evaluate because each package maps to a clear responsibility in the DAST pipeline.

### Separation Between Reporting and Detection

The reporting system does not decide whether a vulnerability exists. It only presents confirmed findings that were produced by scanner modules and enriched by the correlation engine.

This decision prevents report formatting concerns from influencing detection logic. It also ensures that different output formats can be added later without rewriting scanners.

## 8. Engineering Challenges

The implementation reflects several engineering challenges that were addressed during development. These challenges are directly visible in the current backend structure and execution flow.

### Balancing Extensibility With Simplicity

The project needed to support multiple vulnerability classes without becoming too complex for a graduation project. A highly dynamic plugin system would have added unnecessary configuration and runtime behavior, while hard-coding all scanner logic in one file would have limited growth.

The team solved this by using modular scanner classes with a static scanner registry. This provides a clear extension point while keeping execution predictable. The selected solution fits the current local demo scope and leaves room for future scanner selection features.

### Eliminating Duplicated Scanner Logic

Different scanners require different detection techniques, but they all need the same basic capabilities: access to the target URL, an HTTP client, discovered endpoints, telemetry logging, and standardized result output.

The team solved this through `BaseScanner`, `AsyncSafeHttpClient`, `ResponseAnalyzer`, `PayloadManager`, and the shared `Finding` model. These components remove repeated setup code from individual scanners and allow each scanner to focus on its vulnerability-specific logic.

This approach was selected because duplicated scanner code would make the engine harder to maintain as more scanners are added.

### Supporting Multiple Vulnerability Types Through One Framework

The backend currently supports injection, authentication, authorization, and file-security checks. These vulnerability types have different inputs, payloads, and verification methods.

The solution was to normalize the scanner input as `Endpoint` objects and normalize scanner output as `Finding` objects. Scanners can implement different internal logic while still participating in the same orchestrator pipeline.

This made the architecture flexible without requiring every scanner to behave identically internally.

### Designing a Common Finding Model

A common finding model was difficult because each vulnerability type produces different evidence. For example, SQL injection evidence may include boolean variance, XSS evidence may include reflection context, and file-security evidence may include matched file signatures.

The team solved this by defining a shared `Finding` structure with a nested proof-of-concept model. The common fields support reporting consistency, while the evidence section allows scanners to include vulnerability-specific request and response details.

This solution was selected because it keeps reports consistent while preserving enough technical detail for each finding.

### Keeping Scanners Independent

Scanner independence was important because a failure in one scanner should not stop the entire assessment. It was also important that scanners did not need to know how reports are generated or how findings are stored.

The team solved this by running scanners through the `BaseScanner.execute()` wrapper and collecting their results through the orchestrator. Findings are saved centrally after each scanner returns.

This keeps scanners isolated and makes the scan pipeline more resilient during local testing.

### Managing Payloads Centrally

Hard-coded payloads inside scanner classes would make updates repetitive and error-prone. It would also mix detection code with payload data.

The team solved this by storing payload definitions under `engine/payloads/definitions` and loading them through `PayloadManager`. The payload manager also pre-compiles regex signatures where applicable.

This solution was selected because it creates one maintainable location for payload data and keeps scanners focused on request execution and verification.

### Providing Live Scan Progress Without Blocking the API

The scan engine runs after the initial API request has already returned. The frontend still needs progress updates during crawling, scanning, correlation, and report generation.

The team solved this using Django Channels WebSockets. The orchestrator sends telemetry to a scan-specific channel group, and the frontend receives those messages in real time.

This solution was chosen because the scan lifecycle is event-driven. WebSockets provide immediate updates without requiring repeated status polling.

### Building Reusable Reporting

Findings from different scanners must be presented in one consistent report. The difficulty is that scanners generate different evidence and severity data, but the final document must use one stable layout.

The team solved this with `ReportBuilder` and `ReportGenerator`. `ReportBuilder` creates a structured JSON report from findings, and `ReportGenerator` renders that report into an HTML-based PDF.

This approach was selected because it separates report data preparation from visual rendering and allows future report changes without scanner changes.

### Keeping Reports Consistent Across Scanners

Without a shared reporting schema, each scanner could produce findings with different field names, incomplete evidence, or inconsistent severity presentation.

The common `Finding` model and report builder solve this by enforcing a predictable structure before the PDF is generated. The report template can then render each finding using the same sections: category, severity, affected path, description, impact, recommendations, and proof of concept.

This solution improves report readability and reduces the risk of scanner-specific formatting issues.

### Designing for Additional Scanners

The architecture needed to support future scanner modules without major rewrites. This was difficult because the team had to avoid over-engineering while still keeping scanner integration clean.

The selected design uses the scanner registry, common endpoint model, common finding model, reusable HTTP client, centralized payloads, and shared response analysis helpers. A future scanner can reuse these components and join the same orchestration pipeline.

This gives the project a growth path while keeping the current implementation understandable.

## 9. Development History

The original development plan was to perform scanner validation against DVWA. During implementation, the team decided to build a dedicated vulnerable web application specifically for this project.

This was an engineering decision intended to make the project more controlled and repeatable. A dedicated vulnerable application allowed the team to design vulnerability scenarios that aligned directly with the implemented scanners and project milestones.

This strategy provided several advantages:

- Deterministic testing behavior.
- Stable implementation milestones.
- Predictable project phases.
- Controlled vulnerability coverage.
- Repeatable validation results.
- Easier debugging during scanner development.
- Better alignment with the graduation project timeline.

The dedicated vulnerable application also made it easier to validate scanner behavior end to end, from crawling and endpoint extraction through finding generation, correlation, and report output.

## 10. Future Improvements

### Current Implementation

The current implementation is a local development and demonstration DAST scanner. It includes:

- A Django ASGI backend.
- Django REST Framework endpoints for starting scans and downloading reports.
- SQLite storage for scan records and final report JSON.
- Background Python thread execution for scans.
- `httpx` and `asyncio` based scanner networking.
- Playwright-based crawling.
- Endpoint and parameter extraction.
- A static scanner registry.
- Modular scanners for the currently implemented vulnerability classes.
- Centralized JSON payload definitions.
- Shared response analysis utilities.
- In-memory finding collection during scan execution.
- Rule-based correlation for attack-chain findings.
- WebSocket telemetry through Django Channels using an in-memory channel layer.
- JSON report building and HTML-to-PDF report generation.

These features represent the current implemented system. They are intended for local development, testing, and project demonstration.

### Future Work

The following items are planned improvements and are not part of the current implementation:

- Redis-backed Channel Layer for WebSocket communication across multiple backend processes.
- Celery background workers for durable scan execution outside the Django request process.
- PostgreSQL for production-grade relational persistence.
- User authentication for scanner access control.
- Scan history APIs and UI views.
- Persistent normalized `Finding` storage throughout the scan lifecycle.
- Multi-user support with ownership boundaries between scans.
- Distributed scanning across multiple workers or hosts.
- Additional scanner modules for broader vulnerability coverage.
- Improved correlation engine with richer matching logic than the current rule-based approach.
- Authentication-aware scanning beyond raw cookie injection.
- Performance optimization for large applications and higher request volumes.

These future improvements are intentionally separated from the current implementation. They define the roadmap for evolving the project beyond the local graduation demo into a more complete scanning platform.
