# Architecture

This document describes the architecture of NexusFlow, a modular Dynamic Application Security Testing (DAST) platform. 

Rather than focusing only on implementing vulnerability checks, the project explores how a DAST platform can be structured into loosely coupled components responsible for crawling, endpoint discovery, vulnerability assessment, finding correlation, live monitoring, and report generation. 

The current implementation targets local development and controlled testing environments, prioritizing execution clarity and modularity.

## Related Documentation

- [README](../README.md)
- [Local Setup Guide](setup.md)
- [API Documentation](api.md)
- [Testing Guide](testing.md)
- [Architecture Diagrams](diagrams/)

## Design Goals

The primary architectural goals of the platform are:

- Keep the scanning engine modular so new scanners can be added with minimal changes.
- Separate the scanning engine from the web framework whenever possible.
- Isolate each stage of the scan pipeline into a dedicated responsibility.
- Stream scan progress in real time instead of waiting for scan completion.
- Generate structured findings that can later support reporting and higher-level correlation.

## Core Design Principles

### Separation of Concerns
Each stage of the assessment pipeline is implemented independently. Crawling, endpoint extraction, vulnerability scanning, finding correlation, and reporting are separate responsibilities with clearly defined inputs and outputs.

### Extensibility
Scanner implementations follow a shared contract and are loaded from a central registry, allowing new scanners to be introduced without changing the orchestration flow.

### Shared Infrastructure
Networking, scan context, payload handling, verification, and reporting are centralized rather than duplicated across scanners:
- **AsyncSafeHttpClient**: Centralizes asynchronous HTTP networking, enforcing timeouts, connection pooling, and request budgets globally.
- **ScanContext**: Acts as a centralized, read-only runtime state object holding assessment boundaries (e.g., target URL, abort flags) for all pipeline components.
- **PayloadManager**: Loads and manages test payloads from external JSON files, decoupling vulnerability test data from scanner execution logic.
- **ResponseAnalyzer**: Centralizes response verification routines to ensure consistent validation rules and reduce false positives across all scanners.
- **ReportBuilder**: Converts technical findings into structured JSON, isolating report generation and formatting from vulnerability detection.

### Framework Independence
Most scanning logic resides inside the engine package instead of Django-specific modules. Django primarily provides APIs, persistence, and WebSocket integration.

### Incremental Evolution
The architecture is designed so new capabilities can be introduced without restructuring the existing scan pipeline. Planned architectural features build upon the current design rather than replace it.

## Overall Architecture

The system is intentionally divided into independent applications so that the scanning engine, user interface, and vulnerable target can evolve separately.

NexusFlow is split into three main applications:

- `backend`: Django ASGI application that exposes scan APIs, WebSocket telemetry, scan orchestration, scanner modules, correlation, and reporting.
- `frontend/nexusflow`: React application that starts scans and displays progress, logs, findings, and reports.
- `vulnerable_app`: Flask application acting as a controlled target for scanner validation.

## Core Components

The backend scanning engine is composed of several specialized components that interact during a scan:

| Component | Responsibility |
|-----------|----------------|
| Orchestrator | Coordinates the complete scan pipeline |
| ScanContext | Stores shared runtime state |
| AsyncSafeHttpClient | Centralizes networking behavior |
| PlaywrightSpider | Crawls JavaScript-rendered applications |
| ParamExtractor | Builds structured endpoints |
| PayloadManager | Loads and manages test payloads from external JSON files |
| BaseScanner | Defines the scanner contract |
| ResponseAnalyzer | Centralizes response verification logic |
| FindingRepository | Temporary finding storage |
| CorrelationEngine | Relates findings across the same target |
| ReportBuilder | Produces structured reports |

## Runtime Execution Flow & Component Boundaries

At runtime, the execution flow is designed as a data pipeline where each stage produces an intermediate representation consumed by the next stage. This prevents tight coupling between crawling, scanning, reporting, and presentation.

1. **Initialization:** The frontend sends a target URL. The API creates a `Scan` database record and starts a background Python thread with a dedicated asyncio event loop.
2. **Context Setup:** A `ScanContext` is initialized to hold the target URL, request budget, timeouts, and abort state. The `AsyncSafeHttpClient` is instantiated using this context.
3. **Crawling:** The `Orchestrator` executes the `PlaywrightSpider`, which navigates the target application and captures raw links, forms, and network response URLs.
4. **Extraction:** The crawler hands raw HTML and links to the `ParamExtractor`. The extractor parses these inputs into structured, deduplicated `Endpoint` and `Parameter` objects.
5. **Scanning:** The `Orchestrator` feeds the structured `Endpoint` objects to all active scanners (loaded via the `SCANNER_REGISTRY`). Scanners execute concurrently using `asyncio.gather`.
6. **Storage:** As scanners identify vulnerabilities, they yield `Finding` objects which are immediately saved into the in-memory `FindingRepository`.
7. **Correlation:** Once all scanners complete, the `CorrelationEngine` reads the `FindingRepository`. It evaluates rules against the current findings to synthesize new attack-chain findings, storing them back in the repository.
8. **Reporting:** The `ReportBuilder` consumes the final state of the `FindingRepository` to produce a structured JSON report. Finally, the API updates the scan status and a PDF is generated upon request.

Live scan logs are sent through Django Channels to a scan-specific WebSocket group. The frontend subscribes to that WebSocket and converts backend telemetry into progress, activity feed entries, endpoint activity, findings, and report readiness.

## Extension Points

The architecture provides a clear path for integrating new vulnerability scanners without modifying the core orchestration pipeline.

To add a new scanner, the architectural flow is as follows:

1. **Inherit `BaseScanner`**: The new scanner implements the shared contract, accepting the target URL and shared HTTP client.
2. **Request Payloads**: The scanner retrieves its specific test cases dynamically from the `PayloadManager`.
3. **Execute Requests**: The scanner issues asynchronous network requests against the target using the `AsyncSafeHttpClient`.
4. **Validate Responses**: The scanner passes the HTTP responses to the `ResponseAnalyzer` to evaluate the presence of vulnerabilities using consistent, centralized rules.
5. **Yield Findings**: If a vulnerability is confirmed, the scanner returns a standardized `Finding` object.
6. **Register the Scanner**: The scanner class is added to the static `SCANNER_REGISTRY`, allowing the `Orchestrator` to automatically load and execute it concurrently alongside existing modules.

## Architectural Decisions and Trade-offs

The current architecture favors modularity, deterministic execution, and clear domain boundaries. The following decisions outline *why* specific technologies and patterns were chosen.

### Why Django and React
Django is utilized for the backend because the project requires a robust ecosystem for HTTP APIs, WebSocket integration (via Django Channels), persistence (ORM), and configuration management. It provides the necessary infrastructure to wrap the asynchronous scanning engine in a web-accessible API. 

React is used for the frontend because the scanner interface is highly stateful and event-driven. WebSockets push continuous updates (logs, findings, endpoint discovery) that require immediate UI re-rendering without full page reloads.

### Why Playwright
A modern DAST platform must understand Single Page Applications (SPAs) and JavaScript-rendered DOMs. Playwright was selected over simpler HTTP scrapers because it provides realistic browser behavior, allowing the engine to execute JavaScript, trigger network requests, and accurately capture dynamic form actions and inputs.

### Why AsyncSafeHttpClient
The scanner is heavily I/O-bound, sending thousands of HTTP requests. `AsyncSafeHttpClient` wraps `httpx.AsyncClient` to centralize networking behavior. This wrapper ensures that timeouts, connection pooling, cookie injection, and request budgets (defined in `ScanContext`) are enforced globally. It prevents individual scanners from reinventing HTTP logic or violating concurrency constraints.

### Why ScanContext
Instead of passing discrete variables (URL, cookies, timeout, abort flags) through multiple layers of function calls, `ScanContext` acts as a centralized runtime state object. This ensures that any component in the pipeline—from crawler to scanner—has read-only access to the assessment boundaries and can safely halt execution if an abort signal is received.

### Why PayloadManager
Vulnerability payloads are stored as external JSON files instead of being embedded directly inside scanner code. Scanners request payloads from the `PayloadManager` at runtime rather than hardcoding them into the Python modules. This centralization ensures that new payloads can be added, tuned, or removed without modifying the underlying scanner implementations. Consequently, payload libraries can evolve entirely independently from the core detection logic.

### Why ResponseAnalyzer
Individual scanners do not implement their own verification logic from scratch. Instead, response validation is centralized within the `ResponseAnalyzer`. By utilizing reusable verification routines across the platform, the engine significantly reduces duplicated code and ensures that all scanners follow consistent validation rules. This centralized approach helps systematically reduce false positives, and any improvements made to the verification heuristics automatically benefit every scanner in the pipeline.

### Why BaseScanner and the Scanner Registry
`BaseScanner` enforces a strict execution contract, ensuring every scanner processes `Endpoint` objects and returns `Finding` objects identically. Crucially, the base class isolates scanner failures; if one scanner throws an unhandled exception, the wrapper catches it, preventing a single faulty module from crashing the entire `asyncio` event loop.

The static `SCANNER_REGISTRY` avoids the complexity and security risks of dynamic module discovery at runtime. It provides a single, explicit extension point for adding new capabilities.

### Why the Correlation Engine
Individual scanners lack context about the broader system; they only report isolated vulnerabilities. The `CorrelationEngine` exists to relate findings across the same target. By evaluating rule-based criteria against the `FindingRepository`, it synthesizes attack chains (e.g., combining a file upload vulnerability with a directory traversal to flag a Remote Code Execution chain).

### Why Isolated ReportBuilder
Report generation is intentionally separated from vulnerability detection. Scanners produce technical `Finding` dataclasses. The `ReportBuilder` converts those findings into structured JSON, which is then rendered into HTML/PDF. This separation ensures that reporting layouts, severity charting, and export formats can evolve without requiring modifications to the scanner detection logic.

### Concurrency and Threading Trade-offs
Scans are executed in background Python threads managed by the Django process, creating a dedicated `asyncio` event loop per scan. While threads are simpler to deploy locally than a dedicated worker queue, they tie scan execution to the API process lifecycle. If the backend restarts, active scans are lost. This trade-off prioritizes local execution simplicity over distributed scalability.

### WebSocket Telemetry Trade-offs
The engine uses Django Channels with an in-memory channel layer to push live telemetry. This avoids polling overhead and keeps the frontend synchronized with real-time scan events. However, an in-memory layer restricts WebSocket state to a single process.

## Future Architectural Evolution

The architecture is designed to support the following infrastructure improvements as the project scales beyond local environments:

- **Durable Task Execution:** Replacing Python background threads with Celery background workers to execute scans outside the Django request process, ensuring scan durability.
- **Distributed Communication:** Implementing a Redis-backed Channel Layer to support WebSocket communication across multiple backend API processes.
- **Persistent Storage:** Transitioning from SQLite and in-memory finding storage to PostgreSQL for production-grade relational persistence and normalized `Finding` records.
- **Distributed Scanning:** Scaling the `Orchestrator` to distribute scanner module execution across multiple worker nodes.
