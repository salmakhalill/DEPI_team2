# Sequence Diagram

This diagram follows the current scan lifecycle from the frontend starting a scan, through backend execution, live WebSocket telemetry, report storage, and PDF download.

Related documentation: [Architecture](../architecture.md), [API](../api.md), [Testing](../testing.md), [Diagram Index](README.md).

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant Frontend as React Frontend
    participant API as Django API
    participant DB as SQLite
    participant Thread as Background Thread
    participant Orchestrator
    participant WS as Channels WebSocket
    participant Crawler as PlaywrightSpider
    participant Extractor as ParamExtractor
    participant Registry as Scanner Registry
    participant Scanners as Individual Scanners
    participant Repo as FindingRepository
    participant Correlation as CorrelationEngine
    participant Builder as ReportBuilder
    participant Generator as ReportGenerator

    User->>Frontend: Enter target URL and optional cookies
    Frontend->>API: POST /api/scan/start/
    API->>DB: Create Scan(status="Running")
    API->>Thread: Start run_scan_in_background(scan_id, target_url, cookies)
    API-->>Frontend: 201 Created(scan_id, status)

    Frontend->>WS: Connect /ws/scan/{scan_id}/
    WS-->>Frontend: Connection accepted

    Thread->>Thread: Create asyncio event loop
    Thread->>Orchestrator: Create ScanContext, AsyncSafeHttpClient, Orchestrator
    Thread->>Orchestrator: load_scanners()
    Orchestrator->>Registry: Read SCANNER_REGISTRY
    Registry-->>Orchestrator: Scanner classes
    Orchestrator->>WS: Broadcast module initialization logs
    WS-->>Frontend: Live telemetry messages

    Orchestrator->>WS: Broadcast Phase 1 discovery log
    Orchestrator->>Crawler: crawl()
    Crawler-->>Orchestrator: Raw crawl data(links, forms)
    Orchestrator->>Extractor: extract(raw_crawl_data)
    Extractor-->>Orchestrator: List of Endpoint objects
    Orchestrator->>WS: Broadcast attack surface count
    WS-->>Frontend: Discovery and endpoint logs

    Orchestrator->>WS: Broadcast Phase 2 scanner execution log
    Orchestrator->>Scanners: asyncio.gather(scanner.execute(endpoints))
    Scanners->>Scanners: Load payloads and send async httpx requests
    Scanners-->>Orchestrator: Lists of Finding objects
    Orchestrator->>Repo: save_all(findings)
    Orchestrator->>WS: Broadcast scanner results
    WS-->>Frontend: Finding and scanner telemetry

    Orchestrator->>WS: Broadcast Phase 3 correlation log
    Orchestrator->>Correlation: run_correlation()
    Correlation->>Repo: get_all()
    Correlation->>Repo: save(chain_finding) when rule matches
    Correlation-->>Orchestrator: Correlation complete

    Orchestrator->>WS: Broadcast Phase 4 report-building log
    Orchestrator->>Repo: get_all()
    Repo-->>Orchestrator: All findings
    Orchestrator->>Builder: build_json_report(scan_id, target_url, findings, start_time)
    Builder-->>Orchestrator: Final report JSON
    Orchestrator-->>Thread: report_json

    Thread->>DB: Update Scan(status="Completed", threat_level, full_report_json)
    Thread->>WS: Broadcast scan completed log
    WS-->>Frontend: Completion message and report-ready state

    User->>Frontend: Open/download report
    Frontend->>API: GET /api/scan/{scan_id}/report/
    API->>DB: Load Scan by UUID
    DB-->>API: Completed scan with full_report_json
    API->>Generator: generate_pdf(full_report_json, output_pdf_path)
    Generator-->>API: PDF file written
    API-->>Frontend: application/pdf file response
    Frontend-->>User: Display or download PDF report
```

Interpretation: the scan starts through HTTP, continues in a background thread, and sends live messages through WebSockets. The PDF is not returned when the scan starts; it is generated later when the report endpoint is requested for a completed scan.
