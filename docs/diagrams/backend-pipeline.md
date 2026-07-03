# Backend Pipeline Diagram

This diagram represents the complete current execution flow from starting a scan in the React frontend to downloading the generated report. It focuses on the backend pipeline and the order in which the major scan components run.

Related documentation: [Architecture](../architecture.md), [API](../api.md), [Testing](../testing.md), [Diagram Index](README.md).

```mermaid
flowchart TD
    A["React Frontend<br/>User enters target URL"] --> B["Django API<br/>POST /api/scan/start/"]
    B --> C["Create Scan row<br/>status = Running"]
    C --> D["Background Thread<br/>run_scan_in_background"]
    D --> E["Create asyncio event loop"]
    E --> F["Create ScanContext<br/>target_url, cookies, request budget"]
    F --> G["Create AsyncSafeHttpClient<br/>httpx.AsyncClient wrapper"]
    G --> H["Create Orchestrator"]

    H --> I["Load Scanner Registry<br/>SCANNER_REGISTRY"]
    I --> J["Instantiate Individual Scanners"]
    J --> K["Broadcast initialization logs<br/>Django Channels WebSocket"]

    K --> L["Phase 1: Discovery<br/>PlaywrightSpider"]
    L --> M["Crawler Output<br/>links and forms"]
    M --> N["Parameter Extraction<br/>ParamExtractor.extract"]
    N --> O["Endpoint Models<br/>Endpoint + Parameter"]

    O --> P["Phase 2: Vulnerability Assessment<br/>asyncio.gather"]
    P --> Q1["SQLInjectionScanner"]
    P --> Q2["XSSScanner"]
    P --> Q3["AuthScanner"]
    P --> Q4["IDORScanner"]
    P --> Q5["SensitiveFileDisclosureScanner"]
    P --> Q6["FileUploadScanner"]
    P --> Q7["LFIScanner"]
    P --> Q8["PathTraversalScanner"]

    Q1 --> R["Findings"]
    Q2 --> R
    Q3 --> R
    Q4 --> R
    Q5 --> R
    Q6 --> R
    Q7 --> R
    Q8 --> R

    R --> S["FindingRepository<br/>in-memory deduplication"]
    S --> T["Phase 3: Correlation Engine<br/>rules.json"]
    T --> U["Attack Chain Findings<br/>when rules match"]
    U --> S

    S --> V["Phase 4: Report Builder<br/>build_json_report"]
    V --> W["Final JSON Report"]
    W --> X["Update Scan row<br/>status = Completed<br/>overall_threat_level<br/>full_report_json"]
    X --> Y["Completion WebSocket Log<br/>Frontend marks report ready"]

    Y --> Z["React Frontend<br/>User opens report"]
    Z --> AA["Django API<br/>GET /api/scan/{scan_id}/report/"]
    AA --> AB["Load completed Scan<br/>read full_report_json"]
    AB --> AC["Report Generator<br/>Jinja2 + charts + Playwright"]
    AC --> AD["HTML Report Template<br/>reporter/templates/report.html"]
    AD --> AE["PDF Report<br/>temporary output file"]
    AE --> AF["Download<br/>FileResponse application/pdf"]
```

Interpretation: the pipeline is sequential at the phase level but asynchronous inside the scanner execution phase. The crawler runs first, endpoint extraction prepares scanner input, all registered scanners run concurrently, findings are correlated, the JSON report is stored, and the PDF is generated only when the report download endpoint is requested.
