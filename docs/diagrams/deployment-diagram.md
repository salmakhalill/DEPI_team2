# Deployment Diagram

This diagram represents the current local development deployment only. It shows the local browser, Vite frontend, Django backend process, background scan thread, Playwright runtime, SQLite database, and Flask vulnerable application.

Related documentation: [Architecture](../architecture.md), [Setup](../setup.md), [Testing](../testing.md), [Diagram Index](README.md).

```mermaid
flowchart TB
    subgraph DevMachine["Developer Machine"]
        Browser["Web Browser"]

        subgraph FrontendProcess["Frontend Process"]
            Vite["Vite Dev Server<br/>React App<br/>http://localhost:3000"]
        end

        subgraph BackendProcess["Backend Process"]
            Django["Django ASGI App<br/>runserver / Daphne<br/>http://localhost:8000"]
            Channels["Django Channels<br/>InMemoryChannelLayer"]
            ScanThread["Background Scan Thread<br/>one thread per scan"]
            AsyncLoop["Thread-local asyncio event loop"]
            Httpx["httpx.AsyncClient"]
            PlaywrightBackend["Playwright Chromium<br/>crawler and PDF rendering"]
            SQLite["SQLite<br/>backend/db.sqlite3"]
            TempPDF["Temporary PDF Output<br/>system temp directory"]
        end

        subgraph VulnerableProcess["Vulnerable App Process"]
            Flask["Flask Vulnerable App<br/>http://127.0.0.1:5004"]
            VulnSQLite["SQLite<br/>vulnerable app database"]
            Uploads["static/uploads"]
            Templates["Jinja Templates"]
        end
    end

    Browser -->|HTTP UI| Vite
    Vite -->|POST /api/scan/start| Django
    Vite -->|GET /api/scan/{id}/report| Django
    Vite <-->|ws://localhost:8000/ws/scan/{id}/| Django

    Django --> Channels
    Django --> SQLite
    Django --> ScanThread
    ScanThread --> AsyncLoop
    ScanThread --> PlaywrightBackend
    ScanThread --> Httpx
    PlaywrightBackend -->|crawl target| Flask
    Httpx -->|scanner requests| Flask
    Flask --> VulnSQLite
    Flask --> Uploads
    Flask --> Templates

    Django -->|generate PDF on download| PlaywrightBackend
    PlaywrightBackend --> TempPDF
    Django -->|PDF file response| Vite
```

Interpretation: all services run on the same local machine. The frontend is served by Vite, the backend is a local Django ASGI process, scan work runs inside a background thread in that backend process, and the target is a separate local Flask process.
