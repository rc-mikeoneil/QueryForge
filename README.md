# QueryForge

**Multi-Platform Security Query Builder with RAG Enhancement**

QueryForge is a unified Model Context Protocol (MCP) server that helps security analysts transform natural-language intent into production-ready hunting queries across Microsoft Defender (KQL), CrowdStrike (CQL), VMware Carbon Black Cloud & Response, Palo Alto Cortex XDR, and SentinelOne. The system includes a developer-friendly RAG layer, Docker-first deployment, and support for both stdio and SSE transports.

## Quick Start

**Docker Compose (Recommended):**
```bash
docker compose build
docker compose up -d
```

**Docker (Alternative):**
```bash
docker build -t queryforge --no-cache .
docker run -d -p 8080:8080 --name queryforge queryforge:latest
```

**Local Python:**
```bash
pip install -r requirements.txt
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
python -m queryforge.server.server
```

## Table of Contents
- [QueryForge](#queryforge)
  - [Quick Start](#quick-start)
  - [Table of Contents](#table-of-contents)
  - [Highlights](#highlights)
  - [Documentation](#documentation)
    - [Core Documentation](#core-documentation)
    - [Advanced Topics](#advanced-topics)
    - [Contributing](#contributing)
  - [Repository Layout](#repository-layout)
  - [Service Capabilities](#service-capabilities)
    - [QueryForge](#queryforge-1)
    - [Microsoft Defender KQL Builder](#microsoft-defender-kql-builder)
    - [Carbon Black Cloud Builder](#carbon-black-cloud-builder)
    - [Cortex XDR Builder](#cortex-xdr-builder)
    - [SentinelOne Builder](#sentinelone-builder)
    - [CrowdStrike Query Language (CQL) Builder](#crowdstrike-query-language-cql-builder)
    - [Carbon Black Response (CBR) Builder](#carbon-black-response-cbr-builder)
  - [Getting Started (Local Python)](#getting-started-local-python)
  - [Running with Docker](#running-with-docker)
    - [QueryForge](#queryforge-2)
  - [Connecting from VS Code Cline](#connecting-from-vs-code-cline)
  - [Testing](#testing)
  - [Additional Resources](#additional-resources)
    - [Quick Links](#quick-links)
    - [For Developers](#for-developers)
    - [For Users](#for-users)

## Highlights
- **Unified multi-platform service** that exposes Defender KQL, Carbon Black Cloud & Response, CrowdStrike CQL, Cortex XDR, and SentinelOne tooling from a single MCP endpoint with shared caching and retrieval-augmented generation (RAG).
- **RAG-Enhanced Query Building** transforms simple queries into comprehensive multi-indicator searches. Example: "RDP" becomes `(netconn_port:3389 OR process_name:mstsc.exe OR process_name:rdpclip.exe)` automatically.
- **CrowdStrike Query Language (CQL)** support with 280+ schemas, 123 example queries, 43 functions, and 25 MITRE ATT&CK technique mappings for comprehensive threat hunting.
- **Rapidfuzz-powered RAG index** that bootstraps at startup for low-latency context retrieval across all schemas.
- **Combined build+validate tools** (`*_build_query_validated`) provide 10x faster query building with automatic validation and corrections in a single API call.
- **First-class SSE transport** across Docker images and example clients, enabling easy integration with web apps and MCP extensions.
- **Comprehensive regression tests** for parsers, schema caches, tool defaults, and guardrails across every builder.

## Documentation

Comprehensive documentation is available to help you get started and understand the system:

### Core Documentation
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - System design, data flows, and component architecture
- **[API_REFERENCE.md](docs/API_REFERENCE.md)** - Complete API documentation for all 40+ MCP tools
- **[DEPLOYMENT.md](docs/DEPLOYMENT.md)** - Deployment guides for local, Docker, Kubernetes, and cloud platforms
- **[TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)** - Common issues and solutions

### Advanced Topics
- **[docs/RAG_INTERNALS.md](docs/RAG_INTERNALS.md)** - Deep dive into the RAG system and semantic search
- **[docs/RAG_ENHANCEMENT_GUIDE.md](docs/RAG_ENHANCEMENT_GUIDE.md)** - RAG-enhanced query building developer guide
- **[docs/SECURITY_CONCEPTS.md](docs/SECURITY_CONCEPTS.md)** - Security concepts recognized by QueryForge
- **[docs/SCHEMA_MANAGEMENT.md](docs/SCHEMA_MANAGEMENT.md)** - Schema versioning, updates, and cache management

### Contributing
- **[CONTRIBUTING.md](docs/CONTRIBUTING.md)** - Guidelines for contributing code, adding platforms, and development workflow

## Repository Layout
The project follows a clean, organized structure with clear separation of concerns:

| Path | Description |
| --- | --- |
| `src/queryforge/` | Main application package |
| `src/queryforge/server/` | MCP server implementation and tool registration |
| `├── server.py` | FastMCP entry point with minimal orchestration logic |
| `├── server_runtime.py` | Runtime coordination, schema management, and two-phase initialization |
| `├── server_tools_*.py` | Modular tool registration files, one per platform (kql, cbc, cbr, cortex, cql, s1, shared) |
| `src/queryforge/platforms/` | Platform-specific implementations |
| `├── cbc/` | Carbon Black Cloud schema loaders, query builders, and RAG document builders |
| `├── cbr/` | Carbon Black Response schema loaders and query builders |
| `├── cortex/` | Cortex XDR dataset loaders, pipeline builders, function/operator references |
| `├── cql/` | CrowdStrike query builder with 280+ schema files, functions, operators, and examples |
| `├── kql/` | Defender KQL schema cache, query builder, and example query catalog |
| `├── s1/` | SentinelOne schema loader, dataset inference helpers, and query builder utilities |
| `src/queryforge/shared/` | Shared components including unified RAG service, configuration, and security utilities |
| `tests/` | Pytest suite covering builders, schema caching, RAG behavior, and transport guards |
| `docs/` | Comprehensive documentation including architecture, API reference, deployment guides, and fix summaries |
| `ecs/` | AWS ECS deployment configurations and Terraform scripts |
| `scripts/` | Utility scripts for schema management and maintenance |

## Service Capabilities

### QueryForge
The recommended entry point for production workflows. Key capabilities include:
- Single MCP registration that surfaces `kql_*`, `cbc_*`, `cbr_*`, `cortex_*`, `cql_*`, and `s1_*` tool namespaces.
- Automatic schema hydration with persisted caches under `.cache/` and refresh toggles per platform.
- **RAG-Enhanced Query Building** that automatically expands security concepts into comprehensive multi-indicator queries.
- Unified RAG layer that merges documentation snippets from all platforms and supports forced re-indexing.
- Configurable SSE or stdio transport (Docker images default to SSE on port `8080`).
- Comprehensive support for 6 security platforms with 40+ MCP tools for query building, validation, and schema exploration.

**RAG Enhancement Examples:**

Simple input queries are automatically enhanced with multiple indicators:

| User Input | Enhanced Query (CBC) |
|------------|---------------------|
| "RDP" | `(netconn_port:3389 OR process_name:mstsc.exe OR process_name:rdpclip.exe)` |
| "PowerShell" | `(process_name:powershell.exe OR process_name:pwsh.exe OR process_cmdline:"-enc")` |
| "SMB" | `(netconn_port:445 OR netconn_port:139 OR process_name:net.exe)` |

See **[SECURITY_CONCEPTS.md](docs/SECURITY_CONCEPTS.md)** for the full list of recognized security patterns and **[RAG_ENHANCEMENT_GUIDE.md](docs/RAG_ENHANCEMENT_GUIDE.md)** for implementation details.

### Microsoft Defender KQL Builder
- `schema_scraper.py` keeps a cached Defender table/column inventory.
- `build_kql_query` safeguards table, column, and where-clause selection from natural-language prompts.
- Retrieval utilities (`rag.py`, `retrieve_context`) embed Microsoft Learn documentation.
- `query_logging.py` captures metadata for downstream audit trails.
- Docker Compose profile exposes SSE transport on port `8083` with persistent caches.

### Carbon Black Cloud Builder
- Search-type aware schema cache (`CBCSchemaCache`) with normalization helpers.
- Query builder that translates intent into Carbon Black search syntax with guardrails and auto-applied defaults.
- RAG document builder seeded with Carbon Black schema guides.
- Ships inside the unified server and can also be targeted directly over SSE when running all services via Docker.

### Cortex XDR Builder
- Dataset introspection helpers to list fields, operators, and enums from the Cortex schema cache.
- Query builder that assembles XQL pipelines, enforces dataset compatibility, and auto-tunes time ranges.
- RAG integration that surfaces Cortex documentation snippets for natural-language prompts.

### SentinelOne Builder
- Schema loader backed by the curated SentinelOne exports in `s1_builder/`.
- Query builder with dataset inference (`infer_dataset`) and boolean defaults to streamline query authoring.
- RAG document builder so SentinelOne fields and examples are searchable alongside other platforms.

### CrowdStrike Query Language (CQL) Builder
- Comprehensive schema repository with 280+ JSON files covering 10 event types, 43 functions, and 19 operators.
- Query builder with autocomplete support and real-time validation for CQL syntax.
- 123 categorized example queries including 25 MITRE ATT&CK technique mappings for threat hunting.
- 54 how-to guides and 34 best practice documents for query optimization and security analysis.

### Carbon Black Response (CBR) Builder
- Dual dataset support for server-generated events (78 fields) and raw endpoint events (63 fields).
- Natural language and structured query building for CBR's field:value syntax with IOC extraction.
- Security concept expansion and RAG enhancement for comprehensive query coverage.
- Comprehensive validation with performance optimization warnings and injection prevention.

## Getting Started (Local Python)
1. **Create a virtual environment** (Python 3.10+ recommended):
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the MCP server**:
   ```bash
   export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
   python -m queryforge.server.server
   ```
   - The server auto-creates a `.cache/` directory to persist schema metadata and embeddings.
   - Set `MCP_TRANSPORT=stdio` to prefer stdio transport when integrating with terminal-first clients.

## Running with Docker
The project ships with ready-to-use Dockerfile and Compose configuration.

### QueryForge

**Using Docker Compose (Recommended):**
```bash
docker compose up --build -d
```
- Exposes SSE transport on `http://localhost:8080/sse`.
- Persists schema and embedding caches in the `queryforge_cache` named volume.
- Health checks ensure the server is reachable before clients attach.

**Using Docker Directly:**
```bash
docker build -t queryforge --no-cache .
docker run -d -p 8080:8080 --name queryforge queryforge:latest
```
- Build creates a fresh image without using cache layers.
- Run starts the container in detached mode with port 8080 mapped to host.
- Access the SSE endpoint at `http://localhost:8080/sse`.

## Connecting from VS Code Cline
1. **Install the Cline extension** from the VS Code marketplace (requires VS Code ≥ 1.87).
2. **Start QueryForge** locally or with Docker. For SSE, ensure it is reachable at `http://localhost:8080/sse`.
3. **Open VS Code settings (JSON)** and add an entry to `cline.mcpServers`:
   ```json
   {
     "cline.mcpServers": [
       {
         "name": "QueryForge",
         "type": "sse",
         "url": "http://localhost:8080/sse"
       }
     ]
   }
   ```
   - Use `type: "stdio"` with a `command` array instead if you prefer running the Python script directly (`"command": ["python", "-m", "queryforge.server.server"]`, with appropriate `PYTHONPATH` set).
4. **Reload VS Code** (or run “Cline: Reload MCP Servers”) so the extension discovers the new endpoint.
5. **Connect and explore tools** from the Cline side panel; all 40+ MCP tools from QueryForge (KQL, CBC, CBR, Cortex, CQL, S1) are available.

## Testing
From the repository root run:
```bash
pytest
```
Or target a specific module:
```bash
pytest tests/test_kql_builder.py
pytest tests/test_cbc_builder.py
pytest tests/test_cortex_builder.py
pytest tests/test_schema_cache.py
```

## Additional Resources

### Quick Links
- [System Architecture](docs/ARCHITECTURE.md#high-level-architecture) - Understand how components work together
- [API Quick Start](docs/API_REFERENCE.md#overview) - Jump into using the tools
- [Deployment Options](docs/DEPLOYMENT.md#deployment-options) - Choose the right deployment method
- [Common Issues](docs/TROUBLESHOOTING.md#common-issues) - Quick solutions to frequent problems

### For Developers
- [Adding a New Platform](docs/CONTRIBUTING.md#adding-a-new-platform) - Step-by-step guide
- [Testing Guidelines](docs/CONTRIBUTING.md#testing) - How to write and run tests
- [Code Style Guide](docs/CONTRIBUTING.md#code-style) - Formatting and conventions

### For Users
- [Tool Reference](docs/API_REFERENCE.md#table-of-contents) - Find the right tool for your task
- [Example Queries](docs/API_REFERENCE.md#examples) - Real-world usage examples
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions
