# Contributing to MCP Security Query Builders

Thank you for your interest in contributing to the MCP Security Query Builders project! This guide will help you get started with contributing code, documentation, or other improvements.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Adding a New Platform](#adding-a-new-platform)
- [Adding New Tools](#adding-new-tools)
- [Testing](#testing)
- [Code Style](#code-style)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## Code of Conduct

This project follows a code of conduct that all contributors are expected to uphold:

- Be respectful and inclusive
- Welcome diverse perspectives
- Focus on constructive criticism
- Prioritize the project's goals over personal preferences
- Maintain professional communication

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git
- Docker and Docker Compose (for containerized testing)
- Basic understanding of security platforms (Defender, CBC, Cortex, SentinelOne)
- Familiarity with MCP (Model Context Protocol)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/MCPs.git
   cd MCPs
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/ParadoxReagent/MCPs.git
   ```

### Keep Your Fork Updated

```bash
git fetch upstream
git checkout main
git merge upstream/main
```

## Development Setup

### Local Python Environment

1. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   # Install dependencies
   pip install -r requirements.txt

   # For development dependencies
   pip install pytest pytest-cov black flake8 mypy
   ```

3. Run the server:
   ```bash
   python server.py
   ```

### Docker Development

1. Build the image:
   ```bash
   docker compose build
   ```

2. Run the container:
   ```bash
   docker compose up
   ```

3. Test the SSE endpoint:
   ```bash
   curl http://localhost:8080/sse
   ```

## Project Structure

```
                  # Main QueryForge server
│   ├── cbc/                    # Carbon Black Cloud
│   │   ├── schema_loader.py
│   │   └── query_builder.py
│   ├── cortex/                 # Cortex XDR
│   │   ├── schema_loader.py
│   │   └── query_builder.py
│   ├── kql/                    # Microsoft Defender KQL
│   │   ├── schema_loader.py
│   │   └── query_builder.py
│   ├── s1/                     # SentinelOne
│   │   ├── schema_loader.py
│   │   └── query_builder.py
│   ├── shared/                 # Shared components
│   │   └── rag.py              # RAG service
│   └── server.py               # FastMCP entry point
├── kql_builder/                # Standalone KQL builder
├── tests/                      # Test suite
├── docs/                       # Additional documentation
└── README.md                   # Main documentation
```

### Key Files

| File | Purpose |
|------|---------|
| `server.py` | MCP tool registration and routing |
| `schema_loader.py` | Platform schema loading and caching |
| `query_builder.py` | Query construction logic |
| `rag.py` | RAG service for context retrieval |
| `requirements.txt` | Python dependencies |
| `Dockerfile` | Container image definition |
| `docker-compose.yml` | Container orchestration |

## Adding a New Platform

Follow these steps to add support for a new security platform:

### 1. Create Platform Directory

```bash
cd queryforge
mkdir platform_name
cd platform_name
```

### 2. Create Schema Loader

Create `schema_loader.py`:

```python
from pathlib import Path
from typing import Dict, Any, List
import json

class PlatformSchemaCache:
    """Schema cache for Platform Name queries."""

    def __init__(self, schema_path: Path):
        """
        Initialize schema cache.

        Args:
            schema_path: Path to schema JSON file or directory
        """
        self.schema_path = schema_path
        self._cache: Dict[str, Any] | None = None

    def load(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Load schema from cache or file.

        Args:
            force_refresh: Force reload from disk

        Returns:
            Schema dictionary
        """
        if self._cache is None or force_refresh:
            with open(self.schema_path) as f:
                self._cache = json.load(f)
        return self._cache

    def datasets(self) -> Dict[str, Any]:
        """Return available datasets/tables."""
        schema = self.load()
        return schema.get("datasets", {})

    def list_fields(self, dataset: str) -> List[Dict[str, Any]]:
        """
        Return fields for a dataset.

        Args:
            dataset: Dataset/table name

        Returns:
            List of field definitions
        """
        schema = self.load()
        datasets = schema.get("datasets", {})
        if dataset not in datasets:
            return []
        return datasets[dataset].get("fields", [])

    # Add platform-specific methods as needed
```

### 3. Create Query Builder

Create `query_builder.py`:

```python
from typing import Dict, Any, Optional, List, Tuple

class QueryBuildError(Exception):
    """Raised when query building fails."""
    pass

# Define constants
DEFAULT_DATASET = "default_dataset_name"
MAX_LIMIT = 10000

def build_platform_query(
    schema: Dict[str, Any],
    dataset: Optional[str] = None,
    filters: Optional[List[Dict[str, Any]]] = None,
    natural_language_intent: Optional[str] = None,
    limit: Optional[int] = None,
) -> Tuple[str, Dict[str, Any]]:
    """
    Build a query for Platform Name.

    Args:
        schema: Platform schema dictionary
        dataset: Target dataset/table
        filters: Structured filter definitions
        natural_language_intent: Natural language description
        limit: Result limit

    Returns:
        Tuple of (query_string, metadata_dict)

    Raises:
        QueryBuildError: If query construction fails
    """
    # Validate parameters
    if limit and limit > MAX_LIMIT:
        raise QueryBuildError(f"Limit exceeds maximum of {MAX_LIMIT}")

    dataset = dataset or DEFAULT_DATASET

    # Validate dataset
    datasets = schema.get("datasets", {})
    if dataset not in datasets:
        raise QueryBuildError(f"Unknown dataset: {dataset}")

    # Build query components
    query_parts = []

    # Add dataset selection
    query_parts.append(f"FROM {dataset}")

    # Process filters
    if filters:
        filter_clauses = []
        for f in filters:
            # Validate and build filter
            clause = _build_filter_clause(f, datasets[dataset])
            filter_clauses.append(clause)
        if filter_clauses:
            query_parts.append("WHERE " + " AND ".join(filter_clauses))

    # Add limit
    if limit:
        query_parts.append(f"LIMIT {limit}")

    # Assemble final query
    query = " ".join(query_parts)

    # Build metadata
    metadata = {
        "dataset": dataset,
        "filters_count": len(filters) if filters else 0,
        "limit": limit,
    }

    return query, metadata


def _build_filter_clause(
    filter_def: Dict[str, Any],
    dataset_schema: Dict[str, Any]
) -> str:
    """Build a single filter clause."""
    field = filter_def.get("field")
    operator = filter_def.get("operator", "=")
    value = filter_def.get("value")

    # Validate field exists
    fields = {f["name"]: f for f in dataset_schema.get("fields", [])}
    if field not in fields:
        raise QueryBuildError(f"Unknown field: {field}")

    # Format value based on type
    field_type = fields[field].get("type", "string")
    if field_type == "string":
        value = f'"{value}"'

    return f"{field} {operator} {value}"
```

### 4. Create RAG Document Builder

Add to `schema_loader.py` or create separate file:

```python
def build_platform_documents(schema: Dict[str, Any]) -> List[str]:
    """
    Build RAG documents from platform schema.

    Args:
        schema: Platform schema dictionary

    Returns:
        List of text documents for RAG indexing
    """
    documents = []

    # Add dataset descriptions
    datasets = schema.get("datasets", {})
    for name, info in datasets.items():
        doc = f"Dataset: {name}\n"
        if "description" in info:
            doc += f"Description: {info['description']}\n"

        # Add field information
        fields = info.get("fields", [])
        doc += f"Fields: {', '.join(f['name'] for f in fields)}\n"

        documents.append(doc)

    # Add example queries if available
    examples = schema.get("examples", [])
    for example in examples:
        doc = f"Example: {example['name']}\n"
        doc += f"Query: {example['query']}\n"
        if "description" in example:
            doc += f"Description: {example['description']}\n"
        documents.append(doc)

    return documents
```

### 5. Add Platform Schema

Create schema file (e.g., `platform_schema.json`):

```json
{
  "version": "1.0.0",
  "datasets": {
    "events": {
      "name": "Event Dataset",
      "description": "Main event telemetry",
      "fields": [
        {
          "name": "timestamp",
          "type": "datetime",
          "description": "Event timestamp"
        },
        {
          "name": "event_type",
          "type": "string",
          "description": "Type of event"
        }
      ]
    }
  },
  "examples": [
    {
      "name": "Recent events",
      "query": "FROM events WHERE timestamp > now() - 1d",
      "description": "Get events from last 24 hours"
    }
  ]
}
```

### 6. Create Tool Registration Module

Create `server_tools_platform.py`:

```python
"""Platform Name tool registration for QueryForge."""

import logging
from typing import Dict, Any, Optional, List
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from queryforge.platform_name.query_builder import (
    build_platform_query,
    QueryBuildError as PlatformQueryBuildError,
    DEFAULT_DATASET as PLATFORM_DEFAULT_DATASET,
)
from queryforge.server_runtime import ServerRuntime

logger = logging.getLogger(__name__)


class PlatformBuildQueryParams(BaseModel):
    """Parameters for building a Platform Name query."""
    
    dataset: Optional[str] = Field(
        default=None,
        description=f"Target dataset (defaults to {PLATFORM_DEFAULT_DATASET})"
    )
    filters: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Filter definitions"
    )
    natural_language_intent: Optional[str] = Field(
        default=None,
        description="Natural language description of what to search for"
    )
    limit: Optional[int] = Field(
        default=None,
        ge=1,
        le=10000,
        description="Maximum number of results to return"
    )


def register_platform_tools(mcp: FastMCP, runtime: ServerRuntime) -> None:
    """
    Register all Platform Name tools with the MCP server.
    
    Args:
        mcp: FastMCP server instance
        runtime: ServerRuntime instance providing shared state
    """
    
    @mcp.tool()
    def platform_list_datasets() -> Dict[str, Any]:
        """List available Platform Name datasets with descriptions."""
        try:
            datasets = runtime.platform_cache.datasets()
            logger.info("Listed %d Platform datasets", len(datasets))
            return {"datasets": datasets}
        except Exception as exc:
            logger.error("Failed to list Platform datasets: %s", exc)
            return {"error": str(exc)}
    
    @mcp.tool()
    def platform_get_dataset_fields(dataset: str) -> Dict[str, Any]:
        """
        Get available fields for a Platform Name dataset.
        
        Args:
            dataset: Dataset name
        
        Returns:
            Dictionary containing dataset info and field list
        """
        try:
            fields = runtime.platform_cache.list_fields(dataset)
            logger.info("Listed %d fields for Platform dataset: %s", len(fields), dataset)
            return {
                "dataset": dataset,
                "fields": fields
            }
        except Exception as exc:
            logger.error("Failed to get fields for dataset %s: %s", dataset, exc)
            return {"error": str(exc)}
    
    @mcp.tool()
    def platform_build_query(params: PlatformBuildQueryParams) -> Dict[str, Any]:
        """
        Build a Platform Name query from structured parameters or natural language.
        
        This tool converts your search intent into a valid Platform query. You can either:
        - Provide structured filters with field/operator/value
        - Describe what you want to find in natural language
        - Combine both approaches
        """
        schema = runtime.platform_cache.load()
        payload = params.model_dump()
        
        try:
            query, metadata = build_platform_query(schema, **payload)
            logger.info("Built Platform query for dataset=%s", metadata.get("dataset"))
            
            # Enhance with RAG context if natural language intent provided
            intent = payload.get("natural_language_intent")
            if intent and runtime.ensure_rag_initialized(timeout=5.0):
                try:
                    context = runtime.rag_service.search(
                        intent,
                        k=5,
                        source_filter="platform"
                    )
                    if context:
                        metadata["rag_context"] = context
                        logger.debug("Added RAG context to Platform query metadata")
                except Exception as exc:
                    logger.warning("Unable to attach Platform RAG context: %s", exc)
            
            return {"query": query, "metadata": metadata}
        
        except PlatformQueryBuildError as exc:
            logger.warning("Failed to build Platform query: %s", exc)
            return {"error": str(exc)}
```

### 7. Update ServerRuntime

Edit `server_runtime.py` to add the new platform:

```python
from queryforge.platform_name.schema_loader import (
    PlatformSchemaCache,
    build_platform_documents,
)

class ServerRuntime:
    def __init__(self, data_dir: Path | str = Path(".cache")) -> None:
        # ... existing initialization ...
        
        # Add Platform Name schema cache
        self.platform_schema_file = base_dir / "platform_name" / "platform_schema.json"
        self.platform_cache = PlatformSchemaCache(
            self.platform_schema_file,
            cache_dir=self.data_dir
        )
        
        # Update RAG service sources
        self.rag_service = UnifiedRAGService(
            sources=[
                # ... existing sources ...
                SchemaSource(
                    name="platform",
                    schema_cache=self.platform_cache,
                    loader=lambda cache, force=False: cache.load(force_refresh=force),
                    document_builder=build_platform_documents,
                    version_getter=self._platform_version,
                ),
            ],
            cache_dir=self.data_dir,
        )
    
    def _platform_version(self, cache: PlatformSchemaCache) -> Optional[str]:
        """Get Platform schema version."""
        try:
            data = cache.load()
        except Exception:
            return None
        version = data.get("version") if isinstance(data, dict) else None
        return str(version) if version else None
    
    def initialize_critical_components(self) -> None:
        """Initialize schema caches..."""
        # ... existing checks ...
        
        # Add Platform schema check
        schema_checks = {
            # ... existing checks ...
            "Platform": self.platform_schema_file,
        }
        
        # ... rest of initialization ...
        
        try:
            self.platform_cache.load()
            logger.info("✅ Platform schema loaded")
        except Exception as exc:
            logger.warning("⚠️ Failed to load Platform schema: %s", exc)
```

### 8. Register in Main Server

Edit `server.py`:

```python
from queryforge.server_tools_platform import register_platform_tools

# ... existing imports and setup ...

# Register all platform tools
register_cbc_tools(mcp, runtime)
register_cortex_tools(mcp, runtime)
register_kql_tools(mcp, runtime)
register_s1_tools(mcp, runtime)
register_platform_tools(mcp, runtime)  # Add new platform
register_shared_tools(mcp, runtime)
```

### 7. Add Tests

Create `tests/test_platform_query_builder.py`:

```python
import pytest
from queryforge.platform_name.query_builder import (
    build_platform_query,
    QueryBuildError,
)

def test_basic_query():
    """Test basic query building."""
    schema = {
        "datasets": {
            "events": {
                "fields": [
                    {"name": "timestamp", "type": "datetime"},
                    {"name": "event_type", "type": "string"}
                ]
            }
        }
    }

    query, metadata = build_platform_query(
        schema,
        dataset="events",
        filters=[{"field": "event_type", "operator": "=", "value": "login"}],
        limit=100
    )

    assert "FROM events" in query
    assert "event_type = \"login\"" in query
    assert "LIMIT 100" in query
    assert metadata["dataset"] == "events"
    assert metadata["filters_count"] == 1

def test_unknown_dataset():
    """Test error handling for unknown dataset."""
    schema = {"datasets": {}}

    with pytest.raises(QueryBuildError, match="Unknown dataset"):
        build_platform_query(schema, dataset="nonexistent")

def test_limit_enforcement():
    """Test limit maximum enforcement."""
    schema = {"datasets": {"events": {"fields": []}}}

    with pytest.raises(QueryBuildError, match="exceeds maximum"):
        build_platform_query(schema, dataset="events", limit=99999)
```

### 8. Update Documentation

1. Add platform section to `API_REFERENCE.md`
2. Update `ARCHITECTURE.md` with platform details
3. Add example queries to `README.md`

## Adding New Tools

To add a new tool to an existing platform:

1. **Define the tool function**:
   ```python
   @mcp.tool
   def platform_new_tool(params: NewToolParams) -> Dict[str, Any]:
       """
       Brief description of what this tool does.

       This will appear in MCP tool listings.
       """
       # Implementation
       return {"result": ...}
   ```

2. **Create Pydantic parameter model**:
   ```python
   class NewToolParams(BaseModel):
       param1: str = Field(..., description="Parameter description")
       param2: Optional[int] = Field(None, description="Optional parameter")
   ```

3. **Add tests**:
   ```python
   def test_new_tool():
       result = platform_new_tool(NewToolParams(param1="value"))
       assert "result" in result
   ```

4. **Document in API_REFERENCE.md**

## Testing

### Running Tests

```bash
# All tests
pytest

# Specific platform
pytest tests/test_platform_query_builder.py

# With coverage
pytest --cov=queryforge --cov-report=html

# Verbose output
pytest -v
```

### Writing Tests

Follow these guidelines:

1. **Test file naming**: `test_<module_name>.py`
2. **Test function naming**: `test_<scenario_description>`
3. **Use fixtures** for common setup:
   ```python
   @pytest.fixture
   def sample_schema():
       return {"datasets": {...}}
   ```

4. **Test categories**:
   - Happy path (valid inputs)
   - Error cases (invalid inputs)
   - Edge cases (empty inputs, max limits)
   - Integration (full tool invocation)

5. **Use parametrize** for multiple test cases:
   ```python
   @pytest.mark.parametrize("limit,expected", [
       (10, 10),
       (1000, 1000),
       (99999, pytest.raises(QueryBuildError)),
   ])
   def test_limit_values(limit, expected):
       # Test implementation
   ```

## Code Style

### Python Style Guide

Follow PEP 8 with these additions:

1. **Imports**: Group in order (stdlib, third-party, local)
   ```python
   import os
   from pathlib import Path

   from fastmcp import FastMCP
   from pydantic import BaseModel

   from queryforge.kql.schema_loader import SchemaCache
   ```

2. **Type hints**: Use for all function signatures
   ```python
   def build_query(
       schema: Dict[str, Any],
       limit: Optional[int] = None
   ) -> Tuple[str, Dict[str, Any]]:
   ```

3. **Docstrings**: Google style for all public functions
   ```python
   def function_name(param1: str, param2: int) -> str:
       """
       Brief description of function.

       Longer description if needed.

       Args:
           param1: Description of param1
           param2: Description of param2

       Returns:
           Description of return value

       Raises:
           ValueError: When something goes wrong
       """
   ```

4. **Line length**: 100 characters max (not 79)

5. **Quotes**: Double quotes for strings

### Code Formatting

Use Black for automatic formatting:

```bash
# Format all files
black 

# Check without modifying
black --check 
```

### Linting

```bash
# Flake8
flake8  --max-line-length=100

# MyPy (type checking)
mypy  --ignore-missing-imports
```

## Documentation

### Docstring Requirements

All public functions, classes, and modules must have docstrings:

```python
def build_query(schema: Dict, **kwargs) -> Tuple[str, Dict]:
    """
    Build a query from schema and parameters.

    Args:
        schema: Platform schema dictionary
        **kwargs: Query building parameters

    Returns:
        Tuple of (query_string, metadata_dict)

    Raises:
        QueryBuildError: If query building fails

    Example:
        >>> schema = load_schema()
        >>> query, meta = build_query(schema, limit=100)
        >>> print(query)
        'SELECT * FROM table LIMIT 100'
    """
```

### README Updates

When adding features:

1. Update feature list in main README.md
2. Add usage examples
3. Update roadmap if applicable
4. Add to changelog (if maintained)

### API Documentation

Update `API_REFERENCE.md` for new tools:

- Parameter table
- Return format
- Example usage
- Error responses

## Pull Request Process

### Before Submitting

1. **Run tests**: `pytest`
2. **Format code**: `black .`
3. **Check linting**: `flake8 .`
4. **Update docs**: Add/update relevant documentation
5. **Test locally**: Run the server and test manually

### PR Description

Include in your PR:

1. **Summary**: What does this PR do?
2. **Motivation**: Why is this change needed?
3. **Changes**: List of modifications
4. **Testing**: How did you test this?
5. **Screenshots**: If applicable
6. **Related Issues**: Link to issues

Example:
```markdown
## Summary
Adds support for CrowdStrike Humio query building

## Motivation
Users requested CrowdStrike support to complete the security platform suite

## Changes
- Added `cs/` directory with schema loader and query builder
- Registered CS tools in unified server
- Added 15 test cases
- Updated API_REFERENCE.md and README.md

## Testing
- [x] All existing tests pass
- [x] Added new tests for CS builder
- [x] Manually tested query building
- [x] Tested Docker deployment

## Related Issues
Closes #42
```

### Review Process

1. **Automated checks**: CI/CD runs tests and linting
2. **Code review**: Maintainer reviews code
3. **Feedback**: Address review comments
4. **Approval**: Maintainer approves PR
5. **Merge**: PR is merged to main branch

### After Merge

- Your changes will be included in the next release
- Update your fork: `git pull upstream main`
- Close related issues

## Release Process

(For maintainers)

1. **Version bump**: Update version numbers
2. **Changelog**: Update CHANGELOG.md
3. **Tag release**: `git tag v1.2.3`
4. **Push tag**: `git push origin v1.2.3`
5. **GitHub release**: Create release on GitHub
6. **Docker images**: Build and push new images

## Getting Help

- **Issues**: Open an issue on GitHub
- **Discussions**: Use GitHub Discussions
- **Email**: [Project contact email]

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

Thank you for contributing!
