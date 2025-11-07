# Schema Management Guide

Comprehensive guide to managing, updating, and maintaining schemas across all security platforms.

## Table of Contents

- [Overview](#overview)
- [Schema Structure](#schema-structure)
- [Version Management](#version-management)
- [Updating Schemas](#updating-schemas)
- [Schema Validation](#schema-validation)
- [Cache Management](#cache-management)
- [Best Practices](#best-practices)
- [Platform-Specific Details](#platform-specific-details)

## Overview

Each security platform (KQL, CBC, Cortex, S1) maintains its own schema definition that includes:
- Available tables/datasets
- Field definitions and types
- Example queries
- Operators and functions
- Best practices

Proper schema management ensures:
- Accurate query building
- Up-to-date field suggestions
- Valid query syntax
- Efficient caching

## Schema Structure

### Common Schema Elements

All platform schemas share these core elements:

```json
{
  "version": "1.0.0",
  "updated_at": "2024-01-15T10:30:00Z",
  "datasets": {
    "dataset_name": {
      "name": "Display Name",
      "description": "Dataset description",
      "fields": [
        {
          "name": "field_name",
          "type": "string|datetime|integer|boolean",
          "description": "Field description",
          "example": "Example value",
          "required": false
        }
      ]
    }
  },
  "examples": [
    {
      "name": "Example name",
      "query": "Query string",
      "description": "What this query does"
    }
  ]
}
```

### Platform-Specific Extensions

Each platform may add additional metadata:

**KQL**:
```json
{
  "url": "https://learn.microsoft.com/...",
  "retention_days": 30,
  "table_type": "standard|custom"
}
```

**CBC**:
```json
{
  "search_types": {
    "process_search": {...},
    "binary_search": {...}
  },
  "operators": {...},
  "best_practices": [...]
}
```

**Cortex**:
```json
{
  "functions": [...],
  "operators": {...},
  "enum_values": {...},
  "field_groups": {...}
}
```

**S1**:
```json
{
  "metadata": {
    "dataset_type": "events|aggregated",
    "retention_policy": "..."
  }
}
```

## Version Management

### Versioning Scheme

We use semantic versioning: `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes (field removed, type changed)
- **MINOR**: New features (new fields, new tables)
- **PATCH**: Bug fixes (description updates, examples added)

### Version Tracking

Each schema has a version number that triggers cache invalidation:

**KQL**:
```python
class SchemaCache:
    @property
    def version(self) -> int:
        """Return schema version (timestamp-based)."""
        return int(self.schema_path.stat().st_mtime)
```

**Other Platforms**:
```python
def get_version(cache) -> str:
    schema = cache.load()
    return schema.get("version", "unknown")
```

### Version Comparison

```python
def is_schema_updated(cache, cached_version) -> bool:
    """Check if schema has been updated."""
    current_version = get_version(cache)
    return current_version != cached_version
```

### Version History

Maintain a changelog for each schema:

```
## [1.2.0] - 2024-01-15
### Added
- New field: `ParentProcessId` in DeviceProcessEvents
- Example query for ransomware detection

### Changed
- Updated description for `ProcessCommandLine`

### Removed
- Deprecated field: `OldFieldName`

## [1.1.0] - 2023-12-01
...
```

## Updating Schemas

### Update Workflow

```
1. Identify changes in platform
   ↓
2. Update schema JSON files
   ↓
3. Increment version number
   ↓
4. Update CHANGELOG
   ↓
5. Test query building
   ↓
6. Commit changes
   ↓
7. Cache auto-invalidates on next server start
```

### Microsoft Defender KQL

#### Manual Update Process

1. **Check Microsoft Learn for updates**:
   - Visit: https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-schema-tables
   - Compare with current schema

2. **Update schema files**:
   ```bash
   cd queryforge/kql/defender_xdr_kql_schema_fuller/
   # Edit relevant JSON files
   ```

3. **Schema file structure**:
   ```json
   {
     "DeviceProcessEvents": {
       "columns": [
         {
           "name": "Timestamp",
           "type": "datetime",
           "description": "Date and time when the event was recorded"
         },
         ...
       ],
       "url": "https://learn.microsoft.com/..."
     }
   }
   ```

4. **Test changes**:
   ```bash
   python -c "from queryforge.kql.schema_loader import SchemaCache; \
              cache = SchemaCache('path/to/cache.json'); \
              schema = cache.load_or_refresh(); \
              print(list(schema.keys()))"
   ```

#### Automated Update (Future)

The schema scraper can be enhanced:

```python
# kql/schema_scraper.py
def update_schema():
    """Fetch latest schema from Microsoft Learn."""
    tables = scrape_advanced_hunting_tables()

    for table_name, table_info in tables.items():
        # Update JSON file
        schema_file = SCHEMA_DIR / f"{table_name}.json"
        with open(schema_file, 'w') as f:
            json.dump(table_info, f, indent=2)

    # Update version
    version_file = SCHEMA_DIR / "VERSION"
    version_file.write_text(datetime.now().isoformat())
```

### Carbon Black Cloud

1. **Update `cbc_schema.json`**:
   ```json
   {
     "version": "1.2.0",
     "updated_at": "2024-01-15T10:30:00Z",
     "search_types": {
       "process_search": {
         "description": "Search for process executions",
         "fields": [
           {
             "name": "process_name",
             "type": "string",
             "description": "Name of the process",
             "examples": ["cmd.exe", "powershell.exe"]
           }
         ]
       }
     }
   }
   ```

2. **Increment version**:
   ```json
   {
     "version": "1.3.0"
   }
   ```

3. **Test**:
   ```python
   from queryforge.cbc.schema_loader import CBCSchemaCache

   cache = CBCSchemaCache("path/to/cbc_schema.json")
   schema = cache.load()
   print(f"Version: {schema['version']}")
   print(f"Search types: {list(schema['search_types'].keys())}")
   ```

### Cortex XDR

1. **Update `cortex_xdr_schema.json`**:
   ```json
   {
     "version": "2.1.0",
     "datasets": {
       "xdr_data": {
         "description": "Main endpoint telemetry",
         "fields": [...]
       }
     },
     "functions": [...],
     "operators": {...}
   }
   ```

2. **Add new dataset**:
   ```json
   {
     "datasets": {
       "new_dataset": {
         "name": "New Dataset Name",
         "description": "Dataset description",
         "fields": [...]
       }
     }
   }
   ```

3. **Test**:
   ```python
   from queryforge.cortex.schema_loader import CortexSchemaCache

   cache = CortexSchemaCache("path/to/cortex_xdr_schema.json")
   datasets = cache.datasets()
   print(f"Available datasets: {list(datasets.keys())}")
   ```

### SentinelOne

1. **Add new schema file** in `s1_builder/s1_schemas/`:
   ```bash
   cd s1_builder/s1_schemas/
   # Create new_dataset.json
   ```

2. **Schema structure**:
   ```json
   {
     "name": "New Events",
     "key": "new_events",
     "metadata": {
       "description": "Description of new events",
       "dataset_type": "events"
     },
     "fields": [
       {
         "name": "eventType",
         "type": "string",
         "description": "Type of event",
         "example": "FILE_CREATION"
       }
     ]
   }
   ```

3. **Test**:
   ```python
   from queryforge.s1.schema_loader import S1SchemaCache

   cache = S1SchemaCache("path/to/s1_schemas/")
   datasets = cache.datasets()
   print(f"Available datasets: {list(datasets.keys())}")
   ```

## Schema Validation

### Validation Script

Create `scripts/validate_schema.py`:

```python
#!/usr/bin/env python3
"""Validate schema structure and content."""

import json
from pathlib import Path
from typing import Dict, Any, List

def validate_schema(schema: Dict[str, Any], platform: str) -> List[str]:
    """Validate schema structure."""
    errors = []

    # Check required fields
    if "version" not in schema:
        errors.append("Missing 'version' field")

    if "datasets" not in schema and "tables" not in schema:
        errors.append("Missing 'datasets' or 'tables' field")

    # Validate datasets
    datasets = schema.get("datasets", schema.get("tables", {}))
    for name, info in datasets.items():
        # Check dataset structure
        if "fields" not in info:
            errors.append(f"{name}: Missing 'fields'")
            continue

        # Validate fields
        for field in info["fields"]:
            if "name" not in field:
                errors.append(f"{name}: Field missing 'name'")
            if "type" not in field:
                errors.append(f"{name}: Field '{field.get('name')}' missing 'type'")

            # Validate type
            valid_types = ["string", "integer", "datetime", "boolean", "float"]
            if field.get("type") not in valid_types:
                errors.append(
                    f"{name}: Field '{field['name']}' has invalid type '{field['type']}'"
                )

    return errors

def main():
    """Validate all schemas."""
    schemas = {
        "KQL": Path("queryforge/kql/defender_xdr_kql_schema_fuller"),
        "CBC": Path("queryforge/cbc/cbc_schema.json"),
        "Cortex": Path("queryforge/cortex/cortex_xdr_schema.json"),
        "S1": Path("s1_builder/s1_schemas"),
    }

    all_valid = True

    for platform, path in schemas.items():
        print(f"\nValidating {platform} schema...")

        if path.is_dir():
            # Validate all JSON files in directory
            for schema_file in path.glob("*.json"):
                with open(schema_file) as f:
                    schema = json.load(f)

                errors = validate_schema(schema, platform)
                if errors:
                    all_valid = False
                    print(f"  {schema_file.name}: FAILED")
                    for error in errors:
                        print(f"    - {error}")
                else:
                    print(f"  {schema_file.name}: OK")
        else:
            # Single schema file
            with open(path) as f:
                schema = json.load(f)

            errors = validate_schema(schema, platform)
            if errors:
                all_valid = False
                print(f"  FAILED")
                for error in errors:
                    print(f"    - {error}")
            else:
                print(f"  OK")

    if all_valid:
        print("\n✓ All schemas valid")
        return 0
    else:
        print("\n✗ Schema validation failed")
        return 1

if __name__ == "__main__":
    exit(main())
```

### Run Validation

```bash
python scripts/validate_schema.py
```

### Continuous Integration

Add to GitHub Actions:

```yaml
name: Validate Schemas

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      - name: Validate schemas
        run: python scripts/validate_schema.py
```

## Cache Management

### Cache Structure

```
.cache/
├── kql_schema_cache.json      # Aggregated KQL schema
├── unified_rag_documents.pkl  # RAG document cache
├── kql_version.txt            # KQL schema version
├── cbc_version.txt            # CBC schema version
├── cortex_version.txt         # Cortex schema version
└── s1_version.txt             # S1 schema version
```

### Cache Invalidation

Automatic invalidation on version change:

```python
def _is_cache_valid(self) -> bool:
    """Check if cache is still valid."""
    if not self.cache_file.exists():
        return False

    # Check version
    current_version = self._get_current_version()
    cached_version = self._get_cached_version()

    if current_version != cached_version:
        logger.info(f"Schema version changed: {cached_version} -> {current_version}")
        return False

    return True
```

### Manual Cache Refresh

**Via API**:
```python
# Force refresh for specific platform
result = client.call_tool("kql_refresh_schema")
```

**Via Command Line**:
```bash
# Delete cache
rm .cache/*.json .cache/*.pkl

# Restart server (rebuilds cache)
python server.py
```

**Programmatically**:
```python
from queryforge.kql.schema_loader import SchemaCache

cache = SchemaCache("path/to/cache.json")
cache.refresh(force=True)
```

### Cache Monitoring

Monitor cache freshness:

```python
def get_cache_info() -> Dict[str, Any]:
    """Get cache information."""
    cache_dir = Path(".cache")

    info = {}
    for cache_file in cache_dir.glob("*_schema_cache.json"):
        platform = cache_file.stem.replace("_schema_cache", "")
        stat = cache_file.stat()

        info[platform] = {
            "file": str(cache_file),
            "size_mb": stat.st_size / 1024 / 1024,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "age_hours": (time.time() - stat.st_mtime) / 3600,
        }

    return info
```

## Best Practices

### Schema Design

1. **Use clear, descriptive field names**:
   - Good: `process_command_line`
   - Bad: `pcl`, `cmd`

2. **Provide comprehensive descriptions**:
   ```json
   {
     "name": "ProcessCommandLine",
     "description": "Full command line used to launch the process, including all arguments and parameters",
     "example": "powershell.exe -encodedcommand VwByAGkAdABlAC..."
   }
   ```

3. **Include examples for complex fields**:
   ```json
   {
     "name": "FileHash",
     "type": "string",
     "description": "SHA256 hash of the file",
     "example": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
   }
   ```

4. **Document enums**:
   ```json
   {
     "name": "EventType",
     "type": "string",
     "description": "Type of event",
     "enum": ["PROCESS", "FILE", "NETWORK", "REGISTRY"],
     "example": "PROCESS"
   }
   ```

### Version Control

1. **Commit schema changes separately**:
   ```bash
   git add queryforge/kql/defender_xdr_kql_schema_fuller/
   git commit -m "Update KQL schema: Add new DeviceEvents table"
   ```

2. **Tag releases**:
   ```bash
   git tag -a schema-v1.2.0 -m "Schema version 1.2.0"
   git push origin schema-v1.2.0
   ```

3. **Document in pull requests**:
   ```markdown
   ## Schema Changes
   - Added 5 new fields to DeviceProcessEvents
   - Updated description for ProcessCommandLine
   - Added 10 new example queries
   ```

### Testing

1. **Test query building after updates**:
   ```python
   def test_new_field():
       """Test query building with new field."""
       result = client.call_tool("kql_build_query", {
           "table": "DeviceProcessEvents",
           "select": ["NewField"],
           "limit": 10
       })
       assert "error" not in result
       assert "NewField" in result["kql"]
   ```

2. **Validate backward compatibility**:
   ```python
   def test_backward_compatibility():
       """Ensure old queries still work."""
       old_query = {
           "table": "DeviceProcessEvents",
           "select": ["FileName", "ProcessCommandLine"]
       }
       result = client.call_tool("kql_build_query", old_query)
       assert "error" not in result
   ```

3. **Test example queries**:
   ```python
   def test_example_queries():
       """Ensure all example queries are valid."""
       result = client.call_tool("kql_get_examples", {
           "table": "DeviceProcessEvents"
       })
       examples = result["examples"]
       assert len(examples) > 0
       for example in examples:
           assert "query" in example
           assert "name" in example
   ```

### Documentation

1. **Keep schema docs in sync**:
   - Update API_REFERENCE.md when fields change
   - Update CHANGELOG.md for each schema version

2. **Document breaking changes**:
   ```markdown
   ### Breaking Changes in v2.0.0
   - `OldFieldName` has been removed, use `NewFieldName` instead
   - `EventType` values changed from integers to strings
   ```

3. **Provide migration guides**:
   ```markdown
   ## Migrating from v1.x to v2.0

   Replace:
   ```python
   select=["OldFieldName"]
   ```

   With:
   ```python
   select=["NewFieldName"]
   ```
   ```

## Platform-Specific Details

### Microsoft Defender KQL

**Schema Location**: `queryforge/kql/defender_xdr_kql_schema_fuller/`

**Update Frequency**: Monthly (as Microsoft updates tables)

**Sources**:
- https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-schema-tables
- Microsoft Defender portal (Schema reference)

**Special Considerations**:
- Table names are case-sensitive
- New tables may require permission updates
- Retention periods vary by table (7-30 days typically)

### Carbon Black Cloud

**Schema Location**: `queryforge/cbc/cbc_schema.json`

**Update Frequency**: Quarterly (as CBC releases new versions)

**Sources**:
- Carbon Black Developer Network
- CB Cloud API documentation
- Internal field testing

**Special Considerations**:
- Field availability varies by license level
- Some fields only available in specific search types

### Cortex XDR

**Schema Location**: `queryforge/cortex/cortex_xdr_schema.json`

**Update Frequency**: With each Cortex XDR release

**Sources**:
- Palo Alto Networks documentation
- XQL Reference Guide
- Cortex XDR admin console

**Special Considerations**:
- Dataset availability depends on data sources configured
- Custom fields require special handling

### SentinelOne

**Schema Location**: `s1_builder/s1_schemas/`

**Update Frequency**: With SentinelOne platform updates

**Sources**:
- SentinelOne documentation
- API explorer in management console
- Deep Visibility query builder

**Special Considerations**:
- Schema may vary between on-premise and cloud versions
- Some fields only available with specific modules enabled

## Troubleshooting

### Schema Not Loading

**Problem**: Server fails to load schema

**Solution**:
1. Check file permissions:
   ```bash
   ls -la queryforge/kql/defender_xdr_kql_schema_fuller/
   ```

2. Validate JSON syntax:
   ```bash
   python -m json.tool schema_file.json
   ```

3. Check logs for error details

### Cache Not Invalidating

**Problem**: Changes not reflected after schema update

**Solution**:
1. Force delete cache:
   ```bash
   rm .cache/*.json .cache/*.pkl
   ```

2. Restart server

3. Verify version changed:
   ```python
   print(cache.version)
   ```

### Version Mismatch

**Problem**: RAG cache version doesn't match schema

**Solution**:
1. Delete RAG cache:
   ```bash
   rm .cache/unified_rag_*.pkl
   ```

2. Rebuild:
   ```python
   rag_service.refresh(force=True)
   ```

---

For more information on schema usage, see [API Reference](../API_REFERENCE.md).
