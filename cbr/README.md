# Carbon Black Response (CBR) Query Builder

This directory contains the complete implementation of the Carbon Black Response (CBR) query builder, validator, schema loader, and MCP server tools for QueryForge.

## Overview

Carbon Black Response (CBR) is an endpoint detection and response (EDR) platform that uses the Event Forwarder to export security events. This implementation provides natural language and structured query building capabilities for CBR's field:value query syntax.

## Components

### 1. Schema Management (`schema_loader.py`)

The `CBResponseSchemaCache` class manages CBR schema files with secure caching:

```python
from cbr.schema_loader import CBResponseSchemaCache

# Initialize with schema directory
cache = CBResponseSchemaCache(schema_path="cbr/")
schema = cache.load()

# Get available datasets
search_types = cache.search_types()
# Returns: {"server_event": {...}, "endpoint_event": {...}}

# Get fields for a dataset
fields = cache.list_fields("endpoint_event")
# Returns list of field dictionaries with name, type, description
```

**Features:**
- **Split Schema Support**: Loads from 6 separate JSON files (`cbr_*.json`)
- **Secure Caching**: HMAC-SHA256 integrity verification, 100MB size limits
- **Dataset Merging**: Combines 11 server event + 11 endpoint event field sets
- **Field Normalization**: Maps friendly names to canonical field sets

### 2. Query Building (`query_builder.py`)

The `build_cbr_query()` function creates CBR queries from natural language or structured terms:

```python
from cbr.query_builder import build_cbr_query

# Natural language query
query, metadata = build_cbr_query(
    schema=schema,
    search_type="endpoint_event",
    natural_language_intent="chrome.exe connecting to 192.168.1.100 on port 443"
)
# Result: "process_name:chrome.exe AND remote_ip:192.168.1.100 AND remote_port:443"

# Structured terms
query, metadata = build_cbr_query(
    schema=schema,
    search_type="server_event",
    terms=["watchlist_name:Threat Intel", "process_name:malware.exe"],
    boolean_operator="OR"
)
# Result: "watchlist_name:Threat Intel OR process_name:malware.exe"
```

**Features:**
- **IOC Extraction**: Automatically detects MD5 hashes, IP addresses, ports, domains
- **Field Mapping**: Maps patterns to appropriate CBR fields (process_name, remote_ip, etc.)
- **Security Concept Expansion**: Integrates with `shared.security_concepts`
- **RAG Enhancement**: Uses context from `shared.rag_context_parser` 
- **Input Sanitization**: Prevents injection attacks, escapes Windows paths
- **Limit Clamping**: Enforces MAX_LIMIT of 5000 results

### 3. Query Validation (`validator.py`)

The `CBRValidator` class performs comprehensive query validation:

```python
from cbr.validator import CBRValidator

validator = CBRValidator(schema)
result = validator.validate(query, metadata)

if result["valid"]:
    print("Query is valid!")
else:
    # Check specific validation categories
    syntax_errors = result["validation_results"]["syntax"]["errors"]
    schema_errors = result["validation_results"]["schema"]["errors"] 
    # Each error includes suggestion for fixes
```

**Validation Categories:**
- **Syntax**: Query length, dangerous characters, field:value format
- **Schema**: Field existence, dataset validation, typo suggestions
- **Operators**: Only AND/OR supported, warns on inequality operators
- **Performance**: Wildcard usage, overly broad queries, large limits
- **Best Practices**: Prefer field-specific over keyword searches

### 4. MCP Tools (`server_tools_cbr.py`)

Eight MCP tools expose CBR functionality:

#### Read-Only Tools
- `cbr_list_datasets()` - Available datasets (server_event, endpoint_event)
- `cbr_get_fields(search_type)` - Field list with normalization log
- `cbr_get_operator_reference()` - Supported operators (AND, OR, field:value)
- `cbr_get_best_practices()` - Query optimization guidelines
- `cbr_get_examples(category)` - Example queries by category

#### Query Building Tools
- `cbr_build_query()` - Build query from natural language or structured terms
- `cbr_validate_query()` - Validate query and provide suggestions
- `cbr_build_query_validated()` - Combined build + validate with auto-retry

## Schema Structure

### Datasets

CBR supports two main dataset types:

1. **Server Events** (`server_event`): 78 fields from 11 server-generated event types
   - Watchlist hits, feed hits, binary observations
   - Alert metadata, threat intelligence matches
   - Example fields: `watchlist_name`, `feed_name`, `alert_severity`

2. **Endpoint Events** (`endpoint_event`): 63 fields from 11 raw endpoint event types  
   - Process starts, network connections, file modifications
   - Registry changes, module loads, child processes
   - Example fields: `process_name`, `remote_ip`, `netconn_count`

### Field Types

CBR fields use these normalized types:
- `string` - Text values (process names, paths, domains)
- `integer` - Numeric values (PIDs, ports, counts)
- `float` - Decimal values (scores, timestamps)
- `boolean` - True/false values (rare in CBR)

## Query Syntax

CBR uses a simple field:value syntax:

### Basic Queries
```
# Field-specific searches
process_name:chrome.exe
md5:5d41402abc4b2a76b9719d911017c592
remote_ip:192.168.1.100

# Quoted values (spaces)
process_name:"google chrome"
watchlist_name:"Threat Intel Feed"

# Wildcards  
domain:*.malicious.com
process_name:*malware*
```

### Boolean Logic
```
# AND (default)
process_name:cmd.exe AND remote_port:443

# OR
process_name:cmd.exe OR process_name:powershell.exe
```

### Keyword Searches
```
# Unqualified terms search across multiple fields
malware.exe
192.168.1.100
```

## Example Queries

### Process Monitoring
```python
# Find suspicious processes
build_cbr_query(
    schema=schema,
    search_type="endpoint_event", 
    natural_language_intent="powershell.exe with suspicious command line"
)

# Monitor parent-child relationships
build_cbr_query(
    schema=schema,
    search_type="endpoint_event",
    terms=["parent_name:explorer.exe", "process_name:cmd.exe"]
)
```

### Network Analysis
```python
# Detect C2 communications
build_cbr_query(
    schema=schema,
    search_type="endpoint_event",
    natural_language_intent="outbound connections to 192.168.1.100 on port 443"
)

# Domain-based threat hunting
build_cbr_query(
    schema=schema,
    search_type="endpoint_event", 
    terms=["domain:*.malicious.com"]
)
```

### Threat Intelligence
```python
# Watchlist hits
build_cbr_query(
    schema=schema,
    search_type="server_event",
    terms=["watchlist_name:APT Campaign"]
)

# Hash-based detection
build_cbr_query(
    schema=schema,
    search_type="endpoint_event",
    natural_language_intent="process with MD5 hash 5d41402abc4b2a76b9719d911017c592"
)
```

## Best Practices

### Field-Specific Searches
```python
# ✅ GOOD: Use specific fields
"process_name:chrome.exe"
"md5:abc123..."
"remote_ip:192.168.1.100"

# ❌ AVOID: Generic keywords  
"chrome.exe"  # Searches many fields, slower
```

### Dataset Selection
```python
# Use endpoint_event for endpoint telemetry
search_type="endpoint_event"  # Process, network, file events

# Use server_event for alerts and threat intel
search_type="server_event"    # Watchlist hits, feed matches
```

### Performance Optimization
```python
# ✅ GOOD: Specific wildcards
"domain:*.evil.com"

# ❌ AVOID: Leading wildcards (slow)
"domain:*malware*"

# ✅ GOOD: Reasonable limits
limit=1000

# ❌ AVOID: Excessive limits  
limit=50000  # Will be clamped to 5000
```

## Integration with QueryForge

### MCP Server Usage
```python
# Use MCP tools instead of direct imports
result = use_mcp_tool("cbr_build_query", {
    "dataset": "endpoint_event",
    "natural_language_intent": "find chrome processes"
})

query = result["query"]
metadata = result["metadata"]
```

### RAG Enhancement
CBR integrates with QueryForge's RAG system using `source_filter="cbr"`:
- Automatically expands security concepts
- Adds contextual field:value pairs
- Improves query coverage and accuracy

### Validation Workflow
```python
# Always validate queries before use
build_result = cbr_build_query(...)
validation_result = cbr_validate_query(build_result["query"], build_result["metadata"])

if not validation_result["valid"]:
    # Apply corrections and retry
    corrections = extract_corrections(validation_result)
    # ... retry logic
```

## Security Features

- **Input Sanitization**: Rejects dangerous characters (`;`, `|`, `()`, `{}`)
- **Length Limits**: Max 10KB natural language, 2KB field values
- **Path Validation**: Secure schema file loading with path traversal protection
- **Cache Integrity**: HMAC-SHA256 verification prevents tampering
- **Injection Prevention**: Proper escaping and quoting of values

## Testing

The CBR implementation includes comprehensive test coverage:

- **Unit Tests**: 53 query builder + 36 validator + 15 MCP + 2 schema loader = 106 tests
- **Integration Tests**: 15 end-to-end workflow scenarios
- **Error Handling**: Validation failures, retry workflows, edge cases
- **Performance**: Wildcard warnings, limit clamping, broad query detection

Run tests with:
```bash
pytest tests/test_cbr_* -v
```

## Files

| File | Purpose |
|------|---------|
| `cbr_core.json` | Platform metadata, search types |
| `cbr_server_generated_events.json` | 11 server event field sets |  
| `cbr_raw_endpoint_events.json` | 11 endpoint event field sets |
| `cbr_operators.json` | Query operators and syntax |
| `cbr_best_practices.json` | Performance and usage guidelines |
| `cbr_examples.json` | 20 categories of example queries |
| `schema_loader.py` | Schema caching and loading |
| `query_builder.py` | Natural language and structured query building |
| `validator.py` | Comprehensive query validation |
| `__init__.py` | Module exports |

The implementation follows QueryForge patterns established by CBC, Cortex XDR, KQL, and SentinelOne builders for consistency and maintainability.
