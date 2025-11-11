# API Reference

Complete reference for all MCP tools exposed by the QueryForge server.

## Table of Contents

- [Overview](#overview)
- [Carbon Black Cloud (CBC) Tools](#carbon-black-cloud-cbc-tools)
- [Cortex XDR Tools](#cortex-xdr-tools)
- [Microsoft Defender KQL Tools](#microsoft-defender-kql-tools)
- [SentinelOne Tools](#sentinelone-tools)
- [Shared Tools](#shared-tools)
- [Response Formats](#response-formats)
- [Error Handling](#error-handling)

## Overview

QueryForge exposes 30+ MCP tools organized into platform-specific namespaces:

| Namespace | Tools | Purpose |
|-----------|-------|---------|
| `cbc_*` | 6 tools | Carbon Black Cloud query building |
| `cortex_*` | 7 tools | Cortex XDR XQL query building |
| `kql_*` | 8 tools | Microsoft Defender KQL query building |
| `s1_*` | 3 tools | SentinelOne S1QL query building |
| `retrieve_context` | 1 tool | Cross-platform RAG retrieval |

All tools return JSON responses with consistent structure and error handling.

## Carbon Black Cloud (CBC) Tools

### `cbc_list_datasets`

List available Carbon Black Cloud search types with descriptions.

**Parameters**: None

**Returns**:
```json
{
  "datasets": {
    "process_search": {
      "description": "Search for process executions",
      "fields": ["process_name", "process_pid", ...]
    },
    "binary_search": {
      "description": "Search for binary files",
      "fields": ["md5", "sha256", ...]
    },
    "alert_search": {...},
    "threat_search": {...}
  }
}
```

**Example**:
```python
result = client.call_tool("cbc_list_datasets")
print(result["search_types"]["process_search"]["description"])
```

---

### `cbc_get_fields`

Return available fields for a given Carbon Black search type.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `search_type` | string | Yes | Search type (process, binary, alert, threat) |

**Returns**:
```json
{
  "search_type": "process_search",
  "fields": [
    {
      "name": "process_name",
      "type": "string",
      "description": "Name of the process",
      "examples": ["cmd.exe", "powershell.exe"]
    },
    ...
  ],
  "normalisation": [
    "Normalized 'process' to 'process_search'"
  ]
}
```

**Example**:
```python
result = client.call_tool("cbc_get_fields", {"search_type": "process"})
fields = result["fields"]
```

---

### `cbc_get_operator_reference`

Return logical, wildcard, and field operator reference for CBC queries.

**Parameters**: None

**Returns**:
```json
{
  "operators": {
    "logical": {
      "AND": "All conditions must match",
      "OR": "Any condition can match"
    },
    "wildcards": {
      "*": "Match zero or more characters",
      "?": "Match exactly one character"
    },
    "field_operators": {
      ":": "Equals or contains",
      ">": "Greater than",
      "<": "Less than"
    }
  }
}
```

---

### `cbc_get_best_practices`

Return documented query-building best practices for Carbon Black Cloud.

**Parameters**: None

**Returns**:
```json
{
  "best_practices": [
    {
      "category": "performance",
      "practice": "Use specific process names instead of wildcards",
      "example": "process_name:cmd.exe (good) vs process_name:*.exe (slow)"
    },
    ...
  ]
}
```

---

### `cbc_get_examples`

Return example queries, optionally filtered by category.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `category` | string | No | Category filter (process_search, binary_search, etc.) |

**Returns**:
```json
{
  "category": "process_search",
  "examples": [
    {
      "name": "PowerShell with encoded command",
      "query": "process_name:powershell.exe AND cmdline:-encodedcommand",
      "description": "Finds PowerShell executions with base64 encoded commands"
    },
    ...
  ]
}
```

**Example**:
```python
# Get all examples
result = client.call_tool("cbc_get_examples")

# Get process_search examples only
result = client.call_tool("cbc_get_examples", {
    "category": "process_search"
})
```

---

### `cbc_build_query`

Build a Carbon Black Cloud query from structured parameters or natural language.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `search_type` | string | No | process_search | Target search type |
| `terms` | array[string] | No | null | Pre-built expressions (field:value) |
| `natural_language_intent` | string | No | null | High-level description of search goal |
| `boolean_operator` | string | No | AND | Boolean operator (AND/OR) |
| `limit` | integer | No | null | Optional record limit (1-10000) |

**Returns**:
```json
{
  "query": "process_name:cmd.exe AND parent_name:explorer.exe",
  "metadata": {
    "search_type": "process_search",
    "boolean_operator": "AND",
    "terms_count": 2,
    "rag_context": [
      {
        "text": "process_name field matches against the executable name...",
        "source": "cbc",
        "score": 0.89
      }
    ]
  }
}
```

**Example**:
```python
# Structured query
result = client.call_tool("cbc_build_query", {
    "search_type": "process",
    "terms": [
        "process_name:powershell.exe",
        "cmdline:-encodedcommand"
    ],
    "boolean_operator": "AND"
})

# Natural language query
result = client.call_tool("cbc_build_query", {
    "natural_language_intent": "Find suspicious PowerShell executions with encoded commands",
    "search_type": "process"
})
```

---

## Cortex XDR Tools

### `cortex_list_datasets`

List available Cortex XDR datasets with descriptions.

**Parameters**: None

**Returns**:
```json
{
  "datasets": {
    "xdr_data": {
      "description": "Main endpoint telemetry dataset",
      "fields_count": 150
    },
    "panw_ngfw_traffic": {
      "description": "Firewall traffic logs",
      "fields_count": 85
    },
    ...
  }
}
```

---

### `cortex_get_fields`

Return available fields for a Cortex XDR dataset.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `dataset` | string | Yes | Dataset name (e.g., xdr_data) |

**Returns**:
```json
{
  "dataset": "xdr_data",
  "fields": [
    {
      "name": "actor_process_image_name",
      "type": "string",
      "description": "Name of the process executable",
      "example": "cmd.exe"
    },
    ...
  ],
  "normalisation": []
}
```

---

### `cortex_get_xql_functions`

Return documented XQL functions with usage examples.

**Parameters**: None

**Returns**:
```json
{
  "functions": [
    {
      "name": "contains",
      "category": "string",
      "description": "Check if string contains substring",
      "syntax": "contains(field, \"substring\")",
      "example": "contains(actor_process_image_name, \"powershell\")"
    },
    ...
  ]
}
```

---

### `cortex_get_operator_reference`

Return XQL operator reference grouped by category.

**Parameters**: None

**Returns**:
```json
{
  "operators": {
    "comparison": {
      "=": "Equals",
      "!=": "Not equals",
      ">": "Greater than",
      ">=": "Greater than or equal"
    },
    "logical": {
      "and": "Logical AND",
      "or": "Logical OR",
      "not": "Logical NOT"
    },
    "pattern": {
      "~=": "Regular expression match",
      "contains": "String contains"
    }
  }
}
```

---

### `cortex_get_enum_reference`

Return enumerated value mappings from the Cortex schema.

**Parameters**: None

**Returns**:
```json
{
  "enum_values": {
    "action_process_os_type": {
      "values": ["WINDOWS", "LINUX", "MACOS"],
      "description": "Operating system type"
    },
    "event_type": {
      "values": ["PROCESS", "FILE", "NETWORK", "REGISTRY"],
      "description": "Event type classification"
    }
  }
}
```

---

### `cortex_get_field_groups`

Return logical field groupings to assist with projection selection.

**Parameters**: None

**Returns**:
```json
{
  "field_groups": {
    "process_identity": [
      "actor_process_image_name",
      "actor_process_command_line",
      "actor_process_image_path"
    ],
    "network_activity": [
      "dst_ip",
      "dst_port",
      "action_remote_ip",
      "action_remote_port"
    ],
    ...
  }
}
```

---

### `cortex_build_query`

Build a Cortex XDR XQL query from structured parameters or natural language.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `dataset` | string | No | xdr_data | Target dataset |
| `filters` | array[object] or object | No | null | Filter definitions |
| `fields` | array[string] | No | null | Fields for projection |
| `natural_language_intent` | string | No | null | Investigation goal description |
| `time_range` | string or object | No | null | Time range expression |
| `limit` | integer | No | null | Result limit (1-10000) |

**Filter Object Structure**:
```json
{
  "field": "actor_process_image_name",
  "operator": "=",
  "value": "cmd.exe"
}
```

**Returns**:
```json
{
  "query": "dataset = xdr_data | filter actor_process_image_name = \"cmd.exe\" | fields actor_process_image_name, actor_process_command_line | limit 100",
  "metadata": {
    "dataset": "xdr_data",
    "filters_applied": 1,
    "fields_projected": 2,
    "limit": 100,
    "rag_context": [...]
  }
}
```

**Example**:
```python
# Structured query
result = client.call_tool("cortex_build_query", {
    "dataset": "xdr_data",
    "filters": [
        {"field": "actor_process_image_name", "operator": "=", "value": "cmd.exe"}
    ],
    "fields": ["actor_process_image_name", "actor_process_command_line"],
    "limit": 100
})

# Natural language query
result = client.call_tool("cortex_build_query", {
    "natural_language_intent": "Find command prompt executions in the last 24 hours",
    "dataset": "xdr_data"
})
```

---

## Microsoft Defender KQL Tools

### `kql_list_datasets`

List available Advanced Hunting tables with optional keyword filtering.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `keyword` | string | No | Substring filter for table names |

**Returns**:
```json
{
  "datasets": [
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "DeviceFileEvents",
    ...
  ]
}
```

**Example**:
```python
# All tables
result = client.call_tool("kql_list_datasets")

# Filter by keyword
result = client.call_tool("kql_list_datasets", {"keyword": "Device"})
# Returns: DeviceProcessEvents, DeviceNetworkEvents, etc.
```

---

### `kql_get_fields`

Return columns and documentation URL for a given table.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `table` | string | Yes | Table name |

**Returns**:
```json
{
  "table": "DeviceProcessEvents",
  "columns": [
    {
      "name": "Timestamp",
      "type": "datetime",
      "description": "Date and time when the event was recorded"
    },
    {
      "name": "FileName",
      "type": "string",
      "description": "Name of the file the recorded action was applied to"
    },
    ...
  ],
  "url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table"
}
```

**Error Response** (unknown table):
```json
{
  "error": "Unknown table 'DeviceProcess'. Did you mean 'DeviceProcessEvents' (score 95)?"
}
```

---

### `kql_suggest_fields`

Suggest columns for a table with optional keyword filtering.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `table` | string | Yes | Table name |
| `keyword` | string | No | Column name filter |

**Returns**:
```json
{
  "suggestions": [
    {
      "column": "ProcessCommandLine",
      "type": "string",
      "description": "Command line used to run the process",
      "relevance_score": 0.95
    },
    ...
  ]
}
```

**Example**:
```python
# All columns
result = client.call_tool("kql_suggest_fields", {
    "table": "DeviceProcessEvents"
})

# Filter by keyword
result = client.call_tool("kql_suggest_fields", {
    "table": "DeviceProcessEvents",
    "keyword": "command"
})
# Returns columns like: ProcessCommandLine, InitiatingProcessCommandLine
```

---

### `kql_get_examples`

Return example KQL queries for a given table.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `table` | string | Yes | Table name |

**Returns**:
```json
{
  "examples": [
    {
      "name": "PowerShell executions",
      "query": "DeviceProcessEvents\n| where FileName =~ \"powershell.exe\"\n| project Timestamp, DeviceName, FileName, ProcessCommandLine",
      "description": "Find all PowerShell executions"
    },
    ...
  ]
}
```

---

### `kql_build_query`

Build a KQL query from structured parameters or natural language intent.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `table` | string | No | null | Source table name |
| `select` | array[string] | No | null | Columns to project |
| `where` | array[string] | No | null | Filter conditions |
| `time_window` | string | No | null | Time range (e.g., "24h", "7d") |
| `summarize` | string | No | null | Aggregation expression |
| `order_by` | string | No | null | Sort expression |
| `limit` | integer | No | null | Result limit |
| `natural_language_intent` | string | No | null | Natural language description |

**Returns**:
```json
{
  "kql": "DeviceProcessEvents\n| where Timestamp > ago(24h)\n| where FileName =~ \"cmd.exe\"\n| project Timestamp, DeviceName, FileName, ProcessCommandLine\n| limit 100",
  "meta": {
    "table": "DeviceProcessEvents",
    "time_window": "24h",
    "filters_count": 1,
    "selected_columns": 4,
    "rag_context": [...]
  }
}
```

**Example**:
```python
# Structured query
result = client.call_tool("kql_build_query", {
    "table": "DeviceProcessEvents",
    "where": ["FileName =~ \"powershell.exe\""],
    "select": ["Timestamp", "DeviceName", "ProcessCommandLine"],
    "time_window": "7d",
    "limit": 100
})

# Natural language query
result = client.call_tool("kql_build_query", {
    "natural_language_intent": "Show me all PowerShell executions from the last week with encoded commands"
})
```

---

### Additional KQL Tools

The following tools are also available:

- `kql_refresh_schema`: Force refresh the schema cache from source
- `kql_get_schema_version`: Return current schema cache version
- `kql_validate_query`: Validate a KQL query for syntax errors

---

## SentinelOne Tools

### `s1_list_datasets`

List SentinelOne datasets with display names and descriptions.

**Parameters**: None

**Returns**:
```json
{
  "datasets": [
    {
      "key": "processes",
      "name": "Process Events",
      "description": "Process execution and termination events"
    },
    {
      "key": "files",
      "name": "File Events",
      "description": "File creation, modification, and deletion events"
    },
    ...
  ]
}
```

Available datasets:
- `processes` - Process events
- `files` - File events
- `network` - Network connections
- `dns` - DNS queries
- `registry` - Registry modifications (Windows)
- `cross_process` - Inter-process operations
- `modules` - Module/DLL loads
- `indicators` - Threat indicators
- `url` - URL access events
- `scheduled_tasks` - Scheduled task events
- `logins` - Authentication events

---

### `s1_get_fields`

Return available fields for a SentinelOne dataset.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `dataset` | string | Yes | Dataset key (e.g., processes, files) |

**Returns**:
```json
{
  "dataset": "processes",
  "name": "Process Events",
  "fields": [
    {
      "name": "srcProcName",
      "type": "string",
      "description": "Source process name",
      "example": "cmd.exe"
    },
    {
      "name": "srcProcCmdLine",
      "type": "string",
      "description": "Source process command line"
    },
    ...
  ]
}
```

---

### `s1_build_query`

Build a SentinelOne S1QL query from structured inputs or natural language intent.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `dataset` | string | No | processes | Target dataset |
| `filters` | array[string or object] | No | null | Filter expressions |
| `natural_language_intent` | string | No | null | Natural language description |
| `boolean_operator` | string | No | AND | Boolean operator (AND/OR) |

**Filter Object Structure**:
```json
{
  "field": "srcProcName",
  "operator": "=",
  "value": "cmd.exe"
}
```

**Returns**:
```json
{
  "query": "srcProcName = \"cmd.exe\" AND srcProcCmdLine ContainsCIS \"encoded\"",
  "metadata": {
    "dataset": "processes",
    "boolean_operator": "AND",
    "filters_count": 2,
    "inferred_dataset": true,
    "rag_context": [...]
  }
}
```

**Example**:
```python
# Structured query
result = client.call_tool("s1_build_query", {
    "dataset": "processes",
    "filters": [
        {"field": "srcProcName", "operator": "=", "value": "powershell.exe"},
        "srcProcCmdLine ContainsCIS \"encoded\""
    ],
    "boolean_operator": "AND"
})

# Natural language query
result = client.call_tool("s1_build_query", {
    "natural_language_intent": "Find PowerShell with encoded commands",
    "dataset": "processes"
})
```

---

## Shared Tools

### `retrieve_context`

Return relevant schema passages for a natural language query using RAG.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `query` | string | Yes | - | Natural language query |
| `k` | integer | No | 5 | Number of results to return (1-20) |
| `query_type` | string | No | null | Filter by platform (cbc, kql, cortex, s1) |

**Returns**:
```json
{
  "matches": [
    {
      "text": "DeviceProcessEvents table contains process execution events including FileName, ProcessCommandLine, and InitiatingProcess details...",
      "source": "kql",
      "score": 0.92,
      "metadata": {
        "table": "DeviceProcessEvents",
        "doc_type": "table_description"
      }
    },
    ...
  ]
}
```

**Example**:
```python
# Search all platforms
result = client.call_tool("retrieve_context", {
    "query": "How do I search for PowerShell executions?",
    "k": 5
})

# Search specific platform
result = client.call_tool("retrieve_context", {
    "query": "process name field",
    "query_type": "kql",
    "k": 3
})
```

---

## Response Formats

### Success Response

All successful tool calls return a JSON object with relevant data:

```json
{
  "query": "...",           // Generated query string
  "metadata": {             // Query metadata
    "platform": "...",
    "timestamp": "...",
    ...
  }
}
```

### Error Response

Failed tool calls return an error object:

```json
{
  "error": "Error description here",
  "details": {              // Optional additional context
    "invalid_field": "FieldName",
    "suggestions": ["Field1", "Field2"]
  }
}
```

### Common Error Types

| Error Type | Description | Example |
|------------|-------------|---------|
| ValidationError | Invalid parameters | "Limit exceeds maximum of 10000" |
| SchemaError | Unknown table/field | "Unknown table 'DeviceProcess'" |
| BuildError | Query construction failed | "Cannot combine filters from different datasets" |
| RAGError | Context retrieval failed | "RAG index not initialized" |

---

## Error Handling

### Best Practices

1. **Always check for error field**:
   ```python
   result = client.call_tool("kql_build_query", params)
   if "error" in result:
       print(f"Error: {result['error']}")
       return
   query = result["kql"]
   ```

2. **Use suggestions from errors**:
   ```python
   result = client.call_tool("kql_get_fields", {"table": "DeviceProcess"})
   if "error" in result and "Did you mean" in result["error"]:
       # Extract suggested table name and retry
       suggested = extract_suggestion(result["error"])
       result = client.call_tool("kql_get_fields", {"table": suggested})
   ```

3. **Validate parameters before calling**:
   ```python
   if limit > 10000:
       print("Limit too high, using 10000")
       limit = 10000
   ```

4. **Handle RAG failures gracefully**:
   ```python
   # RAG context is optional - queries still work without it
   result = client.call_tool("kql_build_query", params)
   if "rag_context" in result.get("meta", {}):
       print("Enhanced with RAG context")
   ```

---

## Parameter Validation

All parameters are validated using Pydantic schemas. Common validation rules:

| Parameter | Validation |
|-----------|------------|
| `limit` | Integer, 1-10000 |
| `k` (RAG) | Integer, 1-20 |
| `search_type` | Enum of valid search types |
| `dataset` | Must exist in schema |
| `table` | Must exist in schema (fuzzy match available) |
| `boolean_operator` | "AND" or "OR" |

---

## Rate Limiting

Currently, there are no built-in rate limits. For production deployments, consider:

1. Implementing client-side rate limiting
2. Using a proxy with rate limiting (e.g., nginx)
3. Monitoring tool call frequency
4. Caching frequently used queries

---

## Versioning

API version information:

- **Current Version**: 1.0.0
- **Protocol**: MCP (Model Context Protocol)
- **Schema Versions**: Platform-specific (tracked per schema)

Check schema versions:
```python
# KQL schema version
result = client.call_tool("kql_get_schema_version")

# CBC schema version
result = client.call_tool("cbc_list_datasets")
version = result.get("version")
```

---

## Examples

### Complete Workflow Example

```python
# 1. Discover available tables
tables = client.call_tool("kql_list_datasets", {"keyword": "Device"})

# 2. Get schema for specific table
schema = client.call_tool("kql_get_fields", {
    "table": "DeviceProcessEvents"
})

# 3. Get column suggestions
columns = client.call_tool("kql_suggest_fields", {
    "table": "DeviceProcessEvents",
    "keyword": "command"
})

# 4. Build query
query_result = client.call_tool("kql_build_query", {
    "table": "DeviceProcessEvents",
    "where": ["FileName =~ \"powershell.exe\""],
    "select": ["Timestamp", "DeviceName", "ProcessCommandLine"],
    "time_window": "24h",
    "limit": 100
})

# 5. Execute query on target platform
if "error" not in query_result:
    kql_query = query_result["kql"]
    # Execute on Microsoft Defender...
```

### Multi-Platform Search Example

```python
# Search for the same threat across all platforms

# Defender KQL
kql_result = client.call_tool("kql_build_query", {
    "natural_language_intent": "Find suspicious PowerShell with encoded commands"
})

# Carbon Black
cbc_result = client.call_tool("cbc_build_query", {
    "natural_language_intent": "Find suspicious PowerShell with encoded commands"
})

# Cortex XDR
cortex_result = client.call_tool("cortex_build_query", {
    "natural_language_intent": "Find suspicious PowerShell with encoded commands"
})

# SentinelOne
s1_result = client.call_tool("s1_build_query", {
    "natural_language_intent": "Find suspicious PowerShell with encoded commands"
})

# Execute all queries in parallel on respective platforms
```
