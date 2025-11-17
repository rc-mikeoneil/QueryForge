# CQL Schema Structure Documentation

This document provides detailed documentation of the JSON schema formats used throughout the CQL Schema Repository.

## Table of Contents

1. [Event Type (Table) Schema](#event-type-table-schema)
2. [Function Schema](#function-schema)
3. [Operator Schema](#operator-schema)
4. [Example Query Schema](#example-query-schema)
5. [Metadata Schema](#metadata-schema)
6. [Builder Schemas](#builder-schemas)
7. [Cross-Reference Schema](#cross-reference-schema)

---

## Event Type (Table) Schema

Event type schemas define the structure of CQL event types (tables) including all available fields, their types, and metadata.

### Location
`cql_schemas/tables/*.json`

### Schema Format

```json
{
  "table": "ProcessRollup2",
  "category": "endpoint_process",
  "description": "Process execution events on Windows, macOS, and Linux endpoints",
  "source_url": "https://...",
  "columns": [
    {
      "name": "event_simpleName",
      "type": "string",
      "description": "Event type identifier",
      "required": true,
      "example_values": ["ProcessRollup2"]
    },
    {
      "name": "aid",
      "type": "string",
      "description": "Agent ID - unique identifier for the endpoint",
      "required": true,
      "searchable": true
    },
    {
      "name": "ImageFileName",
      "type": "string",
      "description": "Process executable file name (e.g., chrome.exe, bash)",
      "searchable": true,
      "supports_regex": true,
      "usage_pattern": "filtering, grouping, correlation"
    },
    {
      "name": "CommandLine",
      "type": "string",
      "description": "Full command line used to launch the process",
      "searchable": true,
      "supports_regex": true,
      "usage_pattern": "threat_hunting, filtering"
    },
    {
      "name": "TargetProcessId",
      "type": "long",
      "description": "Process ID of the target process",
      "alias": "falconPID",
      "usage_pattern": "correlation"
    }
  ],
  "col_count": 45,
  "common_filters": [
    "event_platform=Win",
    "event_platform=Mac",
    "event_platform=Lin"
  ],
  "common_correlations": [
    {
      "target_table": "NetworkConnectIP4",
      "join_field": "TargetProcessId",
      "description": "Correlate process execution with network connections"
    }
  ],
  "generated_at": "2025-11-15T00:00:00Z"
}
```

### Field Properties

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `name` | string | Yes | Field name as it appears in CQL queries |
| `type` | string | Yes | Data type (string, long, number, ip_address, timestamp, datetime, boolean) |
| `description` | string | Yes | Human-readable description of the field |
| `required` | boolean | No | Whether field is always present (default: false) |
| `searchable` | boolean | No | Whether field can be used in search filters (default: true) |
| `supports_regex` | boolean | No | Whether field supports regex matching (default: false for non-string) |
| `usage_pattern` | string | No | Common usage (filtering, grouping, correlation, threat_hunting, etc.) |
| `alias` | string | No | Alternative field name |
| `example_values` | array | No | Example values for the field |

### Supported Field Types

| Type | Description | Example Values | Compatible Operators |
|------|-------------|----------------|---------------------|
| `string` | Text data | "chrome.exe", "user@domain.com" | =, !=, =*, =/, in() |
| `long` | Large integers | 1234567890, 42 | =, !=, >, <, >=, <= |
| `number` | Numeric values | 3.14, 100 | =, !=, >, <, >=, <= |
| `ip_address` | IP addresses | "192.168.1.1", "10.0.0.1" | =, !=, cidr(), ipLocation() |
| `timestamp` | Unix timestamps | 1634567890 | >, <, >=, <=, bucket() |
| `datetime` | ISO timestamps | "2025-11-15T10:30:00Z" | >, <, formatTime() |
| `boolean` | True/False | true, false | =, != |

---

## Function Schema

Function schemas define CQL functions including parameters, return types, and usage examples.

### Location
`cql_schemas/functions/*.json`

### Schema Format

```json
{
  "name": "groupBy",
  "category": "aggregation",
  "description": "Groups events by specified fields and applies aggregate functions",
  "syntax": "groupBy([field1, field2, ...], function=[...])",
  "parameters": [
    {
      "name": "fields",
      "type": "array",
      "required": true,
      "description": "One or more fields to group by",
      "example": "[ImageFileName, UserName]"
    },
    {
      "name": "function",
      "type": "aggregation_function",
      "required": false,
      "description": "Aggregate functions to apply (count, sum, avg, etc.)",
      "example": "count(aid, distinct=true, as=UniqueEndpoints)"
    },
    {
      "name": "limit",
      "type": "number|'max'",
      "required": false,
      "description": "Maximum number of groups to return",
      "default": "max"
    }
  ],
  "return_type": "aggregated_events",
  "examples": [
    {
      "query": "groupBy([ImageFileName], function=count(aid, distinct=true))",
      "description": "Count unique endpoints per process"
    },
    {
      "query": "groupBy([aid, falconPID], function=collect([CommandLine]))",
      "description": "Collect all command lines per process instance"
    }
  ],
  "related_functions": ["count", "stats", "bucket", "top"],
  "usage_count": 156,
  "performance_notes": "Avoid grouping by high-cardinality fields like aid or TargetProcessId",
  "documentation_url": "https://..."
}
```

### Function Categories

| Category | Description | Example Functions |
|----------|-------------|-------------------|
| `aggregation` | Group and aggregate data | groupBy, count, bucket, top |
| `network` | Network operations | ipLocation, asn, cidr, rdns |
| `string` | String manipulation | format, regex, lower, concat |
| `transformation` | Data transformation | drop, rename, default, parseJson |
| `time` | Time operations | formatTime, formatDuration, timeChart |
| `advanced` | Complex operations | join, selfJoinFilter, correlate |
| `utility` | Utility functions | table, in, head, tail, sort |
| `control_flow` | Control flow | case, match |
| `array` | Array operations | concatArray |

---

## Operator Schema

Operator schemas define CQL operators including syntax, type compatibility, and usage examples.

### Location
`cql_schemas/operators/operators.json`

### Schema Format

```json
{
  "operators": [
    {
      "operator": "=",
      "name": "equals",
      "category": "comparison",
      "description": "Exact match comparison",
      "syntax": "field=value",
      "compatible_types": ["string", "number", "long", "boolean", "ip_address"],
      "examples": [
        {
          "query": "#event_simpleName=ProcessRollup2",
          "description": "Filter for ProcessRollup2 events"
        },
        {
          "query": "ImageFileName=chrome.exe",
          "description": "Filter for chrome.exe processes"
        }
      ],
      "case_sensitive": true,
      "performance_notes": "Most efficient operator for exact matches"
    },
    {
      "operator": "=*",
      "name": "wildcard",
      "category": "pattern",
      "description": "Wildcard pattern matching (* matches any characters)",
      "syntax": "field=*pattern*",
      "compatible_types": ["string"],
      "examples": [
        {
          "query": "ImageFileName=*chrome*",
          "description": "Match any filename containing 'chrome'"
        },
        {
          "query": "CommandLine=*/c *",
          "description": "Match command lines with /c parameter"
        }
      ],
      "case_sensitive": false,
      "performance_notes": "Leading wildcards (*pattern) prevent index usage"
    }
  ]
}
```

### Operator Categories

| Category | Description | Operators |
|----------|-------------|-----------|
| `comparison` | Exact comparisons | =, !=, >, <, >=, <= |
| `pattern` | Pattern matching | =*, =/, in() |
| `assignment` | Field assignment | := |
| `logical` | Logical operations | AND, OR, NOT |
| `flow` | Query flow | \| (pipe) |
| `special` | Special operators | # (event filter), * (wildcard) |

---

## Example Query Schema

Example query schemas document real-world CQL queries with metadata, categorization, and MITRE mappings.

### Location
`cql_schemas/examples/**/*.json`

### Schema Format

```json
{
  "id": "rdp-login-world-map",
  "title": "RDP Login World Map",
  "category": "network_analysis",
  "subcategory": "visualization",
  "description": "Maps RDP login attempts geographically using IP geolocation to identify unusual access patterns",
  "query": "#event_simpleName=UserLogon LogonType=10\n| ipLocation(RemoteAddressIP4)\n| stats(count(aid, as=LogonCount), by=[RemoteAddressIP4.lat, RemoteAddressIP4.lon])\n| worldMap(lat=RemoteAddressIP4.lat, lon=RemoteAddressIP4.lon, magnitude=LogonCount)",
  "event_types": ["UserLogon"],
  "functions_used": ["ipLocation", "stats", "worldMap"],
  "operators_used": ["=", "|"],
  "fields_referenced": [
    "event_simpleName",
    "LogonType",
    "RemoteAddressIP4",
    "aid"
  ],
  "difficulty": "intermediate",
  "use_case": "Monitor remote access patterns and identify logins from unexpected geographic locations",
  "mitre_tactics": [],
  "mitre_techniques": [],
  "tags": ["geolocation", "remote_access", "visualization"],
  "source_file": "Queries-Only/Helpful-CQL-Queries/RDP Login World Map.md",
  "source_repository": "logscale-community-content-main-2"
}
```

### Example Categories

| Category | Description | Example Count |
|----------|-------------|---------------|
| `threat_hunting` | Security threat detection | 35 |
| `network_analysis` | Network traffic analysis | 28 |
| `system_monitoring` | System health and inventory | 25 |
| `advanced_patterns` | Complex query patterns | 20 |
| `utilities` | Data manipulation utilities | 15 |

### Difficulty Levels

| Level | Description | Characteristics |
|-------|-------------|-----------------|
| `basic` | Simple queries | Single event type, 1-2 functions |
| `intermediate` | Moderate complexity | Multiple functions, joins |
| `advanced` | Complex queries | Multiple joins, advanced correlation |
| `expert` | Very complex | Self-joins, complex aggregations |

---

## Metadata Schema

Metadata schemas provide master indexes and catalogs for all schema elements.

### Master Schema Index

**Location:** `cql_schemas/metadata/master_schema_index.json`

```json
{
  "schema_version": "1.0.0",
  "generated_at": "2025-11-15T00:00:00Z",
  "source_repository": "logscale-community-content-main-2",
  "tables": [
    {
      "name": "ProcessRollup2",
      "file": "tables/ProcessRollup2.json",
      "category": "endpoint_process",
      "column_count": 45,
      "example_count": 23
    }
  ],
  "functions": [
    {
      "name": "groupBy",
      "file": "functions/groupBy.json",
      "category": "aggregation",
      "example_count": 156
    }
  ],
  "operators": {
    "file": "operators/operators.json",
    "count": 19
  },
  "examples": {
    "total_count": 123,
    "by_category": {
      "threat_hunting": 35,
      "network_analysis": 28,
      "system_monitoring": 25,
      "advanced_patterns": 20,
      "utilities": 15
    }
  },
  "statistics": {
    "total_event_types": 10,
    "total_fields": 150,
    "total_functions": 43,
    "total_operators": 19,
    "total_examples": 123
  }
}
```

### Event Types Catalog

**Location:** `cql_schemas/metadata/event_types_catalog.json`

```json
{
  "event_types": [
    {
      "name": "ProcessRollup2",
      "category": "endpoint_process",
      "description": "Process execution events",
      "field_count": 45,
      "usage_frequency": 156,
      "common_use_cases": ["threat_hunting", "inventory", "correlation"],
      "platforms": ["Win", "Mac", "Lin"]
    }
  ],
  "total_count": 10
}
```

### Functions Index

**Location:** `cql_schemas/metadata/functions_index.json`

```json
{
  "functions": [
    {
      "name": "groupBy",
      "category": "aggregation",
      "usage_count": 156,
      "file_path": "functions/groupBy.json"
    }
  ],
  "by_category": {
    "aggregation": 4,
    "network": 5,
    "string": 7,
    "transformation": 6,
    "time": 3,
    "advanced": 4,
    "utility": 6,
    "control_flow": 2,
    "array": 1
  },
  "total_count": 43
}
```

### Examples Index

**Location:** `cql_schemas/metadata/examples_index.json`

```json
{
  "examples": [
    {
      "id": "rdp-login-world-map",
      "title": "RDP Login World Map",
      "category": "network_analysis",
      "difficulty": "intermediate",
      "file_path": "examples/helpful_queries/rdp_login_world_map.json"
    }
  ],
  "by_category": {
    "threat_hunting": 35,
    "network_analysis": 28
  },
  "by_difficulty": {
    "basic": 45,
    "intermediate": 38,
    "advanced": 25,
    "expert": 15
  },
  "total_count": 123
}
```

---

## Builder Schemas

Builder schemas are optimized for query builder and IDE integration.

### Autocomplete Schema

**Location:** `cql_schemas/builder/autocomplete_schema.json`

```json
{
  "event_types": [
    {
      "name": "ProcessRollup2",
      "category": "endpoint_process",
      "description": "Process execution events",
      "priority": 1,
      "example_usage": "#event_simpleName=ProcessRollup2",
      "common_use_cases": ["threat_hunting", "inventory"]
    }
  ],
  "fields_by_event_type": {
    "ProcessRollup2": [
      {
        "name": "ImageFileName",
        "type": "string",
        "description": "Process executable file name",
        "usage_pattern": "filtering, grouping"
      }
    ]
  },
  "common_fields": [
    {
      "name": "aid",
      "type": "string",
      "description": "Agent ID",
      "appears_in": ["ProcessRollup2", "NetworkConnectIP4", "DnsRequest", "UserLogon"]
    }
  ],
  "functions": [
    {
      "name": "groupBy",
      "category": "aggregation",
      "signature": "groupBy([field1, field2], function=[...])",
      "description": "Group events by fields",
      "parameters": [...],
      "example": "groupBy([ImageFileName], function=count())"
    }
  ],
  "operators": [
    {
      "operator": "=",
      "name": "equals",
      "category": "comparison",
      "compatible_types": ["string", "number", "long"],
      "example": "ImageFileName=chrome.exe"
    }
  ]
}
```

### Validation Rules Schema

**Location:** `cql_schemas/builder/validation_rules.json`

```json
{
  "type_compatibility_matrix": {
    "operator_to_field_types": {
      ">": {
        "compatible_types": ["number", "long", "timestamp"],
        "incompatible_types": ["string", "boolean"],
        "error_message": "Operator '>' can only be used with numeric or timestamp fields"
      }
    },
    "function_to_field_types": {
      "ipLocation": {
        "required_field_type": "ip_address",
        "compatible_fields": ["RemoteAddressIP4", "LocalAddressIP4"],
        "error_message": "ipLocation requires an IP address field"
      }
    }
  },
  "required_fields": {
    "all_queries": ["event_simpleName"],
    "by_event_type": {
      "ProcessRollup2": {
        "always_available": ["aid", "event_simpleName"],
        "commonly_used": ["ImageFileName", "CommandLine"]
      }
    }
  },
  "function_parameter_validation": {
    "groupBy": {
      "required_parameters": ["fields"],
      "optional_parameters": ["function", "limit"],
      "parameter_rules": {
        "fields": {
          "type": "array",
          "min_length": 1,
          "error_message": "groupBy requires at least one field"
        }
      }
    }
  },
  "performance_warnings": [
    {
      "pattern": "groupBy.*aid",
      "warning": "Grouping by 'aid' creates high cardinality groups",
      "suggestion": "Consider grouping by ImageFileName instead"
    }
  ]
}
```

### Context Examples Schema

**Location:** `cql_schemas/builder/context_examples.json`

```json
{
  "examples_by_event_type": {
    "ProcessRollup2": {
      "starter_templates": [
        {
          "name": "Basic Process Filter",
          "difficulty": "basic",
          "query": "#event_simpleName=ProcessRollup2\n| table([aid, ImageFileName, CommandLine])",
          "description": "List recent processes",
          "when_to_use": "Starting point for process analysis"
        }
      ],
      "correlation_examples": [
        {
          "name": "Process-to-Network Correlation",
          "difficulty": "advanced",
          "query": "#event_simpleName=ProcessRollup2\n| join({#event_simpleName=NetworkConnectIP4}, field=[TargetProcessId=ContextProcessId, aid=aid])",
          "description": "Correlate processes with network connections"
        }
      ]
    }
  },
  "examples_by_function": {
    "groupBy": {
      "basic_examples": [...],
      "advanced_examples": [...]
    }
  },
  "examples_by_use_case": {
    "threat_hunting": [...],
    "lateral_movement": [...],
    "persistence": [...]
  },
  "examples_by_mitre_attack": {
    "TA0007": {
      "tactic_name": "Discovery",
      "techniques": [...]
    }
  }
}
```

---

## Cross-Reference Schema

Cross-reference schemas document relationships between schema elements.

**Location:** `cql_schemas/metadata/cross_references.json`

```json
{
  "field_to_event_types": {
    "aid": ["ProcessRollup2", "NetworkConnectIP4", "DnsRequest", "UserLogon"],
    "ImageFileName": ["ProcessRollup2"],
    "RemoteAddressIP4": ["NetworkConnectIP4", "UserLogon"]
  },
  "function_to_field_types": {
    "ipLocation": {
      "required_types": ["ip_address"],
      "compatible_fields": ["RemoteAddressIP4", "LocalAddressIP4"]
    },
    "groupBy": {
      "compatible_types": ["string", "number", "long", "ip_address"],
      "recommended_fields": ["ImageFileName", "UserName", "ComputerName"]
    }
  },
  "event_type_correlations": {
    "ProcessRollup2": {
      "commonly_joined_with": [
        {
          "event_type": "NetworkConnectIP4",
          "join_field": "TargetProcessId=ContextProcessId",
          "use_case": "Identify network activity from specific processes"
        }
      ]
    }
  },
  "mitre_to_examples": {
    "T1021.002": {
      "technique_name": "Remote Services: SMB/Windows Admin Shares",
      "example_queries": ["psexec_detection", "lateral_movement_smb"]
    }
  }
}
```

---

## Schema Versioning

All schemas include versioning information for tracking changes and compatibility.

### Version Format

Schemas use semantic versioning: `MAJOR.MINOR.PATCH`

- **MAJOR:** Breaking changes to schema structure
- **MINOR:** New fields or features added
- **PATCH:** Bug fixes and clarifications

### Version Tracking

Each schema file includes:
```json
{
  "schema_version": "1.0.0",
  "generated_at": "2025-11-15T00:00:00Z",
  "last_updated": "2025-11-15T00:00:00Z"
}
```

---

## Extending the Schemas

### Adding New Event Types

1. Create a new JSON file in `cql_schemas/tables/`
2. Follow the event type schema format
3. Update `cql_schemas/metadata/event_types_catalog.json`
4. Update `cql_schemas/metadata/master_schema_index.json`
5. Run validation: `python validate_schemas.py`

### Adding New Functions

1. Create a new JSON file in `cql_schemas/functions/`
2. Follow the function schema format
3. Update `cql_schemas/metadata/functions_index.json`
4. Update `cql_schemas/metadata/master_schema_index.json`
5. Add examples to `cql_schemas/examples/`
6. Run validation: `python validate_schemas.py`

### Adding New Examples

1. Create a new JSON file in appropriate `cql_schemas/examples/` subdirectory
2. Follow the example query schema format
3. Update `cql_schemas/metadata/examples_index.json`
4. Add MITRE mappings if applicable
5. Run validation: `python validate_schemas.py`

---

## Best Practices

### Schema Design

1. **Consistency:** Use consistent naming conventions across all schemas
2. **Completeness:** Include all required fields and metadata
3. **Documentation:** Provide clear descriptions for all fields
4. **Examples:** Include real-world examples for each schema element
5. **Validation:** Always validate schemas after changes

### Field Naming

1. Use CamelCase for field names (matching CQL convention)
2. Use descriptive names that indicate purpose
3. Include aliases for alternative field names
4. Document field relationships in descriptions

### Type Assignment

1. Use the most specific type available
2. Prefer `long` over `number` for large integers
3. Use `ip_address` for IP fields (enables network functions)
4. Use `timestamp` for Unix timestamps, `datetime` for ISO format

---

## Schema Validation

Run validation to ensure schema integrity:

```bash
python validate_schemas.py
```

Validation checks:
- JSON syntax correctness
- Required field presence
- Type compatibility
- Cross-reference integrity
- Example query validity

See [VALIDATION_REPORT.md](VALIDATION_REPORT.md) for results.

---

**Last Updated:** 2025-11-15
**Schema Version:** 1.0.0
