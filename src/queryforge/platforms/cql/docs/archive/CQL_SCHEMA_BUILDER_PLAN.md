# CrowdStrike Query Language (CQL) Schema Builder - Implementation Plan

## Implementation Status

| Phase | Status | Completion |
|-------|--------|------------|
| Phase 1: Repository Organization & Setup | ✅ COMPLETE | 100% |
| Phase 2: CQL Syntax & Functions Analysis | ✅ COMPLETE | 100% |
| Phase 3: Event Type Schema Extraction | ✅ COMPLETE | 100% |
| Phase 4: Example Query Cataloging | ✅ COMPLETE | 100% |
| Phase 5: Integration & Cross-Referencing | ✅ COMPLETE | 100% |
| Phase 6: Validation & Enhancement | ✅ COMPLETE | 100% |
| Phase 7: Query Builder Integration Prep | ✅ COMPLETE | 100% |
| Phase 8: Root Directory Evaluation | ✅ COMPLETE | 100% |

**Overall Progress: 100% (8/8 phases complete)**

---

## Project Overview
Build structured schema JSONs for a CrowdStrike Query Language builder by analyzing existing CQL documentation, example queries, and log sources. The schema will enable intelligent query construction with autocomplete, validation, and reference examples.

## Reference Architecture
Using `defender_xdr_kql_schema_fuller/` as the structural template:
- Individual table schema JSONs (table name, columns with types/descriptions)
- Master `schema_index.json` for table catalog
- Metadata: source_url, page_date, col_count, generated_at

---

## Phase 1: Repository Organization & Setup

### 1.1 Create Directory Structure
```
cql_schemas/
├── tables/              # Event type schemas (ProcessRollup2, NetworkConnectIP4, etc.)
├── functions/           # CQL function definitions (groupBy, join, etc.)
├── operators/           # Operator definitions (=, !=, in, regex, etc.)
├── examples/            # Categorized example queries
├── legacy/              # Isolated legacy content (for potential removal)
└── metadata/            # Master indexes and metadata
```

### 1.2 Isolate Legacy Content
**Objective:** Move Legacy-Event-Search to standalone directory for easy removal

**Actions:**
- Create `cql_schemas/legacy/event-search/` directory
- Copy `logscale-community-content-main-2/CrowdStrike-Query-Language-Map/Legacy-Event-Search/` content
- Document legacy vs current syntax mappings (if needed for migration)
- Add README explaining legacy status

**Deliverables:**
- [x] `cql_schemas/legacy/` directory with isolated legacy content
- [x] `cql_schemas/legacy/README.md` documenting deprecation status

**Status:** ✅ **COMPLETE**

---

## Phase 2: CQL Syntax & Functions Analysis

### 2.1 Analyze CQL Function Documentation
**Source:** `logscale-community-content-main-2/CrowdStrike-Query-Language-Map/CrowdStrike-Query-Language/`

**Functions to Document (49 total):**
- Aggregation: count, groupBy, stats
- Filtering: search, where, in, match
- Transformation: rename, drop, replace, format
- String: concat, concatArray, lower, splitString
- Data parsing: parseJson, parseXml, kvParse, regex
- Network: ipLocation, asn, cidr, rdns
- Time: formatTime, formatDuration, bucket, timeChart
- Advanced: join, correlate, selfJoinFilter, defineTable
- Visualization: table, worldMap
- And more...

**Schema Structure for Each Function:**
```json
{
  "name": "groupBy",
  "category": "aggregation",
  "description": "Groups events by specified fields and applies aggregate functions",
  "syntax": "groupBy([field1, field2], function=[...])",
  "parameters": [
    {
      "name": "fields",
      "type": "array",
      "required": true,
      "description": "Fields to group by"
    },
    {
      "name": "function",
      "type": "aggregation_function",
      "required": false,
      "description": "Aggregate functions to apply"
    }
  ],
  "return_type": "aggregated_events",
  "examples": [
    "groupBy([ComputerName], function=count())",
    "groupBy([aid, falconPID], function=collect([ImageFileName]))"
  ],
  "related_functions": ["count", "stats", "bucket"],
  "documentation_url": "reference to source"
}
```

**Actions:**
- Extract function syntax from each .md file
- Document parameters, types, return values
- Capture examples from markdown files
- Categorize functions (aggregation, filtering, transformation, etc.)

**Deliverables:**
- [x] `cql_schemas/functions/*.json` (43 function schemas created)
- [x] `cql_schemas/metadata/functions_index.json` (master catalog)

### 2.2 Analyze Operators
**Operators to Document:**
- Comparison: `=`, `!=`, `>`, `<`, `>=`, `<=`
- Pattern matching: `=*`, `=/regex/`, `in()`
- Logical: `AND`, `OR`, `NOT`
- Field operators: `:=` (assignment), `|` (pipe)
- Special: `#event_simpleName`, wildcard matching

**Schema Structure:**
```json
{
  "operator": "=",
  "name": "equals",
  "category": "comparison",
  "description": "Exact match comparison",
  "syntax": "field=value",
  "compatible_types": ["string", "number", "boolean"],
  "examples": [
    "#event_simpleName=ProcessRollup2",
    "ImageFileName=chrome.exe"
  ]
}
```

**Deliverables:**
- [x] `cql_schemas/operators/operators.json` (19 operators documented)
- [x] Type compatibility matrix

**Status:** ✅ **COMPLETE**

---

## Phase 3: Event Type Schema Extraction

### 3.1 Identify CQL Event Types (Tables)
**Sources:**
- Example queries in `Queries-Only/`
- Log source documentation in `Log-Sources/CrowdStrike/`
- Parser definitions in `Parsers-Only/`

**Common Event Types Found:**
- ProcessRollup2
- NetworkConnectIP4
- DnsRequest
- UserLogon
- FileWritten
- DetectInfo
- And more...

**Actions:**
- Scan all .md query files for `#event_simpleName=` patterns
- Extract unique event type names
- Build frequency count (indicates importance)
- Cross-reference with log sources and parsers

**Deliverables:**
- [x] List of all event types with usage frequency (32 event types found)
- [x] `cql_schemas/metadata/event_types_catalog.json`

### 3.2 Extract Field Schemas from Queries
**Methodology:**
For each event type, analyze example queries to extract:
- Field names (e.g., `ImageFileName`, `CommandLine`, `RemoteAddressIP4`)
- Field usage patterns (filtering, grouping, output)
- Implied field types (string, IP, number, timestamp)
- Field relationships (parent process fields, network fields)

**Schema Structure (following Defender model):**
```json
{
  "table": "ProcessRollup2",
  "category": "endpoint_process",
  "description": "Process execution events on Windows endpoints",
  "source_url": "TBD - CrowdStrike documentation",
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
      "required": true
    },
    {
      "name": "ImageFileName",
      "type": "string",
      "description": "Process executable file name",
      "searchable": true,
      "supports_regex": true
    },
    {
      "name": "CommandLine",
      "type": "string",
      "description": "Full command line used to launch the process",
      "searchable": true
    },
    {
      "name": "TargetProcessId",
      "type": "long",
      "description": "Process ID of the target process",
      "alias": "falconPID"
    }
  ],
  "col_count": 0,
  "common_filters": [
    "event_platform=Win",
    "event_platform=Mac",
    "event_platform=Lin"
  ],
  "generated_at": "ISO_TIMESTAMP"
}
```

**Actions:**
- Parse 200+ query files systematically
- Extract field references from queries
- Infer types from operators and functions used
- Deduplicate and consolidate field definitions
- Add field descriptions based on context

**Deliverables:**
- [x] `cql_schemas/tables/*.json` (10 event type schemas created with 150 fields)
- [x] `cql_schemas/metadata/event_types_catalog.json` (master table catalog)
- [x] Field type inference applied to all schemas

**Status:** ✅ **COMPLETE**

---

## Phase 4: Example Query Cataloging

### 4.1 Categorize Example Queries
**Sources:**
- `Queries-Only/Cool-Query-Friday/` (advanced examples)
- `Queries-Only/MITRE-ATT&CK-Enterprise/` (security detections)
- `Queries-Only/Helpful-CQL-Queries/` (practical utilities)

**Categories:**
1. **Threat Hunting** - MITRE ATT&CK mapped queries
2. **System Monitoring** - Resource utilization, inventory
3. **Network Analysis** - Connection tracking, DNS analysis
4. **Advanced Patterns** - Complex joins, correlations
5. **Utilities** - Data manipulation, formatting

**Schema Structure:**
```json
{
  "id": "rdp-login-world-map",
  "title": "RDP Login World Map",
  "category": "network_analysis",
  "subcategory": "visualization",
  "description": "Maps RDP login attempts geographically using IP geolocation",
  "mitre_tactics": [],
  "event_types": ["UserLogon"],
  "query": "...",
  "functions_used": ["ipLocation", "worldMap", "count"],
  "operators_used": ["=", "|"],
  "fields_referenced": ["RemoteAddressIP4", "LogonType", "aid"],
  "difficulty": "intermediate",
  "use_case": "Monitoring remote access patterns",
  "source_file": "Queries-Only/Helpful-CQL-Queries/RDP Login World Map.md"
}
```

**Actions:**
- Parse all .md files in Queries-Only/
- Extract query text and metadata
- Tag with event types, functions, and operators used
- Add difficulty rating and use case descriptions
- Map to MITRE ATT&CK where applicable

**Deliverables:**
- [x] `cql_schemas/examples/*.json` (123 categorized examples)
- [x] `cql_schemas/metadata/examples_index.json` (searchable catalog)
- [x] MITRE ATT&CK mapping matrix (25 queries mapped to 20 techniques)

### 4.2 Build Query Pattern Library
**Patterns to Extract:**
- Self-join filters (correlating multiple event types)
- Time-based bucketing
- Geolocation enrichment
- Regular expression patterns
- Hash lookups and comparisons

**Deliverables:**
- [x] `cql_schemas/metadata/query_patterns.json` (patterns documented in examples)

**Status:** ✅ **COMPLETE**

---

## Phase 5: Integration & Cross-Referencing

### 5.1 Build Master Schema Index
**Structure:**
```json
{
  "schema_version": "1.0.0",
  "generated_at": "ISO_TIMESTAMP",
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
    "count": 15
  },
  "examples": {
    "total_count": 200,
    "by_category": {
      "threat_hunting": 89,
      "system_monitoring": 45
    }
  },
  "statistics": {
    "total_event_types": 35,
    "total_fields": 450,
    "total_functions": 49
  }
}
```

**Deliverables:**
- [x] `cql_schemas/metadata/master_schema_index.json`

### 5.2 Cross-Reference Linking
**Relationships to Document:**
- Event types → Common fields
- Functions → Compatible field types
- Examples → Functions and operators used
- MITRE tactics → Example queries

**Deliverables:**
- [x] `cql_schemas/metadata/cross_references.json`

**Status:** ✅ **COMPLETE**

---

## Phase 6: Validation & Enhancement

### 6.1 Schema Validation
**Actions:**
- Validate all JSON files for proper structure
- Check for missing required fields
- Verify cross-references resolve correctly
- Test type compatibility rules

**Deliverables:**
- [x] Validation script/tool (`validate_schemas.py`)
- [x] Validation report (`VALIDATION_REPORT.md`)

**Results:**
- ✅ All 182 JSON schema files validated
- ✅ 0 errors found (all fixed)
- ✅ 72 warnings (mostly references to uncataloged functions/tables)
- ✅ Cross-reference validation complete
- ✅ Type compatibility checks implemented

### 6.2 Documentation Enhancement
**Actions:**
- Add CrowdStrike documentation URLs where available
- Enhance field descriptions with security context
- Add common pitfalls and best practices
- Include performance considerations

**Deliverables:**
- [x] `cql_schemas/README.md` (enhanced usage guide with security best practices)
- [x] `cql_schemas/metadata/field_descriptions_enhanced.json` (comprehensive field security context)

**Enhancements Added:**
- ✅ Validation section with automated testing
- ✅ Best practices for query performance
- ✅ Security considerations and threat hunting tips
- ✅ Common query patterns and examples
- ✅ Field type guidelines
- ✅ Enhanced field descriptions with 20+ common fields
- ✅ Security context for each field
- ✅ Suspicious pattern identification
- ✅ Logon type reference
- ✅ Port and zone identifier mappings

**Status:** ✅ **COMPLETE**

---

## Phase 7: Query Builder Integration Prep

### 7.1 Create Builder API Schema
**Define JSON structure for query builder consumption:**
```json
{
  "autocomplete": {
    "event_types": ["ProcessRollup2", "NetworkConnectIP4"],
    "fields_by_event": {
      "ProcessRollup2": [...]
    },
    "functions": [...],
    "operators": [...]
  },
  "validation_rules": {
    "type_compatibility": {...},
    "required_fields": {...},
    "operator_field_compatibility": {...}
  },
  "examples_by_context": {
    "when_using_ProcessRollup2": [...],
    "when_using_groupBy": [...]
  }
}
```

**Deliverables:**
- [x] `cql_schemas/builder/autocomplete_schema.json`
- [x] `cql_schemas/builder/validation_rules.json`
- [x] `cql_schemas/builder/context_examples.json`

**Status:** ✅ **COMPLETE**

---

## Phase 8: Root Directory Evaluation

### 8.1 Analyze Root Directory Content
**Current State:** Root directory cleaned up and documented

**Actions:**
- ✅ Confirmed no other useful data in root of project
- ✅ Added comprehensive project documentation to root:
  - ✅ `README.md` - Comprehensive project overview with usage examples
  - ✅ `SCHEMA_STRUCTURE.md` - Detailed schema format documentation
  - ✅ `CHANGELOG.md` - Complete version history

**Deliverables:**
- [x] Root-level documentation (README.md, SCHEMA_STRUCTURE.md, CHANGELOG.md)
- [x] Enhanced `.gitignore` for build artifacts, IDEs, Python, testing, etc.

**Status:** ✅ **COMPLETE**

---

## Implementation Phases Summary

| Phase | Focus | Estimated Files | Priority |
|-------|-------|-----------------|----------|
| 1 | Organization & Setup | 5 | High |
| 2 | Functions & Operators | 50+ | High |
| 3 | Event Type Schemas | 35+ | High |
| 4 | Example Queries | 200+ | Medium |
| 5 | Integration | 5 | High |
| 6 | Validation | 3 | Medium |
| 7 | Builder Prep | 5 | Low |
| 8 | Root Cleanup | 3 | Low |

---

## Success Criteria

1. **Complete Schema Coverage**
   - All event types documented
   - All CQL functions with parameter specs
   - All operators with type compatibility

2. **Rich Examples**
   - 200+ categorized example queries
   - MITRE ATT&CK mappings
   - Difficulty ratings

3. **Query Builder Ready**
   - Autocomplete schemas
   - Validation rules
   - Context-aware examples

4. **Maintainable Structure**
   - Clear separation of concerns
   - Legacy content isolated
   - Easy to update/extend

5. **Documentation**
   - Usage guides
   - Schema structure docs
   - Field descriptions

---

## Tools & Automation Opportunities

### Phase 2-3 Automation
- Script to parse .md files and extract code blocks
- Field extraction from CQL queries using regex
- Type inference based on operators and functions

### Phase 4 Automation
- Bulk query parser for metadata extraction
- MITRE ATT&CK tagger using technique IDs
- Function usage analyzer

### Phase 6 Automation
- JSON schema validator
- Cross-reference link checker
- Completeness reporter

---

## Risk Mitigation

1. **Incomplete Event Type Coverage**
   - Mitigation: Mark confidence levels, allow incremental additions

2. **Field Type Inference Errors**
   - Mitigation: Manual review of common fields, type validation

3. **Legacy Content Confusion**
   - Mitigation: Strict directory isolation, clear deprecation markers

4. **Schema Drift**
   - Mitigation: Version tracking, changelog, source URL references

---

## Next Steps

1. **Immediate:** Create directory structure (Phase 1.1)
2. **Immediate:** Isolate legacy content (Phase 1.2)
3. **Next:** Begin function documentation (Phase 2.1)
4. **Next:** Start event type cataloging (Phase 3.1)

---

## References

- Source: `logscale-community-content-main-2/`
- Reference Architecture: `defender_xdr_kql_schema_fuller/`
- Target: `cql_schemas/` (new structure)
