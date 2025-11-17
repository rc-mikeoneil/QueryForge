# CrowdStrike Query Language (CQL) Schemas

Structured schema definitions for building intelligent CQL query tools with autocomplete, validation, and contextual help.

## Overview

This repository contains comprehensive JSON schemas for CrowdStrike Query Language (CQL), extracted from the LogScale community content repository. The schemas enable:

- **Autocomplete** - Field suggestions, function parameters, operator compatibility
- **Validation** - Type checking, parameter validation, syntax verification
- **Documentation** - Inline help, examples, use cases
- **Query Building** - Visual query construction tools

## Directory Structure

```
cql_schemas/
├── functions/          # 43 CQL function schemas
├── operators/          # Operator definitions with type compatibility
├── tables/             # Event type schemas (10 event types)
├── examples/           # Categorized example queries (123 queries - COMPLETE)
├── legacy/             # Deprecated legacy syntax (isolated for removal)
├── metadata/           # Master indexes and catalogs
│   ├── functions_index.json        # Function catalog
│   ├── event_types_catalog.json    # Event type catalog
│   ├── examples_index.json         # Example queries master index
│   └── master_schema_index.json    # Overall schema index
├── builder/            # Query builder integration (Phase 7 - pending)
└── types/              # TypeScript definitions (Phase 7 - pending)
```

## Schema Files

### Functions (43 total)

Located in `functions/`, each function has a JSON schema with:
- Function name, category, and description
- Syntax and parameters with types
- Return type and output fields
- Usage examples from real queries
- Related functions and use cases
- Official documentation links

**Categories:**
- **Aggregation** (4): bucket, count, groupBy, top
- **Network** (5): asn, cidr, geoHash, ipLocation, rdns
- **String** (7): concat, format, length, lower, regex, replace, splitString
- **Transformation** (6): default, drop, kvParse, parseJson, parseXml, rename
- **Control Flow** (2): case, match_conditional
- **Advanced** (4): correlate, defineTable, join, selfJoinFilter
- **Utility** (10): createEvents, head, in, readFile, round, select, sort, table, tail, test
- **Array** (1): concatArray
- **Time** (3): formatDuration, formatTime, timeChart
- **Operators** (1): assignment_operator (:=)

### Operators

Located in `operators/operators.json`, includes:
- 19 operators across 6 categories
- Type compatibility matrix
- Operator precedence rules
- Usage examples and best practices

**Categories:**
- Comparison: =, !=, >, <, >=, <=
- Pattern: =*, =/regex/, in()
- Assignment: :=
- Flow: | (pipe)
- Logical: AND, OR, NOT, !
- Special: #, =~, <=>, *

### Example Queries (123 total)

Located in `examples/`, organized by category:
- **cool_query_friday/** (5 queries) - Advanced examples from Cool Query Friday blog series
- **mitre_attack/** (25 queries) - Security detections mapped to MITRE ATT&CK framework
- **helpful_queries/** (93 queries) - Practical utility and analysis queries

Each query includes:
- Full CQL query text
- Difficulty level (basic, intermediate, advanced, expert)
- Event types used
- Functions and operators
- MITRE ATT&CK mapping (where applicable)
- Platform coverage
- Use case description
- Searchable tags

**See detailed documentation:**
- `CATALOG_SUMMARY.md` - Comprehensive statistics and analysis
- `QUICK_REFERENCE.md` - Quick reference for finding and using queries

### Master Indexes

Located in `metadata/`:
- **functions_index.json** - Catalog of all functions with quick reference
- **event_types_catalog.json** - Event type schemas catalog
- **examples_index.json** - Master index of all 123 example queries
- **master_schema_index.json** - Complete schema overview and statistics

## Usage

### For Query Builders

```javascript
// Load function index
const functions = require('./cql_schemas/metadata/functions_index.json');

// Get functions by category
const aggregationFuncs = functions.by_category.aggregation;
// ["bucket", "count", "groupBy", "top"]

// Load specific function schema
const groupBy = require('./cql_schemas/functions/groupBy.json');
console.log(groupBy.syntax); // "groupBy([field1, field2, ...], function=...)"
console.log(groupBy.parameters); // Array of parameter definitions
```

### For Autocomplete

```javascript
// Load operators
const operators = require('./cql_schemas/operators/operators.json');

// Get compatible operators for string fields
const stringOps = operators.type_compatibility_matrix.string;
// ["=", "!=", "=*", "=/regex/", "in()", ":=", "=~"]

// Get operator details
const regex = operators.operators.find(op => op.name === "regex_match");
console.log(regex.examples); // Array of regex examples
```

### For Validation

```javascript
// Validate operator usage
function canUseOperator(operator, fieldType) {
  const ops = require('./cql_schemas/operators/operators.json');
  return ops.type_compatibility_matrix[fieldType].includes(operator);
}

canUseOperator('>', 'string'); // false
canUseOperator('>', 'number'); // true
```

## Legacy Content

The `legacy/` directory contains deprecated Event Search syntax documentation. This content is isolated for:
1. Historical reference
2. Migration support from legacy to current CQL
3. Easy removal when no longer needed

**To remove legacy content:**
```bash
rm -rf cql_schemas/legacy/
```

## Schema Reference Architecture

This schema structure is modeled after `defender_xdr_kql_schema_fuller/`, which provides:
- Individual table schemas with column definitions
- Master index for table catalog
- Metadata including source URLs and timestamps

## Development Phases

- ✅ **Phase 1**: Repository Organization & Setup
- ✅ **Phase 2**: CQL Functions & Operators Analysis
- ✅ **Phase 3**: Event Type Schema Extraction (10 event types)
- ✅ **Phase 4**: Example Query Cataloging (123 queries)
- ✅ **Phase 5**: Integration & Cross-Referencing
- ✅ **Phase 6**: Validation & Enhancement
- ⏳ **Phase 7**: Query Builder Integration Prep
- ⏳ **Phase 8**: Root Directory Evaluation

See `CQL_SCHEMA_BUILDER_PLAN.md` for detailed implementation plan.

## Statistics

- **Total Schemas**: 177 (43 functions + 1 operator collection + 10 event types + 123 example queries)
- **Total Functions**: 43
- **Total Operators**: 19
- **Total Event Types**: 10
- **Total Example Queries**: 123
  - Cool Query Friday: 5
  - MITRE ATT&CK: 25 (20 unique techniques)
  - Helpful Queries: 93
- **Function Categories**: 10
- **Operator Categories**: 6
- **Query Difficulty Levels**: 4 (Basic: 39, Intermediate: 59, Advanced: 13, Expert: 12)
- **Query Types**: 7 (Analysis, Utility, Hunting, Detection, Inventory, Visualization, Monitoring)
- **Platform Coverage**: 4 (Windows: 65, Linux: 61, Mac: 14, Cross-platform: 34)
- **Documentation URLs**: 43
- **Usage Examples**: 100+

## Validation

A comprehensive validation script is provided to ensure schema integrity:

```bash
python3 validate_schemas.py
```

The validator checks:
- ✅ Valid JSON syntax in all schema files
- ✅ Required fields present in each schema type
- ✅ Cross-reference integrity (functions/tables referenced in examples)
- ✅ Type compatibility rules
- ✅ Column count accuracy
- ✅ Parameter definitions completeness

**Validation Report:** See `VALIDATION_REPORT.md` for the latest validation results.

## Best Practices & Common Pitfalls

### Query Performance

**Do's:**
- ✅ Filter early with `#event_simpleName` to reduce data volume
- ✅ Use `in()` function instead of multiple OR conditions
- ✅ Leverage `cidr()` for network range filtering instead of manual comparisons
- ✅ Use `groupBy()` with appropriate limits to prevent memory issues
- ✅ Apply time filters to limit search scope

**Don'ts:**
- ❌ Avoid wildcard searches on high-cardinality fields without other filters
- ❌ Don't use regex when simple wildcards suffice (=* is faster than =/regex/)
- ❌ Avoid unbounded `groupBy()` operations on large datasets
- ❌ Don't chain excessive pipe operations without intermediate filtering

### Security Considerations

**Threat Hunting Best Practices:**
- 🔒 Always validate user input when using CommandLine or ImageFileName filters
- 🔒 Use `UserSid` instead of `UserName` for reliable user correlation (names can be spoofed)
- 🔒 Check code signature fields (`SignInfoFlags`) when hunting for unsigned executables
- 🔒 Filter out system accounts to reduce noise: `UserName!=/(\$\$|^DWM-|LOCAL\\sSERVICE|^UMFD-|^$)/`
- 🔒 Use `ZoneIdentifier` to identify files downloaded from the internet (Mark of the Web)
- 🔒 Correlate process events with network events via `TargetProcessId` for command & control detection

**Common Security Fields:**
- `SHA256HashData`, `MD5HashData`, `SHA1HashData` - File hash IOC matching
- `SignInfoFlags` - Code signature validation
- `ZoneIdentifier` - Downloaded file detection
- `ParentProcessId`, `ParentBaseFileName` - Process tree analysis
- `ContextTimeStamp`, `ProcessStartTime` - Temporal analysis

### Field Type Guidelines

**String Fields:**
- Support operators: `=`, `!=`, `=*`, `=/regex/`, `in()`
- Case-sensitive by default unless using regex flags (`/i`)
- Examples: `ImageFileName`, `CommandLine`, `UserName`

**Numeric Fields:**
- Support operators: `=`, `!=`, `>`, `<`, `>=`, `<=`
- Examples: `FileSize`, `ProcessId`, `LogonType`

**Timestamp Fields:**
- Use `formatTime()` for human-readable output
- Use `formatDuration()` for time delta calculations
- Examples: `ContextTimeStamp`, `ProcessStartTime`

**IP Address Fields:**
- Use `ipLocation()` for geolocation enrichment
- Use `cidr()` for network range filtering
- Use `rdns()` for reverse DNS lookups
- Examples: `RemoteAddressIP4`, `LocalAddressIP4`

### Common Query Patterns

**Process Tree Analysis:**
```cql
#event_simpleName=ProcessRollup2
| groupBy([ParentBaseFileName, FileName], function=count())
| sort(field=_count, order=desc, limit=20)
```

**User Context Enrichment:**
```cql
#event_simpleName=ProcessRollup2
| join({#event_simpleName=/^(UserIdentity|UserLogon)$/}, field=UserSid, include=UserName, mode=left)
```

**Temporal Analysis:**
```cql
#event_simpleName=ProcessRollup2
| bucket(timeField=@timestamp, span=1h, function=[count()])
```

**Network Correlation:**
```cql
#event_simpleName=ProcessRollup2 ImageFileName=*powershell*
| join({#event_simpleName=NetworkConnectIP4}, field=TargetProcessId, include=[RemoteAddressIP4, RemotePort])
```

## Contributing

When adding new functions or operators:
1. Follow the existing JSON schema structure
2. Include comprehensive examples
3. Add to appropriate category in indexes
4. Update statistics in master_schema_index.json
5. Run `python3 validate_schemas.py` to ensure validity
6. Review `VALIDATION_REPORT.md` for any issues

## Documentation

Official CQL documentation:
- [LogScale Data Analysis](https://library.humio.com/data-analysis/)
- [CQL Functions Reference](https://library.humio.com/data-analysis/functions.html)
- [CQL Syntax Guide](https://library.humio.com/data-analysis/syntax.html)

## License

Content extracted from CrowdStrike LogScale Community Content repository.

## Version

Schema Version: 1.0.0
Generated: 2025-11-14
Source: logscale-community-content-main-2
