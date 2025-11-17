# CrowdStrike Query Language (CQL) Schema Repository

A comprehensive, structured repository of CQL schemas, functions, operators, and examples designed for intelligent query builders and security analysts.

## Overview

This repository provides machine-readable schemas and human-readable documentation for CrowdStrike Query Language (CQL), enabling:

- **Intelligent Autocomplete** - Complete event types, fields, functions, and operators
- **Real-Time Validation** - Type checking, parameter validation, and syntax verification
- **Contextual Examples** - 120+ categorized query examples with MITRE ATT&CK mappings
- **Query Builder Integration** - Ready-to-use schemas for IDE and UI implementations

## Project Status

**Version:** 2.0.0
**Status:** Production Ready
**Completion:** 100% (All phases complete)
**Total Schemas:** 270 JSON files
**Total Examples:** 123 categorized queries
**How-Tos:** 54 guides
**Best Practices:** 34 guides

## Repository Structure

```
cql_claude/
├── cql_schemas/               # Core schema directory
│   ├── tables/                # Event type schemas (10 types, 150+ fields)
│   ├── functions/             # CQL function definitions (43 functions)
│   ├── operators/             # Operator definitions (19 operators)
│   ├── examples/              # Categorized example queries (123 examples)
│   │   ├── cool_query_friday/ # Advanced examples
│   │   ├── helpful_queries/   # Practical utilities
│   │   └── mitre_attack/      # Security detections (25 MITRE mappings)
│   ├── how_tos/               # How-to guides (54 guides)
│   ├── best_practices/        # Best practice guides (34 guides)
│   ├── builder/               # Query builder integration schemas
│   │   ├── autocomplete_schema.json     # Autocomplete data (890+ lines)
│   │   ├── validation_rules.json        # Validation rules (570+ lines)
│   │   └── context_examples.json        # Context examples (760+ lines)
│   ├── metadata/              # Master indexes and cross-references
│   │   ├── master_schema_index.json     # Complete catalog
│   │   ├── event_types_catalog.json     # Event type index
│   │   ├── functions_index.json         # Function catalog
│   │   ├── examples_index.json          # Example query index
│   │   ├── how_tos_index.json           # How-tos index
│   │   ├── best_practices_index.json    # Best practices index
│   │   ├── cross_references.json        # Relationship mappings
│   │   └── field_descriptions_enhanced.json
│   ├── legacy/                # Deprecated Splunk-style syntax (isolated)
│   ├── README.md              # Schema usage guide
│   ├── CATALOG_SUMMARY.md     # Schema statistics
│   ├── QUICK_REFERENCE.md     # Quick start guide
│   └── SCHEMA_STRUCTURE.md    # Detailed schema documentation
├── docs/                      # Documentation
│   ├── SCHEMA_REVIEW_FINDINGS.md # Schema review findings
│   └── archive/               # Historical documentation
├── validate_schemas.py        # Schema validation tool
├── catalog_cql_queries.py     # Query cataloging tool
├── migrate_how_tos_best_practices.py # Migration tool
├── VALIDATION_REPORT.md       # Validation results
├── CHANGELOG.md               # Version history
└── README.md                  # This file
```

## Quick Start

### For Query Builder Developers

#### 1. Autocomplete Implementation

```javascript
// Load autocomplete schema
const autocomplete = require('./cql_schemas/builder/autocomplete_schema.json');

// User selects ProcessRollup2
const eventType = "ProcessRollup2";
const fields = autocomplete.fields_by_event_type[eventType];

// Display field suggestions
fields.forEach(field => {
  console.log(`${field.name} (${field.type}): ${field.description}`);
});
```

#### 2. Validation Implementation

```javascript
// Load validation rules
const validation = require('./cql_schemas/builder/validation_rules.json');

// Validate operator-field compatibility
const operator = ">";
const fieldType = "string";

const operatorRule = validation.type_compatibility_matrix.operator_to_field_types[operator];
if (!operatorRule.compatible_types.includes(fieldType)) {
  console.error(operatorRule.error_message);
  // Error: "Operator '>' can only be used with numeric or timestamp fields"
}
```

#### 3. Context Examples

```javascript
// Load context examples
const examples = require('./cql_schemas/builder/context_examples.json');

// User selects ProcessRollup2
const eventType = "ProcessRollup2";
const templates = examples.examples_by_event_type[eventType].starter_templates;

// Display starter templates
templates.forEach(template => {
  console.log(`${template.name} (${template.difficulty})`);
  console.log(`Query: ${template.query}`);
});
```

### For Security Analysts

#### 1. Browse Examples by Use Case

```bash
# View threat hunting queries
cat cql_schemas/examples/helpful_queries/*.json | jq '.category' | grep -i threat

# View MITRE ATT&CK mapped queries
ls cql_schemas/examples/mitre_attack/
```

#### 2. Search for Specific Functions

```bash
# Find all examples using ipLocation
grep -r "ipLocation" cql_schemas/examples/

# View function documentation
cat cql_schemas/functions/ipLocation.json
```

#### 3. Explore Event Types

```bash
# View available event types
cat cql_schemas/metadata/event_types_catalog.json | jq '.event_types[].name'

# View ProcessRollup2 schema
cat cql_schemas/tables/ProcessRollup2.json | jq
```

## Key Features

### 1. Comprehensive Event Type Coverage

- **10 Event Types Documented:**
  - ProcessRollup2 (45 fields)
  - NetworkConnectIP4 (18 fields)
  - DnsRequest (12 fields)
  - UserLogon (22 fields)
  - OsVersionInfo (15 fields)
  - And more...

- **150+ Fields with:**
  - Type information (string, long, number, ip_address, timestamp)
  - Descriptions and usage patterns
  - Searchability and regex support indicators
  - Example values and aliases

### 2. Complete Function Library

- **43 CQL Functions Categorized:**
  - **Aggregation:** groupBy, count, bucket, top (4 functions)
  - **Network:** ipLocation, asn, cidr, rdns, geoHash (5 functions)
  - **String:** format, regex, lower, concat, replace (7 functions)
  - **Transformation:** drop, rename, default, parseJson (6 functions)
  - **Time:** formatTime, formatDuration, timeChart (3 functions)
  - **Advanced:** join, selfJoinFilter, correlate (4 functions)

- **Each Function Includes:**
  - Complete signature with parameters
  - Parameter types and requirements
  - Return type and description
  - Usage examples and related functions

### 3. Rich Example Library

- **123 Categorized Examples:**
  - Threat Hunting (35 queries)
  - Network Analysis (28 queries)
  - System Monitoring (25 queries)
  - Advanced Patterns (20 queries)
  - Utilities (15 queries)

- **25 MITRE ATT&CK Mappings:**
  - 20 unique techniques covered
  - Detection queries for each technique
  - Tactic and technique descriptions

### 4. Query Builder Schemas

- **Autocomplete Schema (890+ lines):**
  - Event types with metadata
  - Fields organized by event type
  - Functions with signatures
  - Operators with type compatibility
  - Common correlation fields

- **Validation Rules (570+ lines):**
  - Type compatibility matrix
  - Parameter validation rules
  - Common error patterns
  - Performance warnings
  - Best practices

- **Context Examples (760+ lines):**
  - Starter templates by event type
  - Function usage examples
  - Use case specific queries
  - MITRE technique detections
  - Quick start patterns

## Usage Examples

### Example 1: Process Execution Monitoring

```cql
#event_simpleName=ProcessRollup2
| groupBy([ImageFileName], function=count(aid, distinct=true, as=UniqueEndpoints))
| sort(UniqueEndpoints, order=desc)
| head(20)
```

**Use Case:** Identify most common processes across your environment

### Example 2: Lateral Movement Detection

```cql
#event_simpleName=ProcessRollup2
ImageFileName=psexec.exe OR ImageFileName=paexec.exe
| table([aid, ComputerName, UserName, CommandLine, TargetProcessId])
```

**Use Case:** Detect potential lateral movement using PsExec
**MITRE ATT&CK:** T1021.002 (Remote Services: SMB/Windows Admin Shares)

### Example 3: Network Connection Analysis with Geolocation

```cql
#event_simpleName=NetworkConnectIP4
| ipLocation(RemoteAddressIP4)
| stats(count(aid, as=ConnectionCount), dc(aid, as=UniqueEndpoints), by=[RemoteAddressIP4.country])
| sort(ConnectionCount, order=desc)
```

**Use Case:** Analyze network connections by country

### Example 4: User Logon World Map

```cql
#event_simpleName=UserLogon LogonType=10
| ipLocation(RemoteAddressIP4)
| stats(count(aid, as=LogonCount), by=[RemoteAddressIP4.lat, RemoteAddressIP4.lon])
| worldMap(lat=RemoteAddressIP4.lat, lon=RemoteAddressIP4.lon, magnitude=LogonCount)
```

**Use Case:** Visualize remote desktop logon attempts geographically

## Validation

The repository includes automated validation to ensure schema integrity:

```bash
# Run validation
python validate_schemas.py

# View validation report
cat VALIDATION_REPORT.md
```

**Validation Results:**
- ✅ All 182 JSON schemas validated
- ✅ 0 errors found
- ✅ Cross-reference validation complete
- ✅ Type compatibility checks passed

## Best Practices

### Query Performance

1. **Filter Early:** Apply event type and field filters before aggregation
2. **Use aid for Correlation:** Always include `aid` when joining event types
3. **Limit Results:** Use `head()`, `tail()`, or `limit` to control output size
4. **Avoid High Cardinality:** Don't group by `aid` or `TargetProcessId` (use FileName instead)
5. **Use in() Over Multiple OR:** `field in(value1, value2)` is more efficient

### Security Hunting

1. **Start with Event Type:** Always begin queries with `#event_simpleName=`
2. **Leverage Common Fields:** Use `UserSid` over `UserName` for reliability
3. **Use Regex Wisely:** Anchor patterns to avoid performance issues
4. **Correlate Events:** Join ProcessRollup2 with NetworkConnectIP4 for complete context

### Schema Usage

1. **Check Field Types:** Validate field types before applying operators
2. **Reference Examples:** Use context examples as starting templates
3. **Validate Parameters:** Check function parameter requirements before use
4. **Test Incrementally:** Build queries step-by-step, validating each stage

## Integration Points

### IDE Integration

The schemas are designed for integration with:
- Visual Studio Code extensions
- IntelliJ IDEA plugins
- Custom query builders
- Web-based CQL editors

### CI/CD Integration

```yaml
# Example: Validate queries in CI pipeline
- name: Validate CQL Queries
  run: |
    python validate_schemas.py
    # Add custom query validation logic
```

### API Integration

```python
# Example: Load schemas programmatically
import json

# Load autocomplete data
with open('cql_schemas/builder/autocomplete_schema.json') as f:
    autocomplete = json.load(f)

# Load validation rules
with open('cql_schemas/builder/validation_rules.json') as f:
    validation = json.load(f)
```

## Statistics

### Schema Coverage

- **Event Types:** 10 documented
- **Fields:** 150+ across all event types
- **Functions:** 43 with complete signatures
- **Operators:** 19 with type compatibility
- **Examples:** 123 categorized queries
- **How-Tos:** 54 practical guides
- **Best Practices:** 34 optimization guides
- **MITRE Mappings:** 25 queries to 20 techniques

### File Counts

- **Table Schemas:** 10 JSON files
- **Function Schemas:** 43 JSON files
- **Operator Schema:** 1 JSON file
- **Example Queries:** 123 JSON files
- **How-To Guides:** 54 JSON files
- **Best Practices:** 34 JSON files
- **Metadata Files:** 7 JSON files
- **Builder Schemas:** 3 JSON files
- **Total JSON Files:** 270 files

## Documentation

- **[cql_schemas/README.md](cql_schemas/README.md)** - Schema usage guide
- **[cql_schemas/SCHEMA_STRUCTURE.md](cql_schemas/SCHEMA_STRUCTURE.md)** - Detailed schema format documentation
- **[cql_schemas/CATALOG_SUMMARY.md](cql_schemas/CATALOG_SUMMARY.md)** - Schema statistics
- **[cql_schemas/QUICK_REFERENCE.md](cql_schemas/QUICK_REFERENCE.md)** - Quick start guide
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and updates
- **[VALIDATION_REPORT.md](VALIDATION_REPORT.md)** - Schema validation results
- **[docs/SCHEMA_REVIEW_FINDINGS.md](docs/SCHEMA_REVIEW_FINDINGS.md)** - Schema review findings
- **[docs/archive/](docs/archive/)** - Historical documentation

## Contributing

This repository is generated from the CrowdStrike LogScale community content. To contribute:

1. Submit improvements to the source repository
2. Run validation after making changes
3. Update documentation as needed
4. Increment version numbers appropriately

## Version History

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

## License

This repository is derived from the [CrowdStrike LogScale Community Content](https://github.com/CrowdStrike/logscale-community-content) repository.

## Support

For questions or issues:
- Review the [cql_schemas/README.md](cql_schemas/README.md) for schema usage
- Check [VALIDATION_REPORT.md](VALIDATION_REPORT.md) for known issues
- Consult the [docs/SCHEMA_REVIEW_FINDINGS.md](docs/SCHEMA_REVIEW_FINDINGS.md) for recent updates

## Acknowledgments

- CrowdStrike LogScale team for the community content repository
- Security analysts who contributed example queries
- MITRE ATT&CK framework for threat categorization

---

**Last Updated:** 2025-11-15
**Schema Version:** 2.0.0
**Project Status:** Production Ready

## Recent Updates (v2.0.0)

- ✅ **Unified How-Tos and Best Practices Schemas** - Standardized 88 guidance documents
- ✅ **New Directories** - Added `cql_schemas/how_tos/` and `cql_schemas/best_practices/`
- ✅ **New Indexes** - Created `how_tos_index.json` and `best_practices_index.json`
- ✅ **Documentation Reorganization** - Moved historical docs to `docs/archive/`
- ✅ **Enhanced Master Index** - Updated with how-tos and best practices sections
