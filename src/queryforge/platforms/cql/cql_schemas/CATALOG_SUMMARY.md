# CQL Query Catalog Summary

## Overview

Successfully cataloged **123 CQL example queries** from the CrowdStrike LogScale Community Content repository with comprehensive metadata schemas.

**Generated:** 2025-11-14
**Version:** 1.0.0

---

## Catalog Statistics

### Total Queries by Category

| Category | Count | Location |
|----------|-------|----------|
| **Helpful CQL Queries** | 93 | `cql_schemas/examples/helpful_queries/` |
| **MITRE ATT&CK Enterprise** | 25 | `cql_schemas/examples/mitre_attack/` |
| **Cool Query Friday** | 5 | `cql_schemas/examples/cool_query_friday/` |
| **TOTAL** | **123** | All categories |

---

## Query Characteristics

### Difficulty Level Distribution

| Difficulty | Count | Percentage | Description |
|------------|-------|------------|-------------|
| **Basic** | 39 | 31.7% | Simple filtering, single event type, no joins |
| **Intermediate** | 59 | 48.0% | Multiple functions, basic aggregations, simple correlations |
| **Advanced** | 13 | 10.6% | Complex joins, multiple event types, advanced aggregations |
| **Expert** | 12 | 9.8% | `correlate()`, `selfJoinFilter()`, complex temporal analysis |

### Query Type Distribution

| Query Type | Count | Description |
|------------|-------|-------------|
| **Analysis** | 39 | Data analysis and investigation queries |
| **Utility** | 33 | Helper queries and tools |
| **Hunting** | 26 | Proactive threat hunting queries |
| **Detection** | 13 | Identifies specific threats or behaviors |
| **Inventory** | 8 | Asset and configuration inventory |
| **Visualization** | 2 | Data visualization (maps, charts) |
| **Monitoring** | 2 | Ongoing monitoring and alerting |

### Platform Coverage

| Platform | Count | Percentage |
|----------|-------|------------|
| **Windows** | 65 | 52.8% |
| **Linux** | 61 | 49.6% |
| **Cross-platform** | 34 | 27.6% |
| **Mac** | 14 | 11.4% |

*Note: Some queries support multiple platforms*

---

## MITRE ATT&CK Coverage

### Tactics Covered

| Tactic Code | Tactic Name | Techniques |
|-------------|-------------|------------|
| **TA007** | Discovery | 20 unique techniques |

### Techniques Covered (Top 10)

1. **T1087** - Account Discovery (4 queries)
   - T1087.001 - Local Account
   - T1087.002 - Domain Account
   - T1087.003 - Email Account
   - T1087.004 - Cloud Account

2. **T1069** - Permission Groups Discovery (3 queries)
   - T1069.001 - Local Groups
   - T1069.002 - Domain Groups
   - T1069.003 - Cloud Groups

3. **T1615** - Group Policy Discovery (1 query)
4. **T1083** - File and Directory Discovery (1 query)
5. **T1057** - Process Discovery (1 query)
6. **T1652** - Device Driver Discovery (1 query)
7. **T1082** - System Information Discovery (1 query)
8. **T1580** - Cloud Infrastructure Discovery (1 query)
9. **T1120** - Peripheral Device Discovery (1 query)
10. **T1201** - Password Policy Discovery (1 query)

**Total MITRE Coverage:** 20 unique techniques across 1 tactic

---

## Top Event Types Used

| Event Type | Usage Count | Description |
|------------|-------------|-------------|
| **ProcessRollup2** | 40 | Process execution events |
| **OsVersionInfo** | 14 | Operating system version information |
| **UserLogon** | 7 | User authentication events |
| **DnsRequest** | 4 | DNS query events |
| **NetworkConnectIP4** | 4 | IPv4 network connection events |
| **AgentOnline** | 3 | Falcon agent online status |
| **ResourceUtilization** | 2 | System resource usage metrics |
| **SystemCapacity** | 2 | System capacity information |
| **ReflectiveDotnetModuleLoad** | 2 | .NET reflective loading events |
| **InstalledBrowserExtension** | 2 | Browser extension inventory |

---

## Top CQL Functions Used

| Function | Usage Count | Purpose |
|----------|-------------|---------|
| **groupBy** | 63 | Group and aggregate data |
| **count** | 40 | Count occurrences |
| **format** | 28 | Format strings and output |
| **drop** | 25 | Remove fields from results |
| **table** | 22 | Display results in table format |
| **default** | 16 | Set default values for fields |
| **match** | 16 | Pattern matching |
| **rename** | 16 | Rename fields |
| **in** | 15 | Check membership in list/array |
| **join** | 13 | Join multiple event streams |

### Advanced Functions Highlighted

- **selfJoinFilter** - Used in expert-level correlation queries
- **correlate** - Advanced event correlation
- **sequence** - Temporal sequence detection
- **ipLocation** - IP geolocation enrichment
- **worldMap** - Geographic visualization
- **sankey** - Sankey diagram visualization

---

## Top Tags

| Tag | Count | Category |
|-----|-------|----------|
| **win** | 65 | Platform |
| **lin** | 61 | Platform |
| **processrollup2** | 40 | Event Type |
| **cross-platform** | 34 | Platform |
| **mac** | 14 | Platform |
| **osversioninfo** | 14 | Event Type |
| **join** | 13 | Function |
| **userlogon** | 7 | Event Type |
| **user** | 6 | Category |
| **dnsrequest** | 4 | Event Type |
| **file** | 4 | Category |
| **process** | 4 | Category |
| **networkconnectip4** | 4 | Event Type |
| **network** | 3 | Category |

---

## Notable Query Examples

### Cool Query Friday Highlights

1. **2021-10-29** - CPU, RAM, Disk, Firmware, TPM 2.0, and Windows 11
   - **Difficulty:** Advanced
   - **Type:** Analysis
   - **Functions:** groupBy, stats, aggregate

2. **2023-06-14** - Watching the Watchers - Profiling Falcon Console Logins via Geohashing
   - **Difficulty:** Intermediate
   - **Type:** Monitoring
   - **Functions:** ipLocation, asn, geohash, groupBy

3. **2023-09-08** - Reflective .Net Module Loads and Program Database (PDB) File Paths
   - **Difficulty:** Intermediate
   - **Type:** Hunting
   - **Event Types:** ReflectiveDotnetModuleLoad

### Expert-Level Queries

1. **Combine ProcessRollup2 and NetworkConnectIP4 Events**
   - Uses `selfJoinFilter` for advanced correlation
   - Multi-event correlation (2 event types)
   - Platform: Windows, Linux

2. **Impossible Time To Travel (UserLogon)**
   - Uses `sequence` for temporal correlation
   - IP geolocation enrichment
   - Calculates geographic distance and travel speed
   - Platform: Cross-platform

3. **Merge Parent_Child PR2 with Join**
   - Complex join operations
   - Process hierarchy analysis
   - Advanced process relationship mapping

### Visualization Queries

1. **RDP Login World Map**
   - Geographic visualization using `worldMap()`
   - IP geolocation with `ipLocation()`
   - Event Type: UserLogon

2. **Create Heatmap of Login Activity**
   - Temporal visualization
   - Login pattern analysis

---

## Query Schema Structure

Each query is cataloged with the following metadata:

```json
{
  "id": "unique-query-identifier",
  "title": "Human-readable query title",
  "source_file": "Original markdown file path",
  "category": "cool_query_friday | mitre_attack | helpful_query",
  "subcategory": "Optional subcategory",
  "description": "Query description",
  "mitre_attack": {
    "tactic_code": "TA007",
    "tactic_name": "Discovery",
    "technique_id": "T1057",
    "technique_name": "Process Discovery",
    "sub_technique_id": null
  },
  "event_types": ["List of event_simpleName values"],
  "functions_used": ["List of CQL functions"],
  "operators_used": ["List of operators"],
  "fields_referenced": ["List of field names"],
  "correlation_patterns": ["join", "selfJoinFilter", "correlate", etc.],
  "difficulty": "basic | intermediate | advanced | expert",
  "query_type": "detection | hunting | analysis | etc.",
  "platforms": ["Win", "Mac", "Lin", "Cross-platform"],
  "use_case": "Brief description",
  "query": "Full CQL query text",
  "key_features": ["Notable features"],
  "related_examples": ["Related query IDs"],
  "tags": ["Searchable tags"]
}
```

---

## File Structure

```
cql_schemas/
├── examples/
│   ├── cool_query_friday/
│   │   ├── 2021-10-29-cool-query-friday-*.json (5 files)
│   │   └── ...
│   ├── mitre_attack/
│   │   ├── process-discovery.json (25 files)
│   │   └── ...
│   ├── helpful_queries/
│   │   ├── rdp-login-world-map.json (93 files)
│   │   └── ...
│   └── metadata/
│       └── examples_index.json (Master index)
└── CATALOG_SUMMARY.md (This file)
```

---

## Usage Examples

### Finding Queries by Difficulty

**Expert-level queries (12 total):**
- Combine ProcessRollup2 and NetworkConnectIP4 Events
- Combine ProcessRollup2 and DnsRequest Events
- Merge Parent_Child PR2 with Join
- And 9 more...

### Finding Queries by Event Type

**ProcessRollup2 queries (40 total):**
- Most common event type
- Used for process analysis, correlation, and hunting
- Available across all difficulty levels

### Finding Queries by Function

**Queries using `join` (13 total):**
- Advanced correlation techniques
- Multi-event analysis
- Process and network correlation

---

## Master Index

The master index file (`cql_schemas/metadata/examples_index.json`) contains:

- **Metadata:** Total count, version, last updated
- **Summary Statistics:** Breakdowns by category, difficulty, type, platform
- **Top Statistics:** Top event types, functions, and tags
- **MITRE ATT&CK Coverage:** Full tactics and techniques mapping
- **Query List:** All 123 queries with key metadata

### Accessing the Index

```bash
# View summary statistics
jq '.summary' cql_schemas/metadata/examples_index.json

# Find all expert-level queries
jq '.queries[] | select(.difficulty == "expert")' cql_schemas/metadata/examples_index.json

# Find all detection queries
jq '.queries[] | select(.query_type == "detection")' cql_schemas/metadata/examples_index.json

# Find queries using ProcessRollup2
jq '.queries[] | select(.event_types[] == "ProcessRollup2")' cql_schemas/metadata/examples_index.json

# View MITRE ATT&CK coverage
jq '.mitre_attack' cql_schemas/metadata/examples_index.json
```

---

## Key Insights

### Query Complexity Distribution

- **Beginner-friendly (Basic + Intermediate):** 98 queries (79.7%)
- **Advanced users (Advanced + Expert):** 25 queries (20.3%)
- Most queries are accessible to intermediate CQL users

### Primary Use Cases

1. **Data Analysis (39 queries):** Most common use case
2. **Utility Functions (33 queries):** Helper queries for common tasks
3. **Threat Hunting (26 queries):** Proactive security investigations
4. **Detection (13 queries):** Specific threat identification

### Event Coverage

- Queries utilize **30+ different event types**
- **ProcessRollup2** is overwhelmingly the most used (40 queries)
- Good coverage across process, network, user, and system events

### Function Utilization

- **63 queries use `groupBy()`** - Essential for aggregation
- **Advanced correlation functions** (`join`, `selfJoinFilter`, `correlate`) used in 20+ queries
- **Visualization functions** (`worldMap`, `sankey`) provide geographic and flow analysis

---

## Next Steps & Recommendations

### For Users

1. **Start with Basic queries** to learn CQL fundamentals
2. **Progress to Intermediate** for practical use cases
3. **Study Expert queries** for advanced correlation techniques
4. **Explore MITRE ATT&CK queries** for security detections

### For Catalog Enhancement

1. **Add cross-references** between related queries
2. **Create learning paths** from basic to expert
3. **Add performance metrics** (query execution time, resource usage)
4. **Expand MITRE coverage** to additional tactics beyond Discovery

---

## File Locations

- **Individual Query Schemas:** `/Users/michaeloneil/Github/cql_claude/cql_schemas/examples/`
- **Master Index:** `/Users/michaeloneil/Github/cql_claude/cql_schemas/metadata/examples_index.json`
- **Catalog Script:** `/Users/michaeloneil/Github/cql_claude/catalog_cql_queries.py`
- **This Summary:** `/Users/michaeloneil/Github/cql_claude/cql_schemas/CATALOG_SUMMARY.md`

---

## Catalog Script Features

The Python cataloging script (`catalog_cql_queries.py`) provides:

- Automatic extraction of CQL queries from markdown files
- Event type detection via regex pattern matching
- Function and operator identification
- MITRE ATT&CK metadata parsing from directory structure
- Difficulty assessment based on query complexity
- Query type classification
- Platform detection
- Automatic tag generation
- Comprehensive statistics and reporting

To re-run the catalog:

```bash
python3 catalog_cql_queries.py
```

---

**End of Summary**
