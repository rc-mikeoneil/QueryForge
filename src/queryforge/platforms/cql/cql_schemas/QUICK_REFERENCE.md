# CQL Query Catalog - Quick Reference Guide

## Finding Queries

### By Difficulty Level

```bash
# All expert-level queries
jq '.queries[] | select(.difficulty == "expert") | {id, title}' cql_schemas/metadata/examples_index.json

# All basic queries for learning
jq '.queries[] | select(.difficulty == "basic") | {id, title}' cql_schemas/metadata/examples_index.json
```

### By Event Type

```bash
# All ProcessRollup2 queries
jq '.queries[] | select(.event_types[] == "ProcessRollup2") | {id, title, difficulty}' cql_schemas/metadata/examples_index.json

# All UserLogon queries
jq '.queries[] | select(.event_types[] == "UserLogon") | {id, title, difficulty}' cql_schemas/metadata/examples_index.json

# All NetworkConnect queries
jq '.queries[] | select(.event_types[] == "NetworkConnectIP4") | {id, title, difficulty}' cql_schemas/metadata/examples_index.json
```

### By Query Type

```bash
# All detection queries
jq '.queries[] | select(.query_type == "detection") | {id, title}' cql_schemas/metadata/examples_index.json

# All hunting queries
jq '.queries[] | select(.query_type == "hunting") | {id, title}' cql_schemas/metadata/examples_index.json

# All visualization queries
jq '.queries[] | select(.query_type == "visualization") | {id, title}' cql_schemas/metadata/examples_index.json
```

### By Platform

```bash
# All Windows queries
jq '.queries[] | select(.platforms[] == "Win") | {id, title}' cql_schemas/metadata/examples_index.json

# All Linux queries
jq '.queries[] | select(.platforms[] == "Lin") | {id, title}' cql_schemas/metadata/examples_index.json

# Cross-platform queries
jq '.queries[] | select(.platforms[] == "Cross-platform") | {id, title}' cql_schemas/metadata/examples_index.json
```

### By MITRE ATT&CK

```bash
# All MITRE ATT&CK queries
jq '.queries[] | select(.category == "mitre_attack") | {id, title, mitre_technique: .mitre_technique}' cql_schemas/metadata/examples_index.json

# Queries for specific technique
jq '.queries[] | select(.mitre_technique == "T1057") | {id, title}' cql_schemas/metadata/examples_index.json
```

### By Function

```bash
# All queries using join
jq '.queries[] | select(.functions_used[] == "join")' cql_schemas/metadata/examples_index.json | jq -s 'length'

# All queries using correlate
jq '.queries[] | select(.functions_used[] == "correlate") | {id, title, difficulty}' cql_schemas/metadata/examples_index.json

# All queries using worldMap (visualization)
jq '.queries[] | select(.functions_used[] == "worldMap") | {id, title}' cql_schemas/metadata/examples_index.json
```

## Statistics & Analysis

### Overall Statistics

```bash
# Total query count
jq '.metadata.total_queries' cql_schemas/metadata/examples_index.json

# Breakdown by category
jq '.summary.by_category' cql_schemas/metadata/examples_index.json

# Breakdown by difficulty
jq '.summary.by_difficulty' cql_schemas/metadata/examples_index.json

# Breakdown by query type
jq '.summary.by_query_type' cql_schemas/metadata/examples_index.json
```

### Top Statistics

```bash
# Top 10 event types
jq '.top_statistics.top_event_types' cql_schemas/metadata/examples_index.json

# Top 10 functions
jq '.top_statistics.top_functions' cql_schemas/metadata/examples_index.json

# Top 20 tags
jq '.top_statistics.top_tags' cql_schemas/metadata/examples_index.json
```

### MITRE ATT&CK Coverage

```bash
# All tactics covered
jq '.mitre_attack.tactics' cql_schemas/metadata/examples_index.json

# All techniques covered
jq '.mitre_attack.techniques' cql_schemas/metadata/examples_index.json

# Total technique coverage
jq '.mitre_attack.total_coverage' cql_schemas/metadata/examples_index.json
```

## Viewing Individual Queries

### Direct File Access

```bash
# View a specific query
cat cql_schemas/examples/helpful_queries/rdp-login-world-map.json | jq

# View query content only
jq '.query' cql_schemas/examples/helpful_queries/rdp-login-world-map.json

# View query metadata
jq 'del(.query)' cql_schemas/examples/helpful_queries/rdp-login-world-map.json
```

### By Category

```bash
# List all Cool Query Friday examples
ls -1 cql_schemas/examples/cool_query_friday/*.json

# List all MITRE ATT&CK examples
ls -1 cql_schemas/examples/mitre_attack/*.json

# List all Helpful Queries
ls -1 cql_schemas/examples/helpful_queries/*.json
```

## Common Use Cases

### Learning CQL

**Step 1: Start with basic queries**
```bash
jq '.queries[] | select(.difficulty == "basic") | {id, title, event_types, functions_used}' cql_schemas/metadata/examples_index.json | less
```

**Step 2: Progress to intermediate**
```bash
jq '.queries[] | select(.difficulty == "intermediate" and .query_type == "analysis") | {id, title}' cql_schemas/metadata/examples_index.json
```

**Step 3: Study advanced correlation**
```bash
jq '.queries[] | select(.correlation_patterns | length > 0) | {id, title, correlation_patterns, difficulty}' cql_schemas/metadata/examples_index.json
```

### Finding Detection Examples

```bash
# All detection queries
jq '.queries[] | select(.query_type == "detection") | {id, title, event_types, platforms}' cql_schemas/metadata/examples_index.json

# Detection queries by platform
jq '.queries[] | select(.query_type == "detection" and .platforms[] == "Win") | {id, title}' cql_schemas/metadata/examples_index.json
```

### Finding Process Analysis Queries

```bash
# All ProcessRollup2 queries
jq '.queries[] | select(.event_types[] == "ProcessRollup2") | {id, title, difficulty, query_type}' cql_schemas/metadata/examples_index.json

# Advanced process correlation
jq '.queries[] | select(.event_types[] == "ProcessRollup2" and .difficulty == "expert") | {id, title, key_features}' cql_schemas/metadata/examples_index.json
```

### Finding Network Analysis Queries

```bash
# Network-related queries
jq '.queries[] | select(.subcategory == "network") | {id, title, event_types}' cql_schemas/metadata/examples_index.json

# NetworkConnect queries
jq '.queries[] | select(.event_types[] == "NetworkConnectIP4") | {id, title}' cql_schemas/metadata/examples_index.json

# DNS queries
jq '.queries[] | select(.event_types[] == "DnsRequest") | {id, title}' cql_schemas/metadata/examples_index.json
```

### Finding User/Authentication Queries

```bash
# All UserLogon queries
jq '.queries[] | select(.event_types[] == "UserLogon") | {id, title, difficulty, platforms}' cql_schemas/metadata/examples_index.json

# RDP-specific queries
jq '.queries[] | select(.tags[] == "rdp") | {id, title}' cql_schemas/metadata/examples_index.json
```

## Quick Access to Specific Categories

### Cool Query Friday Examples (5 total)

1. **2021-10-29** - CPU, RAM, Disk, Firmware, TPM 2.0, and Windows 11
   - File: `cql_schemas/examples/cool_query_friday/2021-10-29-cool-query-friday-cpu-ram-disk-firmware-tpm-20-and-windows-11.json`

2. **2023-06-14** - Watching the Watchers - Profiling Falcon Console Logins via Geohashing
   - File: `cql_schemas/examples/cool_query_friday/2023-06-14-cool-query-friday-watching-the-watchers-profiling-falcon-console-logins-via-geohashing.json`

3. **2023-09-08** - Reflective .Net Module Loads and Program Database (PDB) File Paths
   - File: `cql_schemas/examples/cool_query_friday/2023-09-08-cool-query-friday-reflective-net-module-loads-and-program-database-pdb-file-paths.json`

4. **2023-09-20** - Up-leveling Teams With Text-box Driven Queries
   - File: `cql_schemas/examples/cool_query_friday/2023-09-20-cool-query-friday-up-leveling-teams-with-text-box-driven-queries.json`

5. **2024-03-01** - CQF Live Supporting Queries
   - File: `cql_schemas/examples/cool_query_friday/2024-03-01-cqf-live-supporting-queries.json`

### Top Helpful Queries

1. **RDP Login World Map** (Visualization)
   - `cql_schemas/examples/helpful_queries/rdp-login-world-map.json`

2. **Impossible Time To Travel (UserLogon)** (Hunting)
   - `cql_schemas/examples/helpful_queries/impossible-time-to-travel-userlogon.json`

3. **Combine ProcessRollup2 and NetworkConnectIP4 Events** (Expert)
   - `cql_schemas/examples/helpful_queries/combine-processrollup2-and-networkconnectip4-events.json`

4. **Frequency Analysis via Program Clustering** (Analysis)
   - `cql_schemas/examples/helpful_queries/frequency-analysis-via-program-clustering.json`

5. **Hunt PBD File Paths in Reflective .net Module Loads** (Hunting)
   - `cql_schemas/examples/helpful_queries/hunt-pbd-file-paths-in-reflective-net-module-loads.json`

### MITRE ATT&CK Techniques

**Account Discovery (T1087)** - 4 queries:
- `account-discovery-local-account.json`
- `account-discovery-domain-account.json`
- `account-discovery-email-account.json`
- `account-discovery-cloud-account.json`

**Permission Groups Discovery (T1069)** - 3 queries:
- `permission-groups-discovery-local-groups.json`
- `permission-groups-discovery-domain-groups.json`
- `permission-groups-discovery-cloud-groups.json`

**Process Discovery (T1057)** - 1 query:
- `process-discovery.json`

## Advanced Searches

### Multi-criteria Search

```bash
# Expert-level detection queries for Windows
jq '.queries[] | select(.difficulty == "expert" and .query_type == "detection" and .platforms[] == "Win") | {id, title, event_types}' cql_schemas/metadata/examples_index.json

# Intermediate hunting queries with joins
jq '.queries[] | select(.difficulty == "intermediate" and .query_type == "hunting" and (.functions_used[] == "join")) | {id, title}' cql_schemas/metadata/examples_index.json

# Queries using both ProcessRollup2 and NetworkConnect
jq '.queries[] | select((.event_types[] == "ProcessRollup2") and (.event_types[] == "NetworkConnectIP4")) | {id, title, difficulty}' cql_schemas/metadata/examples_index.json
```

### Count Queries by Criteria

```bash
# Count queries by difficulty
jq '[.queries[] | .difficulty] | group_by(.) | map({difficulty: .[0], count: length})' cql_schemas/metadata/examples_index.json

# Count queries by event type
jq '[.queries[] | .event_types[]] | group_by(.) | map({event_type: .[0], count: length}) | sort_by(-.count)' cql_schemas/metadata/examples_index.json

# Count queries using specific function
jq '[.queries[] | select(.functions_used[] == "join")] | length' cql_schemas/metadata/examples_index.json
```

### Full-Text Search in Queries

```bash
# Search for queries containing specific text in title
jq '.queries[] | select(.title | test("RDP"; "i")) | {id, title}' cql_schemas/metadata/examples_index.json

# Search for queries using specific fields
jq '.queries[] | select(.fields_referenced[] == "RemoteAddressIP4") | {id, title}' cql_schemas/metadata/examples_index.json

# Search by tag
jq '.queries[] | select(.tags[] == "network") | {id, title}' cql_schemas/metadata/examples_index.json
```

## Examples for Specific Tasks

### Task: Learn how to correlate events

```bash
# Find all queries with correlation patterns
jq '.queries[] | select(.correlation_patterns | length > 0) | {id, title, correlation_patterns, difficulty, file}' cql_schemas/metadata/examples_index.json
```

### Task: Build a detection for suspicious processes

```bash
# Find process detection queries
jq '.queries[] | select(.query_type == "detection" and (.event_types[] == "ProcessRollup2")) | {id, title, difficulty, file}' cql_schemas/metadata/examples_index.json
```

### Task: Visualize network activity

```bash
# Find visualization queries with network focus
jq '.queries[] | select(.query_type == "visualization" and (.subcategory == "network" or .tags[] == "network")) | {id, title, functions_used, file}' cql_schemas/metadata/examples_index.json
```

### Task: Monitor user authentication

```bash
# Find UserLogon-related queries
jq '.queries[] | select(.event_types[] == "UserLogon") | {id, title, query_type, difficulty, file}' cql_schemas/metadata/examples_index.json
```

## Python Script Usage

### Re-run the Catalog

```bash
python3 catalog_cql_queries.py
```

### Modify for Custom Analysis

The script at `/Users/michaeloneil/Github/cql_claude/catalog_cql_queries.py` can be modified to:
- Add new metadata fields
- Change difficulty assessment criteria
- Add custom categorization logic
- Extract additional patterns
- Generate different output formats

## Tips & Best Practices

1. **Start Simple**: Begin with basic queries to understand CQL fundamentals
2. **Study Patterns**: Look at how expert queries use correlation functions
3. **Platform-Specific**: Filter by your target platform (Win/Mac/Lin)
4. **Event Types**: Identify which event types are relevant to your use case
5. **Build on Examples**: Use existing queries as templates for new ones
6. **MITRE Mapping**: Use MITRE ATT&CK queries for security detections
7. **Tags**: Use tags for quick discovery of related queries

## Quick Stats Commands

```bash
# Total queries
jq '.metadata.total_queries' cql_schemas/metadata/examples_index.json

# Categories breakdown
jq '.summary' cql_schemas/metadata/examples_index.json

# Most common event type
jq '.top_statistics.top_event_types[0]' cql_schemas/metadata/examples_index.json

# Most common function
jq '.top_statistics.top_functions[0]' cql_schemas/metadata/examples_index.json

# MITRE coverage
jq '.mitre_attack.total_coverage' cql_schemas/metadata/examples_index.json
```

---

**For more details, see:** `cql_schemas/CATALOG_SUMMARY.md`
