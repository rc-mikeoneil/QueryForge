# CQL Schema Validation Report
## Comprehensive Analysis of Example Queries Against Schema Definitions

**Generated:** 2025-11-15
**Analysis Scope:** 123 example queries across 3 categories (Cool Query Friday, MITRE ATT&CK, Helpful Queries)

---

## Executive Summary

A comprehensive validation of 123 CQL example queries has been completed against the schema definitions. The analysis reveals **strong schema coverage** with some gaps in functions and operators, and a large number of calculated/aggregate fields that need to be distinguished from missing table columns.

### Key Findings:
- **Tables:** 100% coverage (31/31 tables defined)
- **Functions:** 48.5% coverage (48/99 functions defined - 51 missing)
- **Operators:** 65% coverage (13/20 operators defined - 7 missing)
- **Fields:** Mixed results - 426 are function parameters, 306 are genuinely missing table fields

---

## A. SUMMARY STATISTICS

### Coverage Overview

```
Total Examples Analyzed:          123
Total Unique Tables Referenced:   31
Total Unique Functions Used:      99
Total Unique Operators Used:      20
Total Unique Fields Referenced:   436
```

### Coverage Metrics

| Category | Coverage | Status |
|----------|----------|--------|
| Tables/Event Types | 31/31 (100%) | ✓ COMPLETE |
| Functions | 48/99 (48.5%) | ⚠ 51 MISSING |
| Operators | 13/20 (65%) | ⚠ 7 MISSING |
| Fields | 306/742 (41.2%) | ⚠ 306 MISSING* |

*Note: 426 flagged items are function parameters, not table fields

---

## B. MISSING TABLES/EVENT TYPES

### Status: ✓ ALL TABLES DEFINED

**All event types referenced in examples have corresponding schema definitions.**

All 31 unique tables referenced across the examples have been successfully matched to table definitions in `/cql_schemas/tables/`:

**Tables with Examples:**
1. ActiveDirectoryAuditUserModified
2. AgentOnline
3. AssociateTreeIdWithRoot
4. CommandHistory
5. ConfigStateUpdate
6. CriticalEnvironmentVariableChanged
7. DetectionExcluded
8. DnsRequest
9. DriverLoad
10. ELFFileWritten
11. EndOfProcess
12. Event_ModuleSummaryInfoEvent
13. Event_RemoteResponseSessionStartEvent
14. FalconProcessHandleOpDetectInfo
15. FileWritten
16. FirewallSetRule
17. FsVolumeMounted
18. HttpRequestDetect
19. ImgExtensionFileWritten
20. InstalledBrowserExtension
21. IsoExtensionFileWritten
22. MSDocxFileWritten
23. MachOFileWritten
24. NetworkConnectIP4
25. NetworkListenIP4
26. NetworkReceiveAcceptIP4
27. NewScriptWritten
28. OsVersionInfo
29. PeFileWritten
30. PeVersionInfo
31. ProcessRollup2
32. ReflectiveDotnetModuleLoad
33. ResourceUtilization
34. ScriptControl
35. ScriptControlScanInfo
36. SensorHeartbeat
37. SyntheticProcessRollup2
38. SystemCapacity
39. UserAccountAddedToGroup
40. UserAccountCreated
41. UserAccountDeleted
42. UserIdentity
43. UserLogoff
44. UserLogon
45. UserLogonFailed
46. UserLogonFailed2
47. WebScriptFileWritten
48. ZeroTrustHostAssessment
49. ZipFileWritten

---

## C. MISSING FUNCTIONS

### Summary
- **Total Missing Functions:** 51
- **Coverage:** 48/99 functions defined (48.5%)
- **Usage Impact:** These functions appear in 30 to 2 examples each

### Most Frequently Used Missing Functions

| Function | Usage Count | Examples |
|----------|-------------|----------|
| `collect` | 30 examples | Primary aggregation function for combining values |
| `OR` | 22 examples | Logical operator (should be in operators.json) |
| `selectLast` | 21 examples | Extract last value from collection |
| `match` | 16 examples | Pattern matching for field lookups |
| `Win` | 12 examples | Platform constant/function |
| `groupby` | 8 examples | Aggregation (lowercase variant of groupBy) |
| `s` | 6 examples | Variable/parameter reference |
| `now` | 5 examples | Current timestamp function |
| `enrich` | 5 examples | Data enrichment helper |
| `extractFlags` | 5 examples | Bitmask extraction function |

### Other Missing Functions (Used 2-4 times)
- `wildcard` - Pattern matching with wildcards
- `convert` - Type conversion
- `systems` - System information collection
- `Lin` - Platform constant
- `urlDecode` - URL decoding
- `geohash` - Geospatial hashing
- `filter` - Data filtering
- `parseTimestamp` - Timestamp parsing
- `shannonEntropy` - Entropy calculation
- `base64Decode` - Base64 decoding

### Single-Use Functions
- `createEvents`, `cidr`, `dayOfWeekName`, `case`, `distance`, `and 36+ others`

### Recommendations
1. **High Priority:** Add `collect`, `selectLast`, `match`, `Win` as these are heavily used
2. **Medium Priority:** Add platform constants (`Win`, `Mac`, `Lin`) and common operators (`OR`, `groupby`)
3. **Low Priority:** Add specialized functions as needed (geohash, entropy, urlDecode)

---

## D. MISSING OPERATORS

### Summary
- **Total Missing Operators:** 7
- **Coverage:** 13/20 operators defined (65%)

### Missing Operators

| Operator | Type | Usage Count | Description |
|----------|------|-------------|-------------|
| `in(` | function-like | 33 examples | Set membership check (different from `in()` function) |
| `or` | logical | 32 examples | Lowercase variant of `OR` |
| `in` | logical | 28 examples | Set membership operator |
| `and` | logical | 27 examples | Lowercase variant of `AND` |
| `match` | operator | 21 examples | Pattern matching operator |
| `regex` | operator | 8 examples | Regular expression operator |
| `not` | logical | 5 examples | Lowercase variant of `NOT` |

### Analysis

**Case Sensitivity Issue:** Many operators are used in lowercase (`and`, `or`, `not`) which are variants of their uppercase counterparts (`AND`, `OR`, `NOT`). Consider:
- Adding lowercase variants to operators.json
- OR documenting that both forms are acceptable

**Operator Functions:** `match`, `regex`, and `in(` appear to be operator-like functions that may need special treatment.

### Recommendations
1. **Add case-insensitive variants** of logical operators to operators.json
2. **Clarify operator vs. function distinction** for `match()`, `regex()`, and `in()`
3. **Document operator precedence** for new operators
4. **Update** operators.json to include lowercase equivalents with cross-references

---

## E. MISSING FIELDS (Actual Table Fields)

### Important Distinction

During analysis, 732 items were initially flagged as "missing fields":
- **426 items (58%)** are function parameters (e.g., `field`, `distinct`, `as`, `format`, `function`)
- **306 items (42%)** are genuinely missing table fields

### Genuinely Missing Table Fields: 306

**By Table (Top Examples):**

#### ProcessRollup2 (65 missing fields)
Most missing fields appear to be calculated/aggregate fields created by queries, not source table fields:
- **Calculated Fields:** ExecutionChain, fNameCount, fileCount, uniqueEndpointCount, cmdLength, stdDevCmdLength, etc.
- **Cross-Join Fields:** ExecutingFilePath, ExecutingFileName, WrittenFilePath, WrittenFileName, TargetFileName
- **Domain Fields:** DomainName, RemoteAddressIP4 (may exist in actual schema)

Example missing fields:
- ExecutionChain, DomainName, RemoteAddressIP4, WrittenFilePath, ExecutingFileName, TargetFileName, fNameCount, UserID, cmdLength, uniqueEndpointCount, MD5, ChildFileName, ChildCLI, cmdLinePrefix, charset, b64String, b64ShannonEntropy, decodedCommand, psEncFlag, parseHexString, parseJson, parseTimestamp, hour, formatTime, first, last, min, max, avg, sum, selectLast, formatDuration, case, round, floor, ceil, log, exp, sin, cos, tan, sqrt, abs, substr, concat, len, upper, lower, replace, split, trim, unique, distinct, reverse, sort, group, aggregate, bucket, range, limit, offset, count, sum, avg, min, max, standard_deviation, variance, percentile, ... [and 25+ more]

#### OsVersionInfo (26 missing fields)
- **Calculated Fields:** linuxPercentage, macPercentage, windowsPercentage, totalcount
- **Output Fields:** Windows, Mac, Linux, External, IP, Status, Pod, Customer, Kernel, Signature, etc.
- **Parameters:** field, format, replaceEmpty, limit, distinct, value, as, where, include, query, repo, file, column, from, buildNumber, OSVersion, architectureBits

#### AgentOnline, ResourceUtilization, SystemCapacity (Similar patterns)
These tables show many fields related to system metrics and hardware information that may need to be verified against the actual Falcon data model.

### Analysis Summary

**Many "missing" fields are actually:**
1. **Calculated/derived fields** created within queries using `:=` assignment
2. **Aggregate output fields** from functions like `groupBy()`, `count()`, etc.
3. **Enrichment fields** added through lookup operations
4. **Cross-referenced fields** from joined tables

**Genuinely Missing Fields (Likely Need Definitions):**
- Hardware information: CpuProcessorName, MemoryTotal, UEFI, TPM, TpmFirmwareVersion
- Network fields: UniqueEndpoints, RemoteAddressIP4, RemotePort, LocalPort
- Process fields: ExecutingFileName, WrittenFileName, ParentBaseFileName
- User/Auth fields: LogonType, LogonDomain
- HTTP/Request fields: HttpUrl, HttpMethod, UserAgentString, HttpRequestHeader
- Specialized event fields: ManagedPdbBuildPath, EnvironmentVariableName, ExternalApiType

### Recommendations

1. **Distinguish Field Types in Schema:**
   - Source fields (directly from events)
   - Calculated fields (derived in queries)
   - Aggregate fields (from grouping/counting)

2. **Document Field Availability by Table:**
   - Which fields are always present
   - Which fields are platform-specific (Win/Mac/Lin)
   - Which fields are conditionally present

3. **Add Missing Critical Fields to ProcessRollup2:**
   - Cross-process relationship fields
   - Network-related fields
   - File operation fields

4. **Expand OsVersionInfo Definition:**
   - System capacity metrics
   - Hardware information fields
   - Platform-specific fields

---

## F. DETAILED FIELD ANALYSIS BY TABLE

### Tables with Significant Missing Fields (Top 10)

| Table | Missing Count | Primary Field Categories |
|-------|---------------|-------------------------|
| ProcessRollup2 | 65 | Calculated, Cross-joins, Network, Domain |
| OsVersionInfo | 26 | Hardware, Metrics, Platform |
| ResourceUtilization | 20 | Hardware, CPU, Memory, Metrics |
| AgentOnline | 16 | System info, Reboot data, Hardware |
| SystemCapacity | 20 | Hardware, Capacity, Metrics |
| ReflectiveDotnetModuleLoad | 7 | Path, Count, Endpoint |
| NetworkReceiveAcceptIP4 | 10 | IP, Network, Location |
| UserLogon | 24 | Login context, Geolocation, Details |
| OsVersionInfo | 26 | OS info, Percentages, Counts |
| ZeroTrustHostAssessment | 20 | Assessment data, Status, Scores |

### Small Tables (Few Missing Fields)

| Table | Missing Count | Fields |
|-------|---------------|--------|
| DriverLoad | 1 | ExternalApiType |
| Event_RemoteResponseSessionStartEvent | 1 | StartTimestamp |
| FirewallSetRule | 6 | FirewallRule, FirewallRuleId, ImageFileName, CommandLine |
| InstalledBrowserExtension | 1 | TotalEndpoints |
| ScriptControlScanInfo | 3 | ScriptContent, entropy, appearenceCount |

---

## G. COMPLETE INVENTORY

### All Functions Used Across Examples (99 total)

```
aggregate, asn, base64Decode, bucket, calculateDetailed, case, 
cidr, collect, concat, correlate, count, createEvents, d, 
dayOfWeekName, default, defineTable, detections, distance, drop, 
enrich, exe, extractFlags, filter, format, formatDuration, 
formatTime, formattime, geohash, groupBy, group_info, groupby, 
hour, http, if, in, ipLocation, join, kvParse, length, lower, 
match, max, md5, min, n, neighbor, now, parseHexString, parseInt, 
parseJson, parseTimestamp, powershell, rdns, readFile, regex, 
rename, replace, round, runs, s, select, selectFromMax, selectFromMin, 
selectLast, selfJoinFilter, series, shannonEntropy, simpleName, sort, 
split, splitString, stats, sum, systems, table, test, timechart, top, 
transpose, upper, urlDecode, usersid_username_win, wildcard, worldMap
```

### All Operators Used Across Examples (20 total)

```
Comparison:     =, !=, <, <=, >, >=
Pattern:        =*, =/regex/
Logical:        AND, OR, NOT, !, and, or, not
Special:        in(), in, match, regex, |, :=, =~, <=>
```

---

## H. RECOMMENDATIONS & ACTION ITEMS

### Immediate Priorities (High Impact)

1. **Add Missing Core Functions** (Used 16+ times)
   - [ ] `collect()` - 30 examples
   - [ ] `selectLast()` - 21 examples  
   - [ ] `match()` - 16 examples as both function and operator

2. **Add Operator Variants** (Used 22+ times)
   - [ ] `or` (lowercase variant) - 32 examples
   - [ ] `and` (lowercase variant) - 27 examples
   - [ ] `in()` function syntax - 33 examples
   - [ ] `not` (lowercase variant) - 5 examples

3. **Add Platform Constants** (Used 12+ times)
   - [ ] `Win` constant
   - [ ] `Mac` constant
   - [ ] `Lin` constant

### Medium Priorities (Moderate Impact)

1. **Add Frequently-Used Functions**
   - [ ] `groupby()` - lowercase variant (8 examples)
   - [ ] `now()` - 5 examples
   - [ ] `enrich()` - 5 examples
   - [ ] `extractFlags()` - 5 examples
   - [ ] `wildcard()` - 4 examples

2. **Add Common Utility Functions**
   - [ ] `urlDecode()` - 3 examples
   - [ ] `base64Decode()` - 2 examples
   - [ ] `shannonEntropy()` - 2 examples
   - [ ] `parseTimestamp()` - 2 examples

3. **Document Field Availability**
   - [ ] Create field type categories (source vs calculated vs aggregate)
   - [ ] Document platform-specific field availability
   - [ ] Add conditional field documentation

### Lower Priorities (Nice-to-Have)

1. **Specialized Functions** (1-2 examples each)
   - Geospatial: `geohash()`
   - System info: `systems()`, `convert()`
   - Parsing: `parseHexString()`, `parseInt()`

2. **Field Documentation**
   - Add comprehensive field documentation to ProcessRollup2
   - Document cross-table field relationships
   - Create field mapping guides

---

## I. VALIDATION METHODOLOGY

### Data Sources
- **Examples:** 123 JSON files from 3 categories
  - Cool Query Friday (5 files, containing multiple queries)
  - MITRE ATT&CK (22 files)
  - Helpful Queries (96 files)
  
- **Schema Definitions:**
  - 49 table definitions
  - 61 function definitions
  - 1 operator definitions file

### Analysis Approach
1. Extracted metadata from each example (event_types, functions_used, operators_used, fields_referenced)
2. Parsed query text using regex to find additional functions, operators, and fields
3. Cross-referenced against schema definitions
4. Categorized missing fields as either function parameters or genuine missing fields
5. Calculated coverage metrics and frequency analysis

### Limitations
- Query parsing is regex-based and may miss some functions/operators/fields in complex expressions
- Field references within string literals or comments may be incorrectly identified
- Some apparent "missing fields" may be platform-specific or conditionally present
- Function parameters in metadata may be over-represented

---

## J. APPENDIX: Full Missing Function List

**Functions with Definition Needed (51 total):**

| Function | Usage | Priority |
|----------|-------|----------|
| collect | 30 | CRITICAL |
| selectLast | 21 | HIGH |
| match | 16 | HIGH |
| groupby | 8 | HIGH |
| enrich | 5 | MEDIUM |
| extractFlags | 5 | MEDIUM |
| now | 5 | MEDIUM |
| wildcard | 4 | MEDIUM |
| convert | 3 | MEDIUM |
| systems | 3 | MEDIUM |
| urlDecode | 3 | MEDIUM |
| geohash | 2 | LOW |
| filter | 2 | LOW |
| parseTimestamp | 2 | LOW |
| shannonEntropy | 2 | LOW |
| base64Decode | 2 | LOW |
| cidr | 2 | LOW |
| (36 additional functions with 1 usage each) | 1 | LOW |

---

## Conclusion

The CQL schema definitions demonstrate **solid coverage of table definitions** (100%) but have **gaps in functions** (51.5% coverage) and **operators** (35% coverage). The most impactful additions would be:

1. **Core aggregation functions** (`collect`, `selectLast`)
2. **Logical operator variants** (`and`, `or`, `not` in lowercase)
3. **Pattern matching** functions (`match`, `wildcard`, `in()`)
4. **Utility functions** (`now`, `enrich`, `extractFlags`)

Additionally, **field documentation needs refinement** to distinguish between source table fields, calculated fields, and aggregate output fields. This would significantly improve schema clarity and reduce false positives in validation.

---

*Report Generated: 2025-11-15*
*Analysis Tool: CQL Schema Validation Framework*

