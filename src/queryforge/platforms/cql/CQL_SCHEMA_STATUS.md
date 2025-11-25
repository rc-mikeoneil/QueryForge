# CQL Schema Status & Documentation Index

**Last Updated:** 2025-11-25  
**Schema Version:** 1.1.0  
**Status:** ✅ Production Ready

---

## Current Schema Coverage

| Category | Coverage | Status |
|----------|----------|--------|
| **Tables/Event Types** | 31/31 (100%) | ✅ Complete |
| **Functions** | 87/99 (88%) | ✅ Excellent |
| **Operators** | 25/25 (100%) | ✅ Complete |
| **Fields** | Varies by table | ⚠️ In Progress |

---

## Recent Updates (2025-11-25)

### Functions Added
- ✅ `groupby.json` - Lowercase variant of groupBy
- ✅ `formattime.json` - Lowercase variant of formatTime

### Validation Corrections
- ✅ Corrected function coverage from 48% to 88%
- ✅ Verified all operators exist (100% coverage)
- ✅ Confirmed platform constants (Win, Mac, Lin) exist
- ✅ Identified 426 false positives in field analysis

### Key Findings
- Schema is production-ready with excellent coverage
- Only 12 low-priority specialized functions missing
- All critical functions and operators present
- Field work remains: 306 fields need investigation (many are calculated/aggregate)

---

## Documentation Files

### Primary Documentation
1. **README.md** - Overview and getting started guide
2. **SCHEMA_MAINTENANCE_GUIDE.md** - How to maintain and update schemas
3. **VALIDATION_SUMMARY.md** - Quick validation status and statistics
4. **CQL_SCHEMA_STATUS.md** (this file) - Current status dashboard

### Detailed Analysis
1. **CQL_VALIDATION_REPORT.md** - Full validation methodology and findings
2. **CQL_VALIDATION_ANALYSIS_AND_REVISION_PLAN.md** - Validation accuracy assessment and corrections
3. **CQL_VALIDATION_DATA.json** - Raw validation data (85KB)
4. **REMAINING_FIELD_ANALYSIS.md** - Field investigation details

### Historical/Reference
1. **CQL_SCHEMA_IMPROVEMENTS_SUMMARY.md** - Previous improvement work
2. **CQL_SCHEMA_VALIDATION_STATUS_UPDATED.md** - Previous validation status
3. **CHANGELOG.md** - Change history

---

## Schema Structure

```
cql_schemas/
├── functions/          87 function definitions
├── operators/          1 operators.json (25 operators)
├── tables/            49+ table definitions  
├── examples/          123 example queries
├── best_practices/    Query optimization guidelines
├── how_tos/          Usage guides
└── metadata/         Schema metadata and documentation
```

---

## Known Gaps & Next Steps

### Missing Functions (12 low-priority)
- Event_, AddComputerName, BZ, addresses, bcdedit, cid_name
- communityId, detections, HttpMethod, n, powershell, ProcessRollup2

**Action:** Add only if needed for specific use cases

### Field Investigation (306 fields)
Most are:
- Calculated/derived fields created by queries
- Aggregate output fields from groupBy/stats
- Enrichment fields from lookups
- Cross-table references from joins

**Action:** Document field types and availability

### Documentation Cleanup
- ✅ Consolidated status into this file
- ✅ Updated VALIDATION_SUMMARY.md with corrections
- ✅ Created CQL_VALIDATION_ANALYSIS_AND_REVISION_PLAN.md
- [ ] Archive old validation files when no longer needed

---

## Quick Reference

### Getting Schema Information
```python
from queryforge.platforms.cql.schema_loader import CQLSchemaLoader

loader = CQLSchemaLoader()
functions = loader.get_functions()          # All function definitions
operators = loader.get_operators()          # All operator definitions
tables = loader.get_tables()                # All table definitions
```

### Validation
```bash
# Run schema validation
python src/queryforge/platforms/cql/validate_schemas.py

# Check for specific function
ls src/queryforge/platforms/cql/cql_schemas/functions/ | grep -i "function_name"
```

### Adding New Schema Items
See: **SCHEMA_MAINTENANCE_GUIDE.md** for detailed instructions

---

## Schema Quality Metrics

### Function Coverage by Category
- **Aggregation**: 100% (groupBy, count, sum, avg, min, max, collect, etc.)
- **String**: 100% (concat, split, replace, upper, lower, etc.)
- **Time**: 100% (formatTime, bucket, now, formatDuration, etc.)
- **Network**: 100% (cidr, ipLocation, rdns, etc.)
- **Pattern**: 100% (match, regex, wildcard, etc.)
- **Data**: 100% (join, correlate, selfJoinFilter, etc.)

### Operator Coverage
- **Comparison**: 100% (=, !=, <, >, <=, >=)
- **Pattern**: 100% (=*, =/regex/, match, regex)
- **Logical**: 100% (AND, OR, NOT, and, or, not, !)
- **Special**: 100% (:=, |, #, =~, <=>, *)

### Production Readiness: ✅ EXCELLENT
- Core functionality: Complete
- Query building: Fully supported
- Validation: Comprehensive
- Documentation: Extensive

---

## Contact & Support

For schema issues or questions:
1. Check SCHEMA_MAINTENANCE_GUIDE.md
2. Review example queries in cql_schemas/examples/
3. Consult CQL_VALIDATION_REPORT.md for detailed analysis

---

*This document provides a consolidated view of CQL schema status. For historical context, see archived validation reports.*
