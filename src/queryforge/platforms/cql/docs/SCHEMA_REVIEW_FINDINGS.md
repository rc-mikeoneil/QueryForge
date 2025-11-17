# How-Tos and Best Practices Schema Review

**Date:** 2025-11-15
**Reviewer:** Claude
**Status:** Complete

## Executive Summary

The how-tos and best practices schemas have **inconsistent structure**, are **not integrated** into the main cql_schemas directory, and are **missing** from the master schema index. This review identifies these issues and provides a remediation plan.

## Findings

### 1. Schema Inconsistencies

#### Current State

**How-Tos Schema (54 files):**
```json
{
  "title": "How-To: Title Here",
  "slug": "snake_case_identifier",
  "type": "how-to",
  "product": "Falcon LogScale",
  "category": "query|integration|admin",
  "description": "Detailed description...",
  "examples": [
    {
      "name": "Example name",
      "description": "Example description",
      "language": "logscale",
      "query": "CQL query here"
    }
  ],
  "tags": ["tag1", "tag2"]
}
```

**Best Practices Schema (34 files):**
```json
{
  "title": "Best Practice Title",
  "url": "https://library.humio.com/kb/...",
  "description": "Description...",
  "example": {
    "query": "CQL query",
    "explanation": "Explanation text"
  },
  "tags": ["tag1", "tag2"]
}
```

#### Issues Identified

1. **Inconsistent field names**: `examples` (array) vs `example` (object)
2. **Missing fields in best practices**: No `slug`, `type`, `product`, `category`
3. **Extra field in best practices**: `url` field not present in how-tos
4. **Different example structures**: Array with metadata vs single object with explanation

### 2. Integration Issues

**Location:**
- How-tos: `/logscale_howtos_json/` (root level, 54 files)
- Best practices: `/logscale_best_practices_individual_json/` (root level, 34 files)

**Problems:**
- Not in `cql_schemas/` directory
- Not referenced in `cql_schemas/metadata/master_schema_index.json`
- No index files for how-tos or best practices
- No cross-references to functions or event types

### 3. Documentation Issues

**Root Level Documentation (12 files, 5419 lines total):**

| File | Lines | Status | Recommendation |
|------|-------|--------|----------------|
| `PHASE_*_COMPLETION_SUMMARY.md` | 2709 | Historical | Archive/Delete |
| `CQL_QUERY_CATALOG_COMPLETE.md` | 498 | Duplicate? | Review/Delete |
| `CQL_SCHEMA_BUILDER_PLAN.md` | 571 | Historical | Archive |
| `SCHEMA_STRUCTURE.md` | 757 | Active | Keep/Reorganize |
| `README.md` | 408 | Active | Keep |
| `VALIDATION_REPORT.md` | 91 | Active | Keep |
| `CHANGELOG.md` | 385 | Active | Keep |

**Issues:**
- 8 Phase completion summaries (historical artifacts)
- Possible duplicate content
- No clear organization

## Recommendations

### Phase 1: Schema Unification

Create a **unified schema** that accommodates both how-tos and best practices:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["title", "slug", "type", "description", "examples", "tags"],
  "properties": {
    "title": {
      "type": "string",
      "description": "Display title (How-To: prefix for how-tos, Best Practice: prefix for best practices)"
    },
    "slug": {
      "type": "string",
      "pattern": "^[a-z0-9_]+$",
      "description": "Unique identifier in snake_case"
    },
    "type": {
      "type": "string",
      "enum": ["how-to", "best-practice"],
      "description": "Content type"
    },
    "product": {
      "type": "string",
      "default": "Falcon LogScale",
      "description": "CrowdStrike product name"
    },
    "category": {
      "type": "string",
      "enum": ["query", "integration", "admin", "performance", "security", "general"],
      "description": "Primary category"
    },
    "subcategory": {
      "type": "string",
      "description": "Optional subcategory"
    },
    "description": {
      "type": "string",
      "description": "Detailed description of the how-to or best practice"
    },
    "examples": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": ["name", "description", "query"],
        "properties": {
          "name": {
            "type": "string",
            "description": "Example name"
          },
          "description": {
            "type": "string",
            "description": "What this example demonstrates"
          },
          "language": {
            "type": "string",
            "default": "logscale",
            "enum": ["logscale", "json", "bash", "javascript"],
            "description": "Code language"
          },
          "query": {
            "type": "string",
            "description": "Code or query content"
          },
          "explanation": {
            "type": "string",
            "description": "Additional explanation (optional)"
          }
        }
      }
    },
    "url": {
      "type": "string",
      "format": "uri",
      "description": "Official documentation URL (optional)"
    },
    "related_functions": {
      "type": "array",
      "items": {"type": "string"},
      "description": "List of related CQL function names"
    },
    "related_event_types": {
      "type": "array",
      "items": {"type": "string"},
      "description": "List of related event_simpleName values"
    },
    "difficulty": {
      "type": "string",
      "enum": ["beginner", "intermediate", "advanced"],
      "default": "beginner"
    },
    "tags": {
      "type": "array",
      "items": {"type": "string"},
      "minItems": 1
    }
  }
}
```

### Phase 2: Migration Plan

1. **Create directories:**
   - `cql_schemas/how_tos/`
   - `cql_schemas/best_practices/`

2. **Migrate and normalize:**
   - Convert all best practices to unified schema
   - Validate all how-tos against unified schema
   - Add missing fields (category, related_functions, etc.)

3. **Create indexes:**
   - `cql_schemas/metadata/how_tos_index.json`
   - `cql_schemas/metadata/best_practices_index.json`

4. **Update master index:**
   - Add how_tos and best_practices sections
   - Update statistics
   - Add cross-references

### Phase 3: Documentation Cleanup

**Archive historical documents:**
```
docs/
└── archive/
    ├── PHASES_1_2_COMPLETION_SUMMARY.md
    ├── PHASE_3_COMPLETION_SUMMARY.md
    ├── PHASE_5_COMPLETION_SUMMARY.md
    ├── PHASE_6_COMPLETION_SUMMARY.md
    ├── PHASE_7_COMPLETION_SUMMARY.md
    ├── PHASE_8_COMPLETION_SUMMARY.md
    ├── CQL_QUERY_CATALOG_COMPLETE.md
    └── CQL_SCHEMA_BUILDER_PLAN.md
```

**Keep at root:**
- README.md (primary documentation)
- CHANGELOG.md (version history)
- VALIDATION_REPORT.md (current validation status)

**Move to cql_schemas/:**
- SCHEMA_STRUCTURE.md → `cql_schemas/SCHEMA_STRUCTURE.md`

### Phase 4: Quality Improvements

1. **Add missing metadata:**
   - Review each file for proper categorization
   - Add `related_functions` and `related_event_types`
   - Assign difficulty levels

2. **Cross-reference:**
   - Link how-tos to relevant functions
   - Link best practices to examples
   - Create bidirectional references

3. **Validation:**
   - Run schema validation on all files
   - Check for duplicate content
   - Verify all URLs are valid

## Statistics

### Current State
- **How-Tos:** 54 files
- **Best Practices:** 34 files
- **Total:** 88 guidance documents
- **Integration:** 0% (not in main schema)
- **Schema Consistency:** 60% (different structures)

### Target State
- **How-Tos:** 54 files (unified schema)
- **Best Practices:** 34 files (unified schema)
- **Total:** 88 guidance documents
- **Integration:** 100% (in cql_schemas/)
- **Schema Consistency:** 100%
- **Cross-references:** ~200+ (estimated)

## Implementation Priority

1. **HIGH**: Create unified schema definition
2. **HIGH**: Migrate best practices to unified schema
3. **HIGH**: Move files to cql_schemas/ directories
4. **MEDIUM**: Create index files
5. **MEDIUM**: Update master schema index
6. **MEDIUM**: Archive historical documentation
7. **LOW**: Add missing metadata fields
8. **LOW**: Create cross-references

## Risks and Mitigation

### Risk 1: Data Loss During Migration
**Mitigation:** Keep original directories until validation complete

### Risk 2: Breaking Changes
**Mitigation:** Version the schema (2.0.0) and document changes in CHANGELOG

### Risk 3: URL Validation
**Mitigation:** Keep `url` field optional for backward compatibility

## Next Steps

1. Approve unified schema definition
2. Create migration script
3. Execute migration with validation
4. Update all indexes
5. Archive historical docs
6. Run full validation suite
7. Update README and documentation
8. Commit changes with detailed message

---

**Review Status:** ✅ Complete
**Approval Required:** Yes
**Estimated Migration Time:** 30-45 minutes
