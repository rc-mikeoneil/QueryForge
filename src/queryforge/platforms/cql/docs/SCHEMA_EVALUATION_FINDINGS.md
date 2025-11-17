# CQL Schema Evaluation Findings

**Date:** 2025-11-17  
**Evaluator:** System Analysis  
**Status:** Issues Identified - Action Required

## Executive Summary

The CQL schema structure has been evaluated against CBC and S1 platforms for consistency. Several significant issues were identified that need to be addressed to ensure proper functionality and maintainability.

## Key Findings

### 1. **CRITICAL: Duplicate Operator Schema Files**

**Issue:** Two competing operator schema files exist with different structures:
- `/cql_schemas/cql_operators.json` (root level)
- `/cql_schemas/operators/operators.json` (subdirectory)

**Impact:**
- Schema loader is loading the wrong file
- Operator normalization may fail
- Inconsistent data structures cause confusion

**Details:**
```
cql_operators.json structure:
{
  "operators": {
    "equals": {
      "normalized": "=",
      "operators": ["=", "==", ...],
      ...
    }
  }
}

operators/operators.json structure:
{
  "operators": [
    {
      "operator": "=",
      "name": "equals",
      ...
    }
  ]
}
```

**Evidence in schema_loader.py (line 176):**
```python
def get_operators(self) -> Dict[str, Any]:
    """Get operator definitions and normalization rules."""
    # Load from operators/operators.json
    return self._load_json("operators/operators.json")
```

But operator normalization (line 200) expects the OLD structure:
```python
def normalize_operator(self, operator: str) -> str:
    operators_data = self.get_operators()
    operators_list = operators_data.get("operators", [])  # Expects array
    ...
    # But then tries to iterate as dict keys!
    for op_def in operators_list:
        if isinstance(op_def, dict):
            op_symbol = op_def.get("operator", "")
```

### 2. **MAJOR: Missing Metadata Index Files**

**Issue:** Schema loader references metadata files that don't exist:
- `metadata/functions_index.json` (referenced but not found)
- `metadata/examples_index.json` (EXISTS and is correct)
- `metadata/best_practices_index.json` (EXISTS and is correct)

**Impact:**
- `get_documentation()` method will fail
- Functions documentation unavailable
- RAG integration incomplete

### 3. **MAJOR: Inconsistent Schema File Organization**

**Comparison with other platforms:**

**CBC Structure (GOOD):**
```
/cbc/
  cbc_schema.json          # Monolithic option
  cbc_*.json               # Split field files
  query_builder.py
  schema_loader.py
  validator.py
```

**S1 Structure (GOOD):**
```
/s1/
  s1_schemas/              # Clean subdirectory
    s1_processes.json
    s1_operators.json
    etc.
  query_builder.py
  schema_loader.py
  validator.py
```

**CQL Structure (PROBLEMATIC):**
```
/cql/
  cql_schemas/            # Subdirectory
    cql_core.json
    cql_operators.json    # DUPLICATE!
    operators/
      operators.json      # DUPLICATE!
    functions/           # 60+ individual files
    best_practices/      # 34+ individual files
    how_tos/            # 50+ individual files
    examples/           # Nested subdirectories
    metadata/           # Index files
    builder/            # Builder-specific configs
    tables/             # Event type schemas
    legacy/             # Old schemas
```

**Issues:**
- Overly complex nested structure
- Duplicate files at different levels
- Unclear which files are authoritative
- Harder to maintain than peer platforms

### 4. **MINOR: Schema Loader Logic Inconsistencies**

**Issue:** Schema loader has hardcoded fallbacks instead of using actual schema files:

```python
def get_core_info(self) -> Dict[str, Any]:
    """Get core platform information."""
    # Build core info from existing schema structure
    return {
        "schema_version": "1.0.0",
        # ... HARDCODED VALUES instead of loading cql_core.json
    }
```

But `cql_core.json` already exists with this data!

### 5. **MINOR: Missing Security Validation**

**Issue:** CQL schema_loader.py lacks security features present in CBC:
- No path validation (`validate_schema_path`, `validate_glob_results`)
- No file size limits
- No integrity checks (HMAC signatures)
- No cache poisoning protection

**CBC Example (secure):**
```python
from queryforge.shared.security import validate_schema_path, validate_glob_results

self.schema_path = validate_schema_path(Path(schema_path))
cbc_files = validate_glob_results(schema_dir, cbc_files_raw)
```

### 6. **INCONSISTENCY: Field Loading Logic**

**Issue:** `get_fields()` method has complex fallback logic instead of using table schemas:

```python
def get_fields(self, dataset: str, query_intent: Optional[str] = None):
    # Tries to load from tables/ directory
    # Falls back to hardcoded common fields
    # Should use dedicated field schema files like CBC
```

## Recommended Actions

### Priority 1: CRITICAL - Fix Operator Schema Duplication

**Action Required:**
1. **Consolidate operator schemas** - Choose ONE authoritative file
2. **Update schema_loader.py** to use correct structure
3. **Delete duplicate file**

**Recommended Approach:**
- Keep: `/cql_schemas/operators/operators.json` (more detailed, newer version 1.1.0)
- Remove: `/cql_schemas/cql_operators.json` (older, simpler version 1.0.0)
- Update: `schema_loader.py` line 176 to correctly parse array structure

### Priority 2: MAJOR - Add Missing Metadata Files

**Action Required:**
1. Create `metadata/functions_index.json` with function catalog
2. Update `get_documentation()` to handle missing files gracefully

### Priority 3: MAJOR - Simplify Directory Structure

**Options:**

**Option A: Follow S1 Pattern (Recommended)**
```
/cql/
  cql_schemas/
    core.json
    operators.json
    functions.json
    best_practices.json
    examples.json
    field_types.json
    event_types/
      ProcessRollup2.json
      NetworkConnectIP4.json
      etc.
```

**Option B: Follow CBC Pattern**
```
/cql/
  cql_core.json
  cql_operators.json
  cql_functions.json
  cql_best_practices.json
  cql_examples.json
  cql_event_*.json
```

**Option C: Keep Current Structure (Not Recommended)**
- Document clear hierarchy
- Remove duplicates
- Add README at each level

### Priority 4: MINOR - Add Security Features

**Action Required:**
1. Import security utilities from `queryforge.shared.security`
2. Add path validation
3. Add file size limits (like CBC's MAX_CACHE_SIZE_BYTES)
4. Add integrity checking

### Priority 5: MINOR - Improve Schema Loader

**Action Required:**
1. Load `cql_core.json` instead of hardcoding
2. Simplify field loading logic
3. Add proper error handling
4. Add logging for missing files

## Implementation Plan

### Phase 1: Critical Fixes (Immediate)
- [ ] Fix operator schema duplication
- [ ] Update schema_loader.py operator methods
- [ ] Test operator normalization

### Phase 2: Structure Improvements (Short-term)
- [ ] Create functions_index.json
- [ ] Simplify directory structure (choose option)
- [ ] Update all loader references
- [ ] Update documentation

### Phase 3: Security & Quality (Medium-term)
- [ ] Add security validation
- [ ] Improve error handling
- [ ] Add comprehensive logging
- [ ] Add schema validation tests

### Phase 4: Alignment (Long-term)
- [ ] Align with CBC/S1 patterns
- [ ] Standardize across all platforms
- [ ] Create platform-independent base class
- [ ] Document schema standards

## Testing Requirements

After implementing changes:
1. Run `tests/test_cql_schema_integration.py`
2. Test query builder with various operators
3. Test validator with all operator types
4. Verify MCP tools functionality
5. Check RAG integration

## Files That Need Updates

### Immediate Changes Required:
1. `src/queryforge/platforms/cql/schema_loader.py` - Fix operator loading
2. `src/queryforge/platforms/cql/cql_schemas/cql_operators.json` - DELETE or consolidate
3. `src/queryforge/platforms/cql/query_builder.py` - Verify operator usage
4. `src/queryforge/platforms/cql/validator.py` - Verify operator validation

### Metadata Files to Create:
1. `src/queryforge/platforms/cql/cql_schemas/metadata/functions_index.json`

### Testing Files to Update:
1. `tests/test_cql_schema_integration.py` - Add operator tests
2. Add new test for schema consistency

## Comparison with Other Platforms

| Aspect | CBC | S1 | CQL | Status |
|--------|-----|----|----|--------|
| Schema Organization | ✅ Clean | ✅ Clean | ❌ Complex | Fix Needed |
| Security Validation | ✅ Yes | ⚠️ Partial | ❌ No | Add Security |
| Duplicate Files | ✅ None | ✅ None | ❌ Yes | Fix Critical |
| Operator Handling | ✅ Good | ✅ Good | ❌ Broken | Fix Critical |
| Documentation | ✅ Good | ✅ Good | ⚠️ Partial | Improve |

## Conclusion

The CQL schema structure has significant issues that need immediate attention:
1. **Critical operator schema duplication breaking functionality**
2. **Complex directory structure harder to maintain**
3. **Missing security features present in CBC**
4. **Inconsistent with peer platforms**

Recommend implementing fixes in priority order, starting with the critical operator schema issue.
