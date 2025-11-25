# CQL Schema Maintenance Guide

**Purpose:** Document processes for maintaining and updating CQL schemas over time  
**Last Updated:** 2025-11-25

---

## Overview

This guide establishes systematic processes for managing CQL schema definitions, ensuring they remain accurate and complete as CrowdStrike Falcon evolves and new query examples emerge.

---

## Source of Truth Hierarchy

When conflicts arise, follow this precedence order:

1. **Official CrowdStrike Documentation**
   - Falcon Data Replicator Guide
   - LogScale/Humio function reference
   - CQL query language documentation

2. **Production Example Queries**
   - Cool Query Friday examples
   - MITRE ATT&CK examples
   - Helpful Queries examples

3. **Existing Schema Definitions**
   - Current table/function/operator schemas

4. **Heuristic Inference**
   - Usage patterns in queries
   - Similar documented functions/operators

---

## Schema Entity Standards

### Functions

All function definitions must include:

```json
{
  "name": "functionName",
  "category": "aggregation|pattern|transformation|time|enrichment|network|...",
  "description": "Clear, concise description of what the function does",
  "syntax": "functionName(param1, param2, [optional])",
  "parameters": [
    {
      "name": "param_name",
      "type": "string|number|boolean|array|...",
      "required": true|false,
      "default": "value (if optional)",
      "description": "What this parameter does"
    }
  ],
  "return_type": "string|number|boolean|array|table|...",
  "examples": [
    "Real usage example 1",
    "Real usage example 2"
  ],
  "related_functions": ["func1", "func2"],
  "use_cases": ["Use case 1", "Use case 2"],
  "notes": "Important caveats or usage notes",
  "documentation_url": "https://..."
}
```

### Operators

All operator definitions must include:

```json
{
  "operator": "symbol",
  "name": "descriptive_name",
  "category": "comparison|logical|pattern|special|...",
  "description": "What the operator does",
  "syntax": "left operator right",
  "compatible_types": ["string", "number", "boolean"],
  "examples": ["example1", "example2"],
  "use_cases": ["use case 1", "use case 2"],
  "notes": "Important notes (optional)"
}
```

### Table Fields

All field definitions must include:

```json
{
  "name": "FieldName",
  "type": "string|long|boolean|timestamp|ip|...",
  "description": "What this field contains",
  "field_category": "source|enrichment|join_output|aggregate|calculated",
  "searchable": true|false,
  "supports_regex": true|false (optional),
  "required": true|false (optional),
  "example_values": ["example1", "example2"] (optional),
  "common_usage": ["usage1", "usage2"],
  "platform_scope": ["Win", "Mac", "Lin"] or "all" (optional)
}
```

---

## Field Categories Explained

Understanding field categories is critical for accurate schema documentation:

### `source`
- Native fields directly from Falcon sensor events
- Always available in raw event data
- Examples: `aid`, `ComputerName`, `ImageFileName`, `ProcessStartTime`
- **Usage**: Can be used in WHERE clauses, GROUP BY, and SELECT

### `enrichment`
- Fields added through enrichment functions (`enrich()`, `ipLocation()`, etc.)
- Not present in raw events but added during query execution
- Examples: `DomainName` (from `enrich()`), geolocation fields
- **Usage**: Only available after enrichment function is applied

### `join_output`
- Fields resulting from cross-event correlation via `join()` or `correlate()`
- Combined from multiple event types
- Examples: `RemoteAddressIP4` (from ProcessRollup2 + NetworkConnectIP4 join)
- **Usage**: Only available after join operation

### `aggregate`
- Computed fields from aggregation functions
- Result of `count()`, `sum()`, `avg()`, etc.
- Examples: `_count`, `totalConnections`, `uniqueEndpointCount`
- **Usage**: Only available in GROUP BY results, not in WHERE clauses

### `calculated`
- Derived fields created with `:=` assignment operator
- Computed from expressions within queries
- Examples: `timeDelta := now()-timestamp`, `entropy := shannonEntropy(field)`
- **Usage**: Available after assignment in query flow

---

## Adding New Functions

### Step 1: Identify the Need
- Check validation reports for missing function errors
- Review new example queries for undocumented functions
- Monitor query builder error logs

### Step 2: Research the Function
1. Search official CrowdStrike/Humio documentation
2. Analyze usage patterns in example queries:
   - How many parameters?
   - Where is it used (WHERE, SELECT, GROUP BY)?
   - What type of value does it return?
3. Find similar existing functions for reference

### Step 3: Create Function Schema
1. Create new JSON file in `cql_schemas/functions/`
2. Follow the function schema standard (see above)
3. Include all required fields
4. Add real examples from actual queries
5. Document related functions and use cases

### Step 4: Validate
1. Run schema validation scripts
2. Test query building with the new function
3. Verify no conflicts with existing schemas

### Example Workflow:
```bash
# 1. Create function definition
vim src/queryforge/platforms/cql/cql_schemas/functions/newFunction.json

# 2. Validate schema
python scripts/validate_cql_schema_improvements.py

# 3. Test with query builder
# Use MCP tools to build queries using the new function
```

---

## Adding New Operators

### Step 1: Verify It's Actually an Operator
- Check if it's a function being used as infix syntax
- Verify against CQL language specification
- Example: `match` can be both function and operator

### Step 2: Update operators.json
1. Open `cql_schemas/operators/operators.json`
2. Add new operator entry following the standard
3. Update `type_compatibility_matrix` if needed
4. Update `operator_precedence` if needed

### Step 3: Handle Aliases
- Lowercase variants: Document as aliases or separate entries
- Example: `and` as lowercase alias of `AND`

---

## Adding New Table Fields

### Step 1: Classify the Field
Determine field category:
- **Source**: In raw events? → `source`
- **From enrichment**: Added by `enrich()`? → `enrichment`  
- **From joins**: Combined events? → `join_output`
- **From aggregation**: Result of `count()`, etc.? → `aggregate`
- **Calculated**: Created with `:=`? → `calculated`

### Step 2: Verify Field Existence
1. Check official Falcon data dictionaries
2. Review example queries for consistent usage
3. Confirm field name spelling (case-sensitive!)
4. Verify data type from usage context

### Step 3: Add to Table Schema
1. Open appropriate table JSON file in `cql_schemas/tables/`
2. Add field to `columns` array
3. Include all required metadata
4. Update `col_count` field
5. Consider adding to `common_fields` if frequently used

### Step 4: Document Cross-References
- If field comes from joins, document in `common_operations`
- If field is platform-specific, note in `platform_scope`

---

## Handling Conflicts

### Type Conflicts
**Scenario**: Field appears as both `string` and `long` in different queries

**Resolution**:
1. Check official documentation for canonical type
2. If documentation unclear, analyze actual query usage:
   - Used in numeric comparison → likely `long`
   - Used in string matching → likely `string`
   - Used in both → document as `string` with note about numeric casting
3. Document the resolution decision

### Name Conflicts  
**Scenario**: Same semantic field has multiple names

**Resolution**:
1. Prefer official vendor name from documentation
2. Add aliases or notes documenting alternative names
3. Ensure query builder emits canonical name only

### Description Conflicts
**Scenario**: Multiple sources describe function/field differently

**Resolution**:
1. Prefer official documentation wording
2. Merge complementary information
3. Add comprehensive notes section if needed

---

## Validation Workflow

### Regular Validation Checks

Run these regularly (weekly or after schema changes):

```bash
# 1. Check schema coverage
python scripts/validate_cql_schema_improvements.py

# 2. Run CQL-specific tests
python -m pytest tests/test_cql_schema_integration.py -v

# 3. Validate against example queries
python src/queryforge/platforms/cql/validate_schemas.py
```

### After Adding New Schemas

```bash
# 1. Validate JSON syntax
find src/queryforge/platforms/cql/cql_schemas -name "*.json" -exec python -m json.tool {} \; > /dev/null

# 2. Run full test suite
python -m pytest tests/ -k cql -v

# 3. Test with MCP server
# Start MCP server and test new functions/fields via MCP tools
```

---

## Detecting New Gaps

### Automated Detection

Create scheduled tasks to:
1. Parse new example queries for unknown functions/operators/fields
2. Compare against current schemas
3. Generate "delta reports" highlighting gaps

### Manual Review Process

When new CQL features are released:
1. Review CrowdStrike release notes
2. Check for new event types, fields, functions
3. Update schemas accordingly
4. Add examples to example query collection

---

## Documentation Standards

### Commit Messages
When updating schemas, use clear commit messages:
- `feat(cql): add collect() function for aggregation`
- `fix(cql): correct LogonType field type to long`
- `docs(cql): add platform scope to Win/Mac/Lin constants`

### Change Log
Maintain `CHANGELOG.md` in CQL directory:
- Document what was added/changed
- Include rationale for changes
- Link to validation reports or issues

### Conflict Records
When resolving conflicts, document in schema change log:
```markdown
## 2025-11-25: LogonType Type Correction
- **Old**: string
- **New**: long  
- **Rationale**: Official Falcon docs specify LogonType as numeric (2, 3, 10, etc.)
- **Impact**: Query builders now treat as numeric for comparisons
```

---

## Quality Assurance Checklist

Before committing schema changes:

- [ ] JSON files validate with no syntax errors
- [ ] All required fields present (name, type, description)
- [ ] Examples are real and representative
- [ ] Field categories correctly assigned
- [ ] No conflicts with existing schemas
- [ ] Documentation URLs valid (if external)
- [ ] Related functions/operators cross-referenced
- [ ] Test suite passes with new schemas
- [ ] Coverage metrics improved or stable

---

## Common Pitfalls

### ❌ Don't Add Calculated Fields as Source Fields
**Wrong**: Adding `fileCount` as a source field in ProcessRollup2  
**Right**: Document `fileCount` as aggregate/calculated field or exclude from schema

### ❌ Don't Assume Field Names
**Wrong**: Adding `ProcessName` because it seems logical  
**Right**: Verify actual field name is `ImageFileName` or `FileName` from docs/examples

### ❌ Don't Mix Function and Operator Roles
**Wrong**: Only documenting `match` as function when it's also used as operator  
**Right**: Document both uses clearly

### ❌ Don't Ignore Case Sensitivity
**Wrong**: Assuming `groupBy` and `groupby` are different functions  
**Right**: Document as aliases or case-insensitive variants

---

## Future Enhancements

### Planned Improvements
1. **Automated Schema Updates**: Script to parse Falcon API documentation
2. **Semantic Validation**: Ensure parameter types match usage patterns
3. **Cross-Platform Testing**: Validate schemas against Win/Mac/Lin queries
4. **Performance Metrics**: Track which functions/fields impact query performance

### Long-Term Maintenance
- Quarterly review of schema coverage
- Annual alignment with Falcon releases
- Community contribution process for new examples
- Automated regression testing for schema changes

---

## Getting Help

### Resources
- CQL Documentation: https://library.humio.com/
- Falcon Data Replicator: https://falcon.crowdstrike.com/documentation/84/
- Internal validation reports: `src/queryforge/platforms/cql/*.md`

### Troubleshooting
- Schema syntax errors: Validate JSON files
- Coverage gaps: Run validation scripts
- Query building errors: Check MCP server logs
- Field conflicts: Review conflict resolution rules above

---

*Maintained by QueryForge CQL Team*
