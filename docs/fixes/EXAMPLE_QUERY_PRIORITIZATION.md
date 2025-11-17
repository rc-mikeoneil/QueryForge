# Example Query Prioritization Enhancement

## Overview

Enhanced the query builder to prioritize returning exact matching production-ready example queries before building queries from scratch. This ensures users get validated, tested queries when their requests match existing examples.

## Changes Made

### 1. Updated CQL Query Builder (`src/queryforge/platforms/cql/query_builder.py`)

Added `_find_exact_example_match()` method that:
- Checks if natural language intent matches example query titles, descriptions, or use cases
- Normalizes user input by removing filler words
- Performs flexible matching on key phrases
- Returns production-ready example queries when found

**Logic Flow:**
1. When `natural_language_intent` is provided WITHOUT filters or fields
2. Search all example queries for matches
3. If exact match found, return the production query directly
4. Otherwise, proceed with normal query building

### 2. Updated Project Rules (`.clinerules`)

Added new Section 1: "Check for Exact Example Query Matches FIRST"

**Guidance:**
- When to return example queries directly
- When NOT to use example queries
- Matching criteria for finding examples

### 3. Schema Enhancement

Added `IsOnRemovableDisk` field to FileWritten schema to support the example query for files written to removable media.

## Example Use Case

**User Request:** "files written to removable media"

**Before Enhancement:**
- Query builder would construct a basic query: `event_simpleName =~ '/Written/' | limit 100`
- Missing critical filters like `IsOnRemovableDisk`
- Missing aggregations and transformations

**After Enhancement:**
- Recognizes match with example query "Files Written to Removable Media"
- Returns production-ready query:
  ```cql
  event_platform=Win #event_simpleName=/Written/ IsOnRemovableDisk=1 
  | FileSizeMB:=unit:convert(Size, to=M) 
  | groupBy([ComputerName], function=([sum(Size, as=SizeBytes), sum(FileSizeMB, as=FileSizeMB), count(TargetFileName, as="File Count"), collect([TargetFileName])]))
  ```

## Metadata Returned

When an example query is matched, the metadata includes:
```json
{
  "source": "example_query",
  "example_id": "files-written-to-removable-media",
  "example_title": "Files Written to Removable Media",
  "description": "...",
  "use_case": "...",
  "dataset": "events",
  "exact_match": true
}
```

## Benefits

1. **Production-Ready Queries:** Users get tested, validated queries with proper aggregations
2. **Faster Results:** No need to build complex queries from scratch
3. **Best Practices:** Example queries follow CrowdStrike best practices
4. **Reduced Errors:** Pre-validated queries are less likely to have syntax or field errors
5. **Complete Functionality:** Includes all transformations and aggregations needed for the use case

## When Example Matching is Bypassed

Example matching is skipped when:
- User provides specific filters (custom values, IPs, device names)
- User requests specific fields (projection)
- User wants modifications to the query structure
- The intent doesn't match any example closely enough

## Future Enhancements

This pattern should be applied to other platforms:
- [ ] CBC (Carbon Black Cloud)
- [ ] Cortex XDR
- [ ] KQL (Microsoft Defender)
- [ ] SentinelOne

Each platform's query builder should implement similar `_find_exact_example_match()` logic.

## Testing

Test the enhancement:
```python
# Should return production example query
cql_build_query_validated(
    natural_language_intent="files written to removable media"
)

# Should build custom query (filters provided)
cql_build_query_validated(
    natural_language_intent="files written to removable media",
    filters=[{"field": "ComputerName", "value": "DESKTOP-123"}]
)
```

## Related Files

- `src/queryforge/platforms/cql/query_builder.py` - Implementation
- `.clinerules` - Documentation
- `src/queryforge/platforms/cql/cql_schemas/examples/` - Example queries source
- `docs/fixes/CQL_QUERY_BUILDER_FIELD_VALIDATION.md` - Related field validation fix
