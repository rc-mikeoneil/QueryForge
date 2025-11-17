# CQL Schema Loader Fix - Browser Extension Fields

## Issue Summary

The CQL MCP server was unable to properly assist with queries involving browser extensions because the `InstalledBrowserExtension` event type fields were not being loaded into the schema.

### Root Cause

The `get_fields()` method in `src/queryforge/platforms/cql/schema_loader.py` was only loading a hardcoded subset of event types:

```python
# OLD CODE (PROBLEMATIC)
event_types = ["ProcessRollup2", "NetworkConnectIP4", "DnsRequest", "UserLogon", "OsVersionInfo"]

for event_type in event_types:
    table_file = tables_dir / f"{event_type}.json"
    # ... load fields
```

This meant that even though `InstalledBrowserExtension.json` existed in the `cql_schemas/tables/` directory with all the correct fields (BrowserExtensionId, BrowserExtensionName, BrowserName, etc.), these fields were never loaded into the schema.

### Impact

- The `cql_get_fields` MCP tool would not return browser extension-specific fields
- RAG-enhanced field filtering couldn't find relevant browser extension fields
- Query building would not have proper schema information for browser extension queries
- The LLM assistant would fall back to generic fields, missing the specialized event type

### Fix Applied

Modified `get_fields()` to load **ALL** table schemas from the tables directory instead of a hardcoded subset:

```python
# NEW CODE (FIXED)
# Load ALL event types from the tables directory
for table_file in tables_dir.glob("*.json"):
    try:
        with table_file.open("r", encoding="utf-8") as f:
            table_data = json.load(f)
        
        # Extract fields from the table schema
        for field in table_data.get("columns", []):
            field_entry = {
                "name": field.get("name", ""),
                "type": field.get("type", "string"),
                "description": field.get("description", ""),
                "indexed": field.get("searchable", True)
            }
            # Avoid duplicates
            if not any(f["name"] == field_entry["name"] for f in fields_list):
                fields_list.append(field_entry)
```

Also fixed the field extraction to use `"columns"` instead of `"fields"` to match the actual table schema structure.

### Verification

Test results after fix:
```
Total fields loaded: 147 (previously ~9)

Checking for browser extension fields...
✓ Found: BrowserExtensionId
✓ Found: BrowserExtensionName
✓ Found: BrowserName
✓ Found: BrowserProfileId

SUCCESS: 4/4 browser extension fields found
```

### Files Changed

1. **src/queryforge/platforms/cql/schema_loader.py**
   - Modified `get_fields()` method to load all table schemas dynamically
   - Changed field extraction from `table_data.get("fields")` to `table_data.get("columns")`
   - Changed indexed detection from `True` default to `field.get("searchable", True)`

2. **test_cql_fields_fix.py** (new test file)
   - Verification test to ensure browser extension fields are loaded

### Future Prevention

**Recommendation**: When adding new event types to the CQL schema:

1. The schema loader now automatically discovers all `*.json` files in the `tables/` directory
2. No code changes needed - just add the new event type JSON file
3. The file should follow the standard structure with a `"columns"` array
4. Fields should have `"searchable": true/false` to indicate indexing

This fix ensures the schema loader is extensible and won't require code updates as new event types are added to the CQL schema.

### Related Components

This fix improves the following MCP tools:
- `cql_get_fields` - Now returns all available fields across all event types
- `cql_build_query` - Has access to complete field schema for validation
- `cql_build_query_validated` - Can properly validate queries using any event type
- RAG field filtering - Can semantically match fields from all event types

### Date
2025-11-17
