# CQL Query Builder Field Validation Issue

## Problem

The CQL query builder is rejecting valid fields that exist in production CrowdStrike queries but are not documented in the schema files.

### Example Case: `IsOnRemovableDisk` Field

**Production Query (Works):**
```cql
event_platform=Win #event_simpleName=/Written/ IsOnRemovableDisk=1 
| FileSizeMB:=unit:convert(Size, to=M) 
| groupBy([ComputerName], function=([sum(Size, as=SizeBytes), sum(FileSizeMB, as=FileSizeMB), count(TargetFileName, as="File Count"), collect([TargetFileName])]))
```

**Query Builder Behavior:**
- When passing structured filters with `IsOnRemovableDisk`, the builder validates against the schema
- The field is not found in `FileWritten.json` schema
- The filter is rejected, causing the builder to only extract recognizable patterns (like `#event_simpleName=/Written/`)
- Result: A simplified query missing critical filters

## Root Cause

In `src/queryforge/platforms/cql/query_builder.py`, the `_build_filter_expression` method validates fields:

```python
def _build_filter_expression(
    self, filter_item: Any, fields: Dict[str, Dict[str, Any]]
) -> Tuple[str, Dict[str, Any]]:
    # ... 
    field = filter_item.get("field")
    
    # Validate field exists
    if field not in fields:
        raise ValueError(f"Field '{field}' is not present in the selected dataset")
    # ...
```

This strict validation prevents using undocumented but valid CrowdStrike fields.

## Why This Happens

1. **Incomplete Schema Documentation**: CrowdStrike's field schemas are extensive but not exhaustive. Many fields exist in production that aren't in official documentation.

2. **Dynamic Fields**: Some fields may be:
   - Event-specific (only present in certain event types)
   - Platform-specific (Win/Mac/Lin)
   - Tenant-specific (custom fields)
   - Deprecated but still functional

3. **Schema Maintenance**: Keeping schema files perfectly synchronized with CrowdStrike's API is challenging.

## Solutions

### Option 1: Disable Strict Field Validation (Recommended)

Make field validation a warning instead of an error:

```python
def _build_filter_expression(
    self, filter_item: Any, fields: Dict[str, Dict[str, Any]]
) -> Tuple[str, Dict[str, Any]]:
    field = filter_item.get("field")
    
    # Warn about unknown fields but allow them
    if field not in fields:
        logger.warning(f"Field '{field}' not found in schema but will be included in query")
    
    # Continue building expression regardless
    # ...
```

**Pros:**
- Allows all valid CrowdStrike fields
- Maintains compatibility with production queries
- Still logs warnings for debugging

**Cons:**
- No validation for typos in field names
- Could allow completely invalid fields

### Option 2: Add Missing Fields to Schema

Manually add undocumented fields to schema files:

```json
{
  "name": "IsOnRemovableDisk",
  "type": "boolean",
  "description": "Indicates if file was written to removable media",
  "searchable": true,
  "common_usage": ["filtering", "removable media detection"],
  "undocumented": true
}
```

**Pros:**
- Maintains strict validation
- Documents known undocumented fields

**Cons:**
- Requires ongoing maintenance
- Can't cover all possible fields
- Time-consuming

### Option 3: Hybrid Approach (Best)

Combine both approaches:

1. **Maintain a "known undocumented fields" list**
2. **Make validation a warning for structured filters**
3. **Keep strict validation for natural language extraction** (to prevent false positives)

```python
# Known undocumented but valid fields
UNDOCUMENTED_FIELDS = {
    "IsOnRemovableDisk": {"type": "boolean", "description": "File on removable media"},
    "FileSizeMB": {"type": "float", "description": "File size in MB"},
    # Add more as discovered
}

def _build_filter_expression(
    self, filter_item: Any, fields: Dict[str, Dict[str, Any]]
) -> Tuple[str, Dict[str, Any]]:
    field = filter_item.get("field")
    
    # Check schema first, then undocumented list
    if field not in fields:
        if field in UNDOCUMENTED_FIELDS:
            logger.info(f"Using undocumented field '{field}'")
            field_meta = UNDOCUMENTED_FIELDS[field]
        else:
            logger.warning(f"Field '{field}' not in schema - using anyway")
            field_meta = {"type": "string"}  # Default assumption
    else:
        field_meta = fields[field]
    
    # Continue with expression building...
```

## Immediate Workaround

For users encountering this issue now:

1. **Use string filters instead of structured filters:**
   ```python
   filters=["IsOnRemovableDisk=1", "event_platform=Win"]
   ```

2. **Use the traditional two-step approach** with manual query construction:
   ```python
   # Build manually, then validate
   query = "event_platform=Win #event_simpleName=/Written/ IsOnRemovableDisk=1"
   result = cql_validate_query(query=query, dataset="events")
   ```

3. **Reference the example queries** which contain working production queries

## Recommendation

**Implement Option 3 (Hybrid Approach)** because:
- Preserves user experience (allows all valid fields)
- Maintains helpful warnings (catches obvious typos)
- Documents commonly used undocumented fields
- Balances strictness with practicality

## Related Files

- `src/queryforge/platforms/cql/query_builder.py` - Query builder implementation
- `src/queryforge/platforms/cql/cql_schemas/tables/*.json` - Schema definitions
- `src/queryforge/platforms/cql/cql_schemas/examples/` - Production query examples

## Testing

After implementing fix, test with:

```python
# Should work without errors
result = cql_build_query_validated(
    dataset="events",
    filters=[
        {"field": "event_platform", "operator": "=", "value": "Win"},
        {"field": "event_simpleName", "operator": "=~", "value": "/Written/"},
        {"field": "IsOnRemovableDisk", "operator": "=", "value": "1"}
    ],
    boolean_operator="AND"
)
