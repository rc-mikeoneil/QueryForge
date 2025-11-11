# Time Filter Integration Fix

## Problem Statement

The Cortex XDR query builder was not leveraging the `cortex_time_filters.json` schema file when building queries. Instead, it used hardcoded time filter logic, which led to:

1. **Inconsistent syntax**: Time filters sometimes used invalid syntax like `| filter 7 days`
2. **Schema validation warnings**: The `_time` field was hardcoded but may not exist in all datasets
3. **Missed schema benefits**: The JSON schema defined proper time filter presets and validation rules that weren't being used

## Root Cause

The query builder had three main issues:

1. **No schema loading**: The `cortex_time_filters.json` was not being loaded by the schema loader
2. **Hardcoded defaults**: Time filter logic was hardcoded throughout the query builder
3. **No preset mapping**: User-friendly inputs like "7 days" weren't being mapped to schema-defined XQL syntax

## Solution Implemented

### 1. Schema Loader Enhancement (`schema_loader.py`)

Added a new method to expose time filter information:

```python
def time_filters(self) -> Dict[str, Any]:
    """Return time filter presets and configuration from schema."""
    payload = self.load()
    time_filters = payload.get("time_filters", {})
    return time_filters if isinstance(time_filters, dict) else {}
```

This method loads the time filter configuration from `cortex_time_filters.json`, which includes:
- **Presets**: Predefined time ranges like `last_hour`, `last_7_days`, `last_30_days`
- **Custom ranges**: Validation rules for relative time filters
- **Valid units**: Supported time units (second, minute, hour, day, week, month)

### 2. Query Builder Refactoring (`query_builder.py`)

#### Added Schema-Based Time Filter Mapping

Created `_get_time_filter_from_schema()` function that:
- Maps user inputs to schema presets (e.g., "7 days" → `_time > current_time() - interval '7 days'`)
- Validates time units against schema definitions
- Handles multiple input formats: "7 days", "7_days", "last_7_days"

```python
def _get_time_filter_from_schema(
    time_range_input: str,
    time_filter_schema: Dict[str, Any],
) -> str | None:
    """Map a time range input to the correct XQL syntax from schema."""
    # Maps to proper XQL syntax using schema presets and validation rules
```

#### Updated Natural Language Extraction

Modified `_extract_time_filters()` to:
- Accept and use the time filter schema
- Attempt schema-based mapping before falling back to constructed syntax
- Validate units against schema before generating XQL

#### Integrated Schema Throughout Build Process

Updated `build_cortex_query()` to:
- Load time filter schema at initialization
- Pass schema to all time filter functions
- Use schema presets for string time ranges

## Results

### Before Fix

```xql
dataset = xdr_data
| filter 7 days                    ❌ Invalid syntax
| filter actor_process_image_name contains 'msf'
| limit 100
```

**Validation warnings**:
- "Field '_time' may not exist in dataset 'xdr_data'"
- Inconsistent time filter formats

### After Fix

```xql
dataset = xdr_data
| filter actor_process_image_name contains 'msf'
| filter _time > current_time() - interval '7 days'    ✅ Valid XQL syntax
| limit 100
```

**Benefits**:
- ✅ Proper XQL syntax from schema
- ✅ Consistent time filter handling
- ✅ Schema-validated time units
- ✅ Support for preset mappings

## Test Coverage

Created `test_time_filter_integration.py` that verifies:

1. **String time ranges**: "7 days" maps correctly to XQL syntax
2. **Preset names**: "last_7_days" uses schema preset
3. **Natural language**: "last 24 hours" in intent parsed correctly
4. **Dict-based ranges**: Structured time_range parameter works
5. **Schema loading**: Time filter schema loads with all presets

All tests pass with valid XQL syntax.

## Schema Structure

The `cortex_time_filters.json` provides:

```json
{
  "cortex_xdr_query_schema": {
    "time_filters": {
      "presets": {
        "last_hour": {
          "syntax": "_time > current_time() - interval '1 hour'"
        },
        "last_7_days": {
          "syntax": "_time > current_time() - interval '7 days'"
        }
      },
      "custom": {
        "relative": {
          "units": ["second", "minute", "hour", "day", "week", "month"]
        }
      }
    }
  }
}
```

## Impact

- **Query Accuracy**: All time filters now use schema-validated XQL syntax
- **Maintainability**: Time filter logic centralized in schema, easier to update
- **Validation**: Proper field and operator validation from schema
- **User Experience**: Multiple input formats supported (e.g., "7 days", "last_7_days")

## Future Enhancements

Potential improvements:
1. **Field validation**: Validate that `_time` field exists in dataset before using it
2. **Alternative fields**: Support dataset-specific time fields beyond `_time`
3. **Absolute times**: Support absolute timestamp filtering from schema
4. **Time zone handling**: Add timezone-aware time filter support

## Files Modified

1. `src/queryforge/platforms/src/queryforge/platforms/cortex/schema_loader.py` - Added `time_filters()` method
2. `src/queryforge/platforms/cortex/query_builder.py` - Integrated schema-based time filter logic
3. `test_time_filter_integration.py` - Comprehensive test coverage

## Backward Compatibility

The changes are backward compatible:
- Existing queries continue to work
- Falls back to constructed syntax if schema mapping fails
- Dict-based time ranges still supported
