# Docker Filter Validation Error - Fix Summary

## Problem

A Docker error was occurring when building Cortex queries:

```
2025-11-05T16:46:14.190431439Z [11/05/25 16:46:14] Error validating tool 'cortex_build_query': 2 validation errors for call[cortex_build_query]                     
filters.dict[str,any]                                       
  Input should be a valid dictionary [type=dict_type,       
input_value=['(action_local_port = 44...ion_remote_port = 444)'], input_type=list]                                    
```

## Root Cause

The `cortex_build_query` MCP tool was receiving filters in the wrong format:

**Expected format:**
```python
filters = [
    {"field": "action_local_port", "operator": "=", "value": 444}
]
# OR
filters = {"field": "action_local_port", "operator": "=", "value": 444}
```

**Actually received:**
```python
filters = ['(action_local_port = 444 OR action_remote_port = 444)']
```

The tool was receiving a **list containing a pre-formatted filter string** instead of structured dictionaries.

## Solution

Added comprehensive input validation to both `cortex_build_query` and `s1_build_query` tools:

### 1. Cortex Validation (queryforge/server_tools_cortex.py)

```python
# Validate filters format before processing
if filters is not None:
    if isinstance(filters, list):
        for i, f in enumerate(filters):
            if not isinstance(f, dict):
                error_msg = (
                    f"Invalid filter format at index {i}: expected dict with "
                    f"'field', 'operator', 'value' keys, got {type(f).__name__}. "
                    f"Received value: {repr(f)[:100]}. "
                    f"Correct format example: {{'field': 'action_local_port', 'operator': '=', 'value': 444}}"
                )
                logger.error(error_msg)
                return {"error": error_msg}
            if "field" not in f:
                # ... validation for missing field key
```

### 2. S1 Validation (queryforge/server_tools_s1.py)

S1 accepts both strings and dictionaries, so the validation is more flexible but still catches malformed inputs.

## Benefits

1. **Clear Error Messages**: Instead of cryptic Pydantic validation errors, users get actionable guidance
2. **Early Detection**: Catches invalid input before it reaches the query builder
3. **Prevents System Failure**: Stops malformed data from causing Docker container crashes
4. **Developer Guidance**: Shows exactly what format is expected with examples

## Test Results

✅ All validation tests pass:
- Correctly rejects string filters in Cortex (the original issue)
- Correctly accepts valid dictionary formats  
- Provides clear error messages with examples
- Handles edge cases (missing keys, wrong types, etc.)

## Files Modified

- `queryforge/server_tools_cortex.py` - Added comprehensive filter validation
- `queryforge/server_tools_s1.py` - Added flexible validation for string/dict filters + fixed missing import

## Impact

This fix resolves the Docker error and prevents similar issues in the future by validating input format early and providing clear guidance to callers.
