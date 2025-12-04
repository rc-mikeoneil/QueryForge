# CQL Timestamp Extraction and Syntax Fix

**Date:** December 4, 2025  
**Severity:** High (Syntax Errors)  
**Status:** ✅ Fixed

## Problem Summary

The CQL query builder was generating syntactically invalid queries when processing natural language requests containing timestamps. This resulted in multiple CrowdStrike syntax errors.

### Original Error Example

User request:
```
"I need assistance creating a query for crowdstrike. I am looking for 
the device LT-PF3M5XSF being infected by a click to run attack. I want 
to see any additional activity that occurred after spawning mshta. 
This activity occurred on 2025-12-01 21:33:06 UTC"
```

Generated errors:
```
Expected an expression. (Error: ExpectedExpression)
ComputerName = 'LT-PF3M5XSF' AND FileName = 'mshta.exe' AND @timestamp >= '2025-12-0...
Expected a string. (Error: ExpectedString)
LocalAddressIP4 = '21:33:06' AND TargetFileName = 'mshta.exe'
```

## Root Causes

### 1. Timestamp Component Misextraction
**Issue:** Time components from timestamps (e.g., "21:33:06") were being extracted and misinterpreted as IP addresses or other field values.

**Example:**
- Input: `"2025-12-01 21:33:06 UTC"`
- Extracted: `"21:33:06"` → Incorrectly used as IP address value
- Result: `LocalAddressIP4 = '21:33:06'` (invalid)

### 2. ISO 8601 Format Issues
**Issue:** Timestamps with spaces weren't being properly converted to ISO 8601 format (T separator).

**Example:**
- Input: `"2025-12-01 21:33:06 UTC"`
- Expected: `"2025-12-01T21:33:06Z"`
- Actual: `"2025-12-01 21:33:06Z"` or `"2025-12-01T21:33:06TZ"`

### 3. Missing Hostname Field Category
**Issue:** The CQL schema loader didn't have a `hostname_fields` category, preventing device/hostname extraction.

### 4. Process Name Extraction
**Issue:** Common process names without extensions (like "mshta") weren't being matched and converted to Windows executable names (e.g., "mshta.exe").

## Solution Implementation

### 1. Timestamp Sanitization (query_builder.py)

Added `_sanitize_text_for_extraction()` method to mask timestamp patterns before extraction:

```python
def _sanitize_text_for_extraction(self, text: str) -> str:
    """
    Sanitize text by removing/masking timestamp patterns.
    Prevents timestamp components from being extracted as IPs or other indicators.
    """
    sanitized = text
    
    # Replace full timestamps with placeholder
    sanitized = _TIMESTAMP_RE.sub("[TIMESTAMP]", sanitized)
    
    # Replace standalone dates with placeholder
    sanitized = _DATE_RE.sub("[DATE]", sanitized)
    
    # Replace standalone times with placeholder
    sanitized = _TIME_RE.sub("[TIME]", sanitized)
    
    return sanitized
```

### 2. IP Address Validation Enhancement

Added negative lookahead to IP regex patterns to prevent matching timestamp components:

```python
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    r"(?![-T:\s]\d)"  # Not followed by timestamp indicators
)
```

### 3. Fixed Timestamp Normalization

Improved `_normalize_timestamp()` to properly handle ISO 8601 conversion:

```python
def _normalize_timestamp(self, timestamp: str) -> str:
    # Remove UTC/GMT text markers first
    ts = re.sub(r"\s+(UTC|GMT)\s*$", "", ts, flags=re.IGNORECASE)
    
    # Replace space with T (ISO 8601 format)
    if "T" not in ts:
        ts = re.sub(r"(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})", r"\1T\2", ts)
    
    # Ensure Z suffix for UTC
    if not re.search(r"[Z\+\-]\d{2}:\d{2}$", ts) and not ts.endswith("Z"):
        ts += "Z"
    
    return f'"{ts}"'
```

### 4. Added Hostname Field Category (schema_loader.py)

Extended field categorization to include hostname/device name fields:

```python
categories = {
    "hostname_fields": [],  # Added
    # ... other categories
}

# Categorize hostname fields
if "Computer" in field_name or field_name in ["aid", "ComputerName", "ComputerNameFQDN"]:
    if field_name not in categories["hostname_fields"]:
        categories["hostname_fields"].append(field_name)

# Fallback values
if not categories["hostname_fields"]:
    categories["hostname_fields"] = ["ComputerName", "aid", "ComputerNameFQDN"]
```

### 5. Added Hostname Extraction Pattern

Created regex pattern to extract device/hostname from natural language:

```python
_HOSTNAME_RE = re.compile(
    r"\b(?:device|host|hostname|computer|computername|endpoint|system|machine)\s+"
    r"(?:is|=|equals|named|called)?\s*['\"]?([A-Z0-9][A-Z0-9-]{0,62}[A-Z0-9]?)['\"]?",
    re.IGNORECASE
)
```

### 6. Enhanced Process Name Extraction

Extended process name regex to include common processes without extensions:

```python
_PROCESS_NAME_RE = re.compile(
    r"\b(powershell|cmd|mshta|chrome|firefox|explorer|winword|excel|notepad|calc|"
    r"msiexec|svchost|rundll32|regsvr32|wscript|cscript|java|python)\b",
    re.IGNORECASE
)

# In _collect_process_expressions:
for match in _PROCESS_NAME_RE.finditer(text):
    process_name = match.group(1)
    value = f"{process_name}.exe"  # Add .exe extension
    expressions.append(f"{field} = {self._quote(value)}")
```

### 7. Added Event Type Inference

Automatically adds CQL event type filters for performance:

```python
def _infer_event_type(self, natural_language_intent, filters):
    intent_lower = natural_language_intent.lower()
    
    # Process execution events
    process_keywords = ["process", "execution", "spawning", "mshta", "cmd", ...]
    if any(kw in intent_lower for kw in process_keywords):
        return "#event_simpleName=ProcessRollup2"
    
    # Network events
    network_keywords = ["network", "connection", "dns", "http", ...]
    if any(kw in intent_lower for kw in network_keywords):
        return "#event_simpleName=NetworkConnectIP4"
    
    return None
```

## Test Coverage

Created comprehensive test suite (`tests/test_cql_timestamp_fix.py`) with 7 test cases:

1. ✅ **test_original_failing_query** - Reproduces original bug scenario
2. ✅ **test_timestamp_sanitization** - Verifies timestamp masking works
3. ✅ **test_device_name_extraction** - Tests hostname extraction
4. ✅ **test_process_name_with_mshta** - Tests mshta.exe extraction
5. ✅ **test_time_range_formats** - Tests various time format handling
6. ✅ **test_event_type_inference** - Tests automatic event type addition
7. ✅ **test_no_timestamp_in_wrong_fields** - Regression test for timestamp components

All tests passing ✅

## Verification

### Before Fix
```cql
ComputerName = 'LT-PF3M5XSF' AND FileName = 'mshta.exe' AND @timestamp >= '2025-12-0...
                                                                          ^
Expected an expression. (Error: ExpectedExpression)
LocalAddressIP4 = '21:33:06' AND TargetFileName = 'mshta.exe'
                  ^
Expected a string. (Error: ExpectedString)
```

### After Fix
```cql
#event_simpleName=ProcessRollup2 AND aid = "LT-PF3M5XSF" AND TargetFileName = "mshta.exe" AND @timestamp >= "2025-12-01T21:33:06Z" | limit 100
```

✅ Valid CQL syntax  
✅ **Double quotes for all string values (CQL requirement)**  
✅ Correct field extraction (aid for device, TargetFileName for process)  
✅ Proper timestamp format (ISO 8601 with T separator and Z suffix)  
✅ No timestamp components in wrong fields  
✅ Event type filter included for performance

## Impact

- **Scope:** All CQL query generation involving timestamps and natural language processing
- **Severity:** High - Prevented query execution
- **Users Affected:** Anyone using natural language query building with timestamps
- **Fix Complexity:** Medium - Required changes across multiple extraction methods

## Files Modified

1. `src/queryforge/platforms/cql/query_builder.py` - Main query builder logic (timestamp handling, double quotes)
2. `src/queryforge/platforms/cql/schema_loader.py` - Field categorization (hostname fields)
3. `tests/test_cql_timestamp_fix.py` - Comprehensive test coverage (new file)
4. `docs/fixes/CQL_TIMESTAMP_EXTRACTION_FIX.md` - Documentation (this file)

## Related Issues

- Timestamp parsing in natural language queries
- Field category completeness in schema loader
- Process name normalization for Windows executables
- CQL syntax validation and best practices

## Prevention Measures

1. ✅ Comprehensive test coverage for timestamp handling
2. ✅ Sanitization before regex extraction
3. ✅ Negative lookahead patterns in IP regex
4. ✅ Field category validation in schema loader
5. ✅ Event type inference for performance optimization

## References

- CrowdStrike Query Language Documentation
- ISO 8601 Timestamp Format Standard
- QueryForge Natural Language Processing Architecture
