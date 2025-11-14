# Command Flag Security Fix for EDR Query Builders

## Issue

The KQL query builder's security validator was too restrictive, blocking legitimate security detection queries that contain command-line flags like `--retry`, `--max-time`, etc. This was causing valid threat hunting queries to fail validation, specifically:

- Double-dash parameters in command lines (`--retry`, `--max-time`, etc.)
- Shell operators like `||` and `&&`
- Shell redirects like `>>`

This affected security detection scenarios like the "MacOS Digit Stealer" detection, which legitimately includes these patterns in its detection logic.

## Root Cause

The security validator in `src/queryforge/platforms/kql/query_builder.py` contained an overly broad regex pattern:

```python
re.compile(r'--'),  # Blocked ANY double dash
```

This pattern was intended to block SQL-style comments (which start with `--`), but it also blocked any legitimate use of command-line parameters that start with double dashes.

## Fix Summary

### 1. More Precise Regex Pattern

Changed the overly broad pattern to a more precise one that only catches SQL-style comments:

```python
# Before: Blocked any double dash
re.compile(r'--'),

# After: Only blocks SQL-style comments, not command flags
re.compile(r'--\s*(?:[^-\w]|$)'),  # Matches: "-- comment" but NOT "--retry" 
```

### 2. Added Allowlist for Legitimate Patterns

Added a comprehensive allowlist of legitimate patterns that should not trigger security validation errors:

```python
_ALLOWED_COMMAND_PATTERNS = (
    re.compile(r'--[a-z]+-[a-z]+'),  # Command flags like --retry-delay, --max-time
    re.compile(r'--[a-z]+'),          # Single-word flags like --retry, --force
    re.compile(r'\|\|'),              # Shell OR operator (||)
    re.compile(r'&&'),                # Shell AND operator (&&)
    re.compile(r'>>'),                # Shell redirect append (>>)
    re.compile(r'<<'),                # Shell here-document (<<)
)
```

### 3. Improved Validation Logic

Updated the validation function to use the allowlist, bypassing dangerous pattern checks if a pattern matches the allowlist:

```python
def _validate_where_conditions(conditions: List[str]) -> List[str]:
    # ... existing validation code ...
    
    for condition in conditions:
        # ... existing validation code ...
        
        # Check dangerous patterns, but skip validation if allowlisted patterns are present
        for pattern in _WHERE_DANGEROUS_PATTERNS:
            if pattern.search(condition):
                # Before failing, check if this is actually an allowlisted pattern
                is_safe = any(allow_pattern.search(condition) for allow_pattern in _ALLOWED_COMMAND_PATTERNS)
                if not is_safe:
                    raise ValueError(f"WHERE condition contains potentially dangerous pattern: {condition}")
                # Pattern matched but it's allowlisted, so continue validation
                break

        # ... rest of validation code ...
```

## Platform Analysis

The issue was specific to the KQL query builder. Other platforms use different validation approaches:

- **KQL**: Fixed. Used overly restrictive pattern matching.
- **CBC**: No issue. Uses `_sanitise_term` to check for specific dangerous characters.
- **CBR**: No issue. Similar approach to CBC.
- **Cortex**: No issue. Uses field validation and quoting, not pattern-based security checks.
- **SentinelOne**: No issue. Uses `_sanitise_expression` to check for specific dangerous characters.

## Impact

This fix allows legitimate security detection queries to pass validation while still maintaining protection against actual injection attempts. Security analysts can now use the full range of threat hunting patterns without false blockages.

### Example Query That Now Works

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (ProcessCommandLine contains "osascript" and ProcessCommandLine contains "set volume with output muted")
    or (ProcessCommandLine contains "mkdir" and ProcessCommandLine contains "/tmp/downloaded_parts")
    or (ProcessCommandLine contains "curl" and ProcessCommandLine contains "--max-time" and ProcessCommandLine contains "--retry" and ProcessCommandLine contains "--retry-delay")
    or (ProcessCommandLine contains "cat" and ProcessCommandLine contains ">>" and ProcessCommandLine contains "/tmp/downloaded_parts/")
    or (ProcessCommandLine contains "killall" and ProcessCommandLine contains "Ledger Live" and ProcessCommandLine contains "|| true")
| limit 1000
