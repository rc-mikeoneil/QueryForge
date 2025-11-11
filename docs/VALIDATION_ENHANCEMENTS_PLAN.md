# Query Validation Feature - Optional Enhancements Plan

**Date Created**: 2025-11-02
**Status**: Planning Phase
**Feature**: Query Validation (v1.0 Complete)

---

## Overview

This document outlines the implementation plan for optional enhancements to the Query Validation feature in QueryForge. The core validation feature is complete and functional, including:

- ✅ Shared validation framework (`src/src/queryforge/shared/validation.py`)
- ✅ Platform-specific validators (S1, KQL, CBC, Cortex)
- ✅ MCP tool integration (4 validation tools)
- ✅ Comprehensive validation categories (syntax, schema, operators, performance, best practices)

This plan covers **testing, documentation, and performance optimization** to ensure the feature is production-ready with comprehensive coverage.

---

## Table of Contents

1. [Phase 1: Unit Tests for Validators](#phase-1-unit-tests-for-validators)
2. [Phase 2: Documentation Updates](#phase-2-documentation-updates)
3. [Phase 3: Integration Tests](#phase-3-integration-tests)
4. [Phase 4: Performance Benchmarking](#phase-4-performance-benchmarking)
5. [Implementation Timeline](#implementation-timeline)
6. [Success Criteria](#success-criteria)
7. [Reference Information](#reference-information)

---

## Phase 1: Unit Tests for Validators

**Priority**: HIGH
**Estimated Effort**: 16-20 hours

### Files to Create

#### 1. `tests/test_shared_validation.py`

Test the shared validation framework components.

**Test Coverage**:
- `ValidationSeverity` enum functionality
- `ValidationIssue` dataclass and `to_dict()` method
- `ValidationResult` dataclass and `add_issue()` logic
- Utility functions:
  - `check_balanced_quotes()`
  - `check_balanced_parentheses()`
  - `check_dangerous_characters()`
  - `suggest_similar_fields()`
  - `format_field_list()`

**Example Test**:
```python
import pytest
from queryforge.shared.validation import (
    ValidationSeverity,
    ValidationIssue,
    ValidationResult,
    check_balanced_quotes,
    suggest_similar_fields
)

class TestValidationFramework:
    def test_validation_issue_to_dict(self):
        """Test ValidationIssue serialization."""
        issue = ValidationIssue(
            severity=ValidationSeverity.ERROR,
            category="syntax",
            message="Test error",
            location="filter[0]",
            suggestion="Fix this"
        )
        result = issue.to_dict()

        assert result["severity"] == "error"
        assert result["category"] == "syntax"
        assert result["message"] == "Test error"
        assert result["location"] == "filter[0]"
        assert result["suggestion"] == "Fix this"

    def test_validation_result_add_issue(self):
        """Test adding issues to ValidationResult."""
        result = ValidationResult(valid=True)

        # Add error - should set valid to False
        error = ValidationIssue(ValidationSeverity.ERROR, "syntax", "Error")
        result.add_issue(error)

        assert result.valid is False
        assert len(result.errors) == 1
        assert len(result.warnings) == 0

        # Add warning - should not change valid
        warning = ValidationIssue(ValidationSeverity.WARNING, "performance", "Warning")
        result.add_issue(warning)

        assert result.valid is False
        assert len(result.warnings) == 1

    def test_check_balanced_quotes(self):
        """Test quote balance checking."""
        # Balanced quotes
        assert check_balanced_quotes('field = "value"', '"') is None

        # Unbalanced quotes
        issue = check_balanced_quotes('field = "unclosed', '"')
        assert issue is not None
        assert "unbalanced" in issue.message.lower()
        assert issue.severity == ValidationSeverity.ERROR

    def test_suggest_similar_fields(self):
        """Test field name suggestions."""
        available = ["process_name", "process_id", "parent_name", "user_name"]

        # Exact substring match
        suggestions = suggest_similar_fields("proc", available)
        assert "process_name" in suggestions or "process_id" in suggestions

        # Partial match
        suggestions = suggest_similar_fields("name", available, max_suggestions=3)
        assert len(suggestions) <= 3
```

**Estimated Tests**: ~15 test methods

---

#### 2. `tests/test_s1_validator.py`

Test SentinelOne S1QL validator.

**Test Coverage**:
- Syntax validation (quotes, parentheses, IN clauses, backslashes)
- Schema validation (datasets, fields, data types)
- Operator validation (S1 operators, boolean operators)
- Performance checks (event filters, unbounded queries, regex, matchcase)
- Best practices (hash fields, OR vs IN, case sensitivity)
- Complexity scoring
- Result size estimation

**Example Test Structure**:
```python
import pytest
from queryforge.platforms.s1.validator import S1Validator

# Mock schema (reuse from test_s1_query_builder.py)
MOCK_S1_SCHEMA = {
    "datasets": {
        "processes": {
            "name": "processes",
            "fields": {
                "tgt.process.name": {"data_type": "string"},
                "tgt.file.md5": {"data_type": "string"},
                "EventType": {"data_type": "string"}
            }
        }
    },
    "common_fields": {},
    "operators": {
        "operators": [
            {"name": "equals", "symbols": ["="]},
            {"name": "in", "symbols": ["in"]},
            {"name": "contains", "symbols": ["contains"]}
        ]
    }
}

class TestS1Validator:
    @pytest.fixture
    def validator(self):
        """Create validator with mock schema."""
        return S1Validator(MOCK_S1_SCHEMA)

    # Syntax validation tests
    def test_valid_simple_query(self, validator):
        """Test validation of valid simple query."""
        query = "tgt.process.name = 'cmd.exe'"
        result = validator.validate(query, {"dataset": "processes"})

        assert result["valid"] is True
        assert result["validation_results"]["syntax"]["error_count"] == 0

    def test_unbalanced_single_quotes(self, validator):
        """Test detection of unbalanced single quotes."""
        query = "tgt.process.name = 'unclosed"
        result = validator.validate(query, {})

        assert result["valid"] is False
        errors = result["validation_results"]["syntax"]["errors"]
        assert any("quotes" in e["message"].lower() for e in errors)

    def test_dangerous_character_detection(self, validator):
        """Test detection of dangerous characters."""
        query = "tgt.process.name = 'cmd.exe'; DROP TABLE"
        result = validator.validate(query, {})

        assert result["valid"] is False
        errors = result["validation_results"]["syntax"]["errors"]
        assert any("dangerous" in e["message"].lower() for e in errors)

    def test_single_backslash_warning(self, validator):
        """Test warning for single backslashes in paths."""
        query = "tgt.process.name = 'C:\\Windows'"  # Should be C:\\\\Windows
        result = validator.validate(query, {})

        warnings = result["validation_results"]["syntax"]["warnings"]
        assert any("backslash" in w["message"].lower() for w in warnings)

    # Schema validation tests
    def test_unknown_field_error(self, validator):
        """Test error for unknown field."""
        query = "unknown_field = 'test'"
        metadata = {"dataset": "processes"}
        result = validator.validate(query, metadata)

        # Should have schema error
        errors = result["validation_results"]["schema"]["errors"]
        assert any("unknown_field" in e["message"].lower() for e in errors)

    def test_unknown_dataset_error(self, validator):
        """Test error for unknown dataset."""
        result = validator.validate("test", {"dataset": "unknown_dataset"})

        errors = result["validation_results"]["schema"]["errors"]
        assert any("dataset" in e["message"].lower() for e in errors)

    # Performance validation tests
    def test_unbounded_query_warning(self, validator):
        """Test warning for queries without filters."""
        result = validator.validate("", {"dataset": "processes", "conditions_count": 0})

        # Should have performance error for no filters
        errors = result["validation_results"]["performance"]["errors"]
        assert any("no filter" in e["message"].lower() for e in errors)

    def test_missing_time_filter_warning(self, validator):
        """Test warning for queries without time filters."""
        query = "tgt.process.name = 'cmd.exe'"
        metadata = {"dataset": "processes", "conditions_count": 1}
        result = validator.validate(query, metadata)

        warnings = result["validation_results"]["performance"]["warnings"]
        # Should warn about missing time filter
        assert any("time" in w["message"].lower() for w in warnings)

    # Metadata tests
    def test_complexity_score_simple_query(self, validator):
        """Test complexity score for simple query."""
        query = "tgt.process.name = 'cmd.exe'"
        result = validator.validate(query, {})

        assert "complexity_score" in result["metadata"]
        score = result["metadata"]["complexity_score"]
        assert 1 <= score <= 10
        assert score <= 3  # Simple query should have low score

    def test_result_size_estimation_with_limit(self, validator):
        """Test result size estimation."""
        query = "tgt.process.name = 'cmd.exe'"
        metadata = {"limit": 50}
        result = validator.validate(query, metadata)

        assert result["metadata"]["estimated_result_size"] == "small"
```

**Estimated Tests**: ~25 test methods

---

#### 3. `tests/test_kql_validator.py`

Test Microsoft Defender KQL validator.

**Test Coverage**:
- Syntax validation (pipes, SQL injection, clause ordering)
- Schema validation (tables, columns)
- Operator validation (KQL operators, case sensitivity)
- Performance checks (time filters, limits, summarize, regex)
- Best practices (filter ordering, field selection, time windowing)

**Key Test Cases**:
```python
class TestKQLValidator:
    @pytest.fixture
    def validator(self):
        return KQLValidator(MOCK_KQL_SCHEMA)

    def test_sql_injection_detection(self, validator):
        """Test detection of SQL injection patterns."""
        queries = [
            "DeviceProcessEvents | where FileName == 'cmd'; DROP TABLE users",
            "DeviceProcessEvents | where AccountName == 'admin' OR '1'='1'",
            "DeviceProcessEvents | where ProcessId == 1 UNION SELECT * FROM passwords"
        ]

        for query in queries:
            result = validator.validate(query, {"table": "DeviceProcessEvents"})
            assert result["valid"] is False
            errors = result["validation_results"]["syntax"]["errors"]
            assert len(errors) > 0

    def test_project_before_where_warning(self, validator):
        """Test warning when project appears before where."""
        query = "DeviceProcessEvents | project FileName | where FileName == 'cmd.exe'"
        result = validator.validate(query, {"table": "DeviceProcessEvents"})

        warnings = result["validation_results"]["best_practices"]["warnings"]
        assert any("project" in w["message"].lower() and "before" in w["message"].lower() for w in warnings)

    def test_case_sensitive_operator_info(self, validator):
        """Test info suggestion for case-sensitive operators."""
        query = "DeviceProcessEvents | where FileName == 'cmd.exe'"
        result = validator.validate(query, {"table": "DeviceProcessEvents"})

        info = result["validation_results"]["operators"]["info"]
        # Should suggest =~ for case-insensitive
        assert any("=~" in i["message"] or "case" in i["message"].lower() for i in info)
```

**Estimated Tests**: ~25 test methods

---

#### 4. `tests/test_cbc_validator.py`

Test Carbon Black Cloud validator.

**Test Coverage**:
- Syntax validation (field:value format, dangerous chars, boolean operators)
- Schema validation (search types, fields)
- Operator validation (AND/OR, unsupported operators)
- Performance checks (wildcards, keyword searches, leading wildcards)
- Best practices (hash fields, structured vs keyword, IP fields)

**Key Test Cases**:
```python
class TestCBCValidator:
    @pytest.fixture
    def validator(self):
        return CBCValidator(MOCK_CBC_SCHEMA)

    def test_field_value_format(self, validator):
        """Test validation of field:value format."""
        # Valid format
        query = "process_name:cmd.exe"
        result = validator.validate(query, {"search_type": "process_search"})
        assert result["valid"] is True

        # Invalid format
        query = "process_name=cmd.exe"  # Should use colon
        result = validator.validate(query, {})
        warnings = result["validation_results"]["syntax"]["warnings"]
        # May warn about unexpected format

    def test_leading_wildcard_warning(self, validator):
        """Test warning for leading wildcards."""
        query = 'process_name:"*cmd.exe"'
        result = validator.validate(query, {})

        warnings = result["validation_results"]["performance"]["warnings"]
        assert any("leading" in w["message"].lower() or "wildcard" in w["message"].lower() for w in warnings)

    def test_hash_field_suggestion(self, validator):
        """Test suggestion to use hash fields for hash values."""
        query = "5d41402abc4b2a76b9719d911017c592"  # MD5 hash as keyword
        metadata = {"search_type": "process_search", "recognised": [{"type": "keyword", "value": "5d41402abc4b2a76b9719d911017c592"}]}
        result = validator.validate(query, metadata)

        info = result["validation_results"]["best_practices"]["info"]
        # Should suggest using md5: field
```

**Estimated Tests**: ~25 test methods

---

#### 5. `tests/test_cortex_validator.py`

Test Cortex XDR validator.

**Test Coverage**:
- Syntax validation (XQL stages, pipes, dataset specification)
- Schema validation (datasets, fields, enum prefixes)
- Operator validation (XQL operators, case sensitivity)
- Performance checks (time filters, contains, regex, limits)
- Best practices (field selection, default fields, filter ordering)

**Key Test Cases**:
```python
class TestCortexValidator:
    @pytest.fixture
    def validator(self):
        return CortexValidator(MOCK_CORTEX_SCHEMA)

    def test_xql_stage_ordering(self, validator):
        """Test validation of XQL stage ordering."""
        # Correct order
        query = "dataset = xdr_data | filter field = 'value' | fields field | limit 100"
        result = validator.validate(query, {})
        assert result["valid"] is True

        # Incorrect order - filter after fields
        query = "dataset = xdr_data | fields field | filter field = 'value'"
        result = validator.validate(query, {})
        warnings = result["validation_results"]["syntax"]["warnings"]
        assert any("filter" in w["message"].lower() and "after" in w["message"].lower() for w in warnings)

    def test_missing_dataset_error(self, validator):
        """Test error for missing dataset specification."""
        query = "filter field = 'value'"  # No dataset
        result = validator.validate(query, {})

        errors = result["validation_results"]["performance"]["errors"]
        assert any("dataset" in e["message"].lower() for e in errors)

    def test_enum_prefix_warning(self, validator):
        """Test warning for enum fields without ENUM. prefix."""
        query = "dataset = xdr_data | filter event_type = 'PROCESS'"
        metadata = {
            "dataset": "xdr_data",
            "recognised": [{"field": "event_type", "value": "PROCESS"}]
        }
        result = validator.validate(query, metadata)

        warnings = result["validation_results"]["schema"]["warnings"]
        # Should warn about missing ENUM. prefix
```

**Estimated Tests**: ~25 test methods

---

### Test Execution

```bash
# Run all validator tests
pytest tests/test_*_validator.py -v

# Run with coverage
pytest tests/test_*_validator.py --cov=queryforge --cov-report=html

# Run specific platform
pytest tests/test_cortex_validator.py -v

# Run specific test class
pytest tests/test_cortex_validator.py::TestCortexValidator -v

# Run tests matching pattern
pytest tests/test_*_validator.py -k "syntax" -v
```

---

## Phase 2: Documentation Updates

**Priority**: HIGH
**Estimated Effort**: 8-10 hours

### 1. Update `docs/API_REFERENCE.md`

Add validation tool documentation for each platform.

**Location in File**: Add after each platform's `build_query` tool

**Template for Each Tool**:

```markdown
### `s1_validate_query`

Validate a SentinelOne S1QL query for syntax, schema compliance, and best practices.

**Purpose**: Pre-execution validation to catch errors, performance issues, and provide optimization suggestions before sending queries to the SentinelOne API.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `query` | string | Yes | - | The S1QL query string to validate |
| `dataset` | string | No | null | Optional dataset name for schema validation |
| `metadata` | object | No | null | Optional metadata from query building (enhances validation) |

**Metadata Object** (optional):
```json
{
  "dataset": "processes",
  "inferred_conditions": [
    {"field": "tgt.process.name", "operator": "=", "value": "cmd.exe"}
  ],
  "boolean_operator": "AND",
  "conditions_count": 1
}
```

**Returns**:
```json
{
  "valid": true,
  "query": "tgt.process.name = 'cmd.exe' AND EventType in:matchcase ('PROCESSCREATION')",
  "validation_results": {
    "syntax": {
      "valid": true,
      "errors": [],
      "warnings": [],
      "info": [],
      "error_count": 0,
      "warning_count": 0,
      "info_count": 0
    },
    "schema": {
      "valid": true,
      "errors": [],
      "warnings": [],
      "info": []
    },
    "operators": {
      "valid": true,
      "errors": [],
      "warnings": [],
      "info": []
    },
    "performance": {
      "valid": true,
      "errors": [],
      "warnings": [
        {
          "severity": "warning",
          "category": "performance",
          "message": "Query lacks time-based filtering - may return large result set",
          "location": null,
          "suggestion": "Add time filter to improve performance, e.g., createdAt > '2024-01-01T00:00:00Z'"
        }
      ],
      "info": []
    },
    "best_practices": {
      "valid": true,
      "errors": [],
      "warnings": [],
      "info": [
        {
          "severity": "info",
          "category": "best_practices",
          "message": "Consider adding event type filter for processes dataset",
          "location": null,
          "suggestion": "Event type filters significantly improve query performance"
        }
      ]
    }
  },
  "metadata": {
    "platform": "s1",
    "complexity_score": 2,
    "estimated_result_size": "large",
    "dataset": "processes",
    "boolean_operator": "AND",
    "conditions_count": 1,
    "has_time_filter": false,
    "uses_regex": false,
    "uses_in_clause": true
  }
}
```

**Validation Categories**:

1. **Syntax**: Quote balance, parentheses, dangerous characters, S1QL syntax rules
2. **Schema**: Dataset existence, field validation, data type compatibility
3. **Operators**: Operator validity, boolean operator correctness
4. **Performance**: Time filters, unbounded queries, expensive operations
5. **Best Practices**: Optimization suggestions, security recommendations

**Severity Levels**:
- **ERROR**: Critical issue preventing query execution
- **WARNING**: Non-critical issue that may cause problems
- **INFO**: Suggestions for improvement

**Example Usage**:

```python
# Basic validation
result = client.call_tool("s1_validate_query", {
    "query": "tgt.process.name = 'cmd.exe'",
    "dataset": "processes"
})

if not result["valid"]:
    print("Query validation failed!")

    # Show syntax errors
    for error in result["validation_results"]["syntax"]["errors"]:
        print(f"❌ {error['message']}")
        if error["suggestion"]:
            print(f"   💡 {error['suggestion']}")

    # Show schema errors
    for error in result["validation_results"]["schema"]["errors"]:
        print(f"❌ {error['message']}")
else:
    print("✅ Query is valid")

    # Show performance warnings
    for warning in result["validation_results"]["performance"]["warnings"]:
        print(f"⚠️  {warning['message']}")
        if warning["suggestion"]:
            print(f"   💡 {warning['suggestion']}")

    # Show best practice suggestions
    for info in result["validation_results"]["best_practices"]["info"]:
        print(f"ℹ️  {info['message']}")

# Validation with metadata (enhances validation accuracy)
build_result = client.call_tool("s1_build_query", {
    "dataset": "processes",
    "filters": [{"field": "tgt.process.name", "value": "cmd.exe"}]
})

validate_result = client.call_tool("s1_validate_query", {
    "query": build_result["query"],
    "metadata": build_result["metadata"]
})

# Workflow: Build → Validate → Execute
def safe_query_execution(client, query_params):
    # 1. Build query
    build_result = client.call_tool("s1_build_query", query_params)

    # 2. Validate query
    validate_result = client.call_tool("s1_validate_query", {
        "query": build_result["query"],
        "metadata": build_result["metadata"]
    })

    # 3. Check validation
    if not validate_result["valid"]:
        print("Query has errors - aborting execution")
        return None

    # 4. Warn about performance issues
    perf_errors = validate_result["validation_results"]["performance"]["errors"]
    if perf_errors:
        print(f"Warning: Query has {len(perf_errors)} performance issues")
        for error in perf_errors:
            print(f"  - {error['message']}")

    # 5. Execute query (send to actual S1 API)
    # return execute_query(build_result["query"])
    return build_result
```

**Common Validation Scenarios**:

```python
# Scenario 1: Unbalanced quotes
result = client.call_tool("s1_validate_query", {
    "query": "tgt.process.name = 'cmd.exe"  # Missing closing quote
})
# → Error: Unbalanced ' quotes detected

# Scenario 2: Unknown field
result = client.call_tool("s1_validate_query", {
    "query": "unknown_field = 'test'",
    "dataset": "processes"
})
# → Error: Field 'unknown_field' not found in dataset 'processes'
# → Suggestion: Did you mean: tgt.process.name, tgt.process.cmdline

# Scenario 3: Unbounded query
result = client.call_tool("s1_validate_query", {
    "query": "",
    "dataset": "processes"
})
# → Error: Query has no filters - would return all records

# Scenario 4: Performance optimization
result = client.call_tool("s1_validate_query", {
    "query": "tgt.process.name contains matchcase 'cmd'"
})
# → Info: Consider using hash fields for IOC searches
# → Warning: Query lacks time-based filtering
```

---
```

**Repeat for**:
- `kql_validate_query` (Microsoft Defender KQL)
- `cbc_validate_query` (Carbon Black Cloud)
- `cortex_validate_query` (Cortex XDR)

---

### 2. Create `docs/VALIDATION.md`

New comprehensive guide for query validation.

**File Structure**:

```markdown
# Query Validation Guide

## Table of Contents
1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Validation Categories](#validation-categories)
4. [Response Structure](#response-structure)
5. [Platform-Specific Notes](#platform-specific-notes)
6. [Integration Workflows](#integration-workflows)
7. [Error Handling](#error-handling)
8. [Best Practices](#best-practices)

---

## Overview

QueryForge provides comprehensive pre-execution validation for queries across all supported platforms (SentinelOne, Microsoft Defender KQL, Carbon Black Cloud, Cortex XDR).

### Why Validate Queries?

- **Catch Errors Early**: Detect syntax errors, invalid fields, and schema issues before sending to APIs
- **Optimize Performance**: Identify expensive operations and unbounded queries
- **Improve Security**: Detect injection attempts and dangerous patterns
- **Learn Best Practices**: Receive platform-specific optimization recommendations
- **Save API Quota**: Prevent failed queries from consuming API limits

### What Gets Validated?

1. **Syntax**: Query structure, balanced quotes/parentheses, dangerous characters
2. **Schema**: Field existence, data types, dataset compatibility
3. **Operators**: Operator validity and appropriate usage
4. **Performance**: Query complexity, result size estimation, expensive operations
5. **Best Practices**: Platform-specific recommendations and optimizations

---

## Quick Start

### Basic Validation

```python
# Import MCP client
from mcp import Client

client = Client("queryforge-mcp-server")

# Validate a query
result = client.call_tool("s1_validate_query", {
    "query": "tgt.process.name = 'cmd.exe'",
    "dataset": "processes"
})

# Check if valid
if result["valid"]:
    print("✅ Query is valid!")
else:
    print("❌ Query has errors")
    for error in result["validation_results"]["syntax"]["errors"]:
        print(f"  - {error['message']}")
```

### Validation with Query Building

```python
# Build a query
build_result = client.call_tool("s1_build_query", {
    "dataset": "processes",
    "natural_language_intent": "find cmd.exe processes"
})

# Validate the built query
validate_result = client.call_tool("s1_validate_query", {
    "query": build_result["query"],
    "metadata": build_result["metadata"]  # Enhances validation
})

# Use validation results
if not validate_result["valid"]:
    # Handle errors
    pass
elif validate_result["validation_results"]["performance"]["warnings"]:
    # Show performance warnings to user
    pass
```

---

## Validation Categories

### 1. Syntax Validation

Checks query structure and formatting.

**Common Checks**:
- Balanced quotes (single and double)
- Balanced parentheses and brackets
- Dangerous characters (`;`, `|`, etc.)
- Platform-specific syntax rules
- Injection patterns (SQL injection, XSS, etc.)

**Example Errors**:
```
❌ Unbalanced " quotes detected
   💡 Ensure all " quotes are properly closed or escaped

❌ Dangerous character ';' detected in query
   💡 Remove or escape the ';' character
```

### 2. Schema Validation

Validates against platform schemas.

**Common Checks**:
- Dataset/table existence
- Field existence in selected dataset
- Field data type compatibility
- Enum value validation
- Required field presence

**Example Errors**:
```
❌ Field 'procname' not found in dataset 'processes'
   💡 Did you mean: process_name, parent_process_name

❌ Dataset 'unknown_dataset' not found in S1 schema
   💡 Available datasets: processes, files, network_actions...
```

### 3. Operator Validation

Checks operator usage and compatibility.

**Common Checks**:
- Operator existence in platform
- Type compatibility (numeric operators on numeric fields)
- Boolean operator validity
- Case sensitivity considerations

**Example Errors**:
```
⚠️  String operator 'contains' used on numeric field 'process_id'
   💡 Use comparison operators (=, <, >, <=, >=) for numeric fields

❌ Invalid boolean operator 'XOR'
   💡 Use 'AND' or 'OR' to combine conditions
```

### 4. Performance Validation

Identifies potential performance issues.

**Common Checks**:
- Missing time filters
- Unbounded queries
- Excessive wildcards
- Unanchored regex patterns
- Large result limits
- Expensive operations (contains, regex, etc.)

**Example Warnings**:
```
⚠️  Query lacks time-based filtering - may scan large amounts of data
   💡 Add time filter: | where Timestamp > ago(7d)

⚠️  Leading wildcards (*value) are particularly slow
   💡 Avoid wildcards at the start of search terms if possible

⚠️  Query requests 10000 results - this may be slow
   💡 Consider reducing the limit or adding more specific filters
```

### 5. Best Practices

Platform-specific optimization recommendations.

**Common Suggestions**:
- Field ordering (specific before generic)
- Hash field usage for IOCs
- Index utilization
- Case-insensitive operators
- Field selection optimization

**Example Info**:
```
ℹ️  Consider using hash-specific fields like tgt.file.md5 for better performance
ℹ️  Use 'has' operator for whole-word matching (faster than 'contains')
ℹ️  Consider placing exact-match filters before 'contains' filters
```

---

## Response Structure

Complete structure of validation responses:

```typescript
{
  // Overall validation status
  "valid": boolean,

  // Original query
  "query": string,

  // Detailed results by category
  "validation_results": {
    "syntax": ValidationCategory,
    "schema": ValidationCategory,
    "operators": ValidationCategory,
    "performance": ValidationCategory,
    "best_practices": ValidationCategory
  },

  // Additional metadata
  "metadata": {
    "platform": "s1" | "kql" | "cbc" | "cortex",
    "complexity_score": number,  // 1-10
    "estimated_result_size": "small" | "medium" | "large" | "unbounded",
    // Platform-specific metadata
    ...
  }
}

// ValidationCategory structure
{
  "valid": boolean,
  "errors": ValidationIssue[],
  "warnings": ValidationIssue[],
  "info": ValidationIssue[],
  "error_count": number,
  "warning_count": number,
  "info_count": number
}

// ValidationIssue structure
{
  "severity": "error" | "warning" | "info",
  "category": "syntax" | "schema" | "operators" | "performance" | "best_practices",
  "message": string,
  "location": string | null,  // e.g., "filter[2].field"
  "suggestion": string | null
}
```

---

## Platform-Specific Notes

### SentinelOne (S1QL)

**Unique Validations**:
- Single quote requirement for strings
- Double backslash requirement for paths
- IN clause format: `in:matchcase ('val1', 'val2')`
- Event type filters for datasets

**Example**:
```python
# ❌ Wrong
query = "tgt.process.name = \"cmd.exe\""  # S1QL uses single quotes

# ✅ Correct
query = "tgt.process.name = 'cmd.exe'"

# ❌ Wrong
query = "path = 'C:\\Windows'"  # Single backslash

# ✅ Correct
query = "path = 'C:\\\\Windows'"  # Double backslash
```

### Microsoft Defender (KQL)

**Unique Validations**:
- Pipe operator ordering
- SQL injection pattern detection
- Clause sequencing (where before summarize)
- Time-based filtering recommendations

**Example**:
```python
# ❌ Inefficient
query = "DeviceProcessEvents | project FileName | where FileName == 'cmd.exe'"

# ✅ Better
query = "DeviceProcessEvents | where FileName == 'cmd.exe' | project FileName"
```

### Carbon Black Cloud (CBC)

**Unique Validations**:
- Field:value format requirement
- Search type compatibility
- Wildcard position warnings
- Boolean operator casing

**Example**:
```python
# ❌ Wrong
query = "process_name=cmd.exe"  # Missing colon

# ✅ Correct
query = "process_name:cmd.exe"

# ❌ Slow
query = "process_name:\"*cmd.exe\""  # Leading wildcard

# ✅ Better
query = "process_name:\"cmd.exe*\""  # Trailing wildcard
```

### Cortex XDR (XQL)

**Unique Validations**:
- XQL stage ordering (dataset → filter → fields → limit)
- ENUM. prefix for enum values
- Dataset specification requirement
- Pipe operator validation

**Example**:
```python
# ❌ Missing dataset
query = "filter field = 'value'"

# ✅ Correct
query = "dataset = xdr_data | filter field = 'value'"

# ❌ Missing ENUM prefix
query = "dataset = xdr_data | filter event_type = 'PROCESS'"

# ✅ Correct
query = "dataset = xdr_data | filter event_type = ENUM.PROCESS"
```

---

## Integration Workflows

### Workflow 1: Validate Before Execute

```python
def execute_s1_query(client, query_params):
    # Build query
    build_result = client.call_tool("s1_build_query", query_params)

    # Validate
    validate_result = client.call_tool("s1_validate_query", {
        "query": build_result["query"],
        "metadata": build_result["metadata"]
    })

    # Check validation
    if not validate_result["valid"]:
        raise ValueError("Query validation failed")

    # Execute (send to S1 API)
    return execute_against_s1_api(build_result["query"])
```

### Workflow 2: Interactive Validation

```python
def interactive_query_builder(client):
    while True:
        # Get user input
        intent = input("What do you want to find? ")

        # Build query
        build_result = client.call_tool("s1_build_query", {
            "natural_language_intent": intent
        })

        print(f"Generated query: {build_result['query']}")

        # Validate
        validate_result = client.call_tool("s1_validate_query", {
            "query": build_result["query"],
            "metadata": build_result["metadata"]
        })

        # Show results
        if not validate_result["valid"]:
            print("❌ Query has errors:")
            for error in get_all_errors(validate_result):
                print(f"  - {error['message']}")
            continue

        # Show warnings
        warnings = get_all_warnings(validate_result)
        if warnings:
            print(f"⚠️  Query has {len(warnings)} warnings:")
            for warning in warnings:
                print(f"  - {warning['message']}")

            if input("Execute anyway? (y/n): ").lower() != 'y':
                continue

        # Execute query
        results = execute_query(build_result["query"])
        print(f"Found {len(results)} results")
        return results
```

### Workflow 3: Batch Validation

```python
def validate_query_batch(client, queries):
    results = []

    for idx, query in enumerate(queries):
        validate_result = client.call_tool("s1_validate_query", {
            "query": query,
            "dataset": "processes"
        })

        results.append({
            "index": idx,
            "query": query,
            "valid": validate_result["valid"],
            "error_count": sum(
                validate_result["validation_results"][cat]["error_count"]
                for cat in validate_result["validation_results"]
            ),
            "warning_count": sum(
                validate_result["validation_results"][cat]["warning_count"]
                for cat in validate_result["validation_results"]
            )
        })

    # Summary
    valid_count = sum(1 for r in results if r["valid"])
    print(f"Validated {len(queries)} queries: {valid_count} valid, {len(queries) - valid_count} invalid")

    return results
```

---

## Error Handling

### Handling Validation Errors

```python
def handle_validation_result(result):
    """Process validation result and take appropriate action."""

    if result["valid"]:
        print("✅ Query is valid")

        # Still check for warnings and info
        total_warnings = sum(
            len(result["validation_results"][cat]["warnings"])
            for cat in result["validation_results"]
        )

        if total_warnings > 0:
            print(f"⚠️  {total_warnings} warnings found")
            # Decide whether to proceed
            return "proceed_with_warnings"

        return "proceed"

    else:
        print("❌ Query validation failed")

        # Collect all errors
        errors = []
        for category in result["validation_results"]:
            errors.extend(result["validation_results"][category]["errors"])

        # Group by category
        by_category = {}
        for error in errors:
            cat = error["category"]
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(error)

        # Display by category
        for category, category_errors in by_category.items():
            print(f"\n{category.upper()} Errors ({len(category_errors)}):")
            for error in category_errors:
                print(f"  ❌ {error['message']}")
                if error["location"]:
                    print(f"     Location: {error['location']}")
                if error["suggestion"]:
                    print(f"     💡 {error['suggestion']}")

        return "abort"
```

### Common Error Patterns

```python
# Pattern 1: Field name typo
validate_result = client.call_tool("s1_validate_query", {
    "query": "tgt.proces.name = 'cmd.exe'",  # Typo: proces instead of process
    "dataset": "processes"
})
# → Error: Field 'tgt.proces.name' not found
# → Suggestion: Did you mean: tgt.process.name

# Pattern 2: Wrong operator for field type
validate_result = client.call_tool("cortex_validate_query", {
    "query": "dataset = xdr_data | filter process_id contains '1234'",
    "dataset": "xdr_data"
})
# → Warning: String operator 'contains' used on numeric field
# → Suggestion: Use comparison operators (=, <, >, <=, >=)

# Pattern 3: Unbounded query
validate_result = client.call_tool("kql_validate_query", {
    "query": "DeviceProcessEvents"
})
# → Error: Query has no filters
# → Suggestion: Add filters to narrow results
```

---

## Best Practices

### 1. Always Validate Before Execution

```python
# ❌ Don't do this
query = build_query(params)
results = execute_query(query)  # May fail at API

# ✅ Do this
query = build_query(params)
validation = validate_query(query)
if validation["valid"]:
    results = execute_query(query)
else:
    handle_errors(validation)
```

### 2. Use Metadata for Enhanced Validation

```python
# Basic validation (less accurate)
validate_result = client.call_tool("s1_validate_query", {
    "query": query_string
})

# Enhanced validation (more accurate)
build_result = client.call_tool("s1_build_query", params)
validate_result = client.call_tool("s1_validate_query", {
    "query": build_result["query"],
    "metadata": build_result["metadata"]  # Provides field info, operators, etc.
})
```

### 3. Don't Ignore Warnings

```python
# Performance warnings can help optimize queries
for warning in result["validation_results"]["performance"]["warnings"]:
    if "time filter" in warning["message"].lower():
        # Add time filter to improve performance
        query = add_time_filter(query)
```

### 4. Log Validation Results

```python
import logging

def validate_and_log(query, dataset):
    result = client.call_tool("s1_validate_query", {
        "query": query,
        "dataset": dataset
    })

    # Log validation outcome
    logging.info(
        "Query validation: valid=%s, errors=%d, warnings=%d, complexity=%d",
        result["valid"],
        sum(len(result["validation_results"][c]["errors"]) for c in result["validation_results"]),
        sum(len(result["validation_results"][c]["warnings"]) for c in result["validation_results"]),
        result["metadata"]["complexity_score"]
    )

    return result
```

### 5. Use Complexity Scores for Query Optimization

```python
validate_result = client.call_tool("s1_validate_query", {
    "query": complex_query
})

complexity = validate_result["metadata"]["complexity_score"]

if complexity > 7:
    print("⚠️  High complexity query - may be slow")
    print(f"   Complexity score: {complexity}/10")

    # Suggest breaking into multiple queries
    print("   💡 Consider breaking into multiple simpler queries")
```

### 6. Validate Programmatically Generated Queries

```python
# When generating queries from templates or user input
def generate_query_from_template(template, values):
    query = template.format(**values)

    # Always validate generated queries
    validation = client.call_tool("s1_validate_query", {"query": query})

    if not validation["valid"]:
        raise ValueError(f"Generated invalid query: {query}")

    return query
```

---

## Troubleshooting

### Common Issues

**Issue**: Validation returns errors but query works in the platform UI

**Solution**:
- Validator may be more strict than platform
- Check for warnings vs errors (warnings won't block execution)
- Report discrepancies as potential validator bugs

**Issue**: Field suggestions not helpful

**Solution**:
- Ensure dataset/table is correctly specified
- Check schema is up-to-date (schemas may change)
- Use `*_get_fields` tools to see all available fields

**Issue**: Performance warnings for valid use cases

**Solution**:
- Warnings are suggestions, not requirements
- Some use cases legitimately need large result sets
- Document why warnings are acceptable in your context

---

## Additional Resources

- [API Reference](API_REFERENCE.md) - Complete MCP tool documentation
- [Testing Guide](TESTING.md) - How to test validation in your code
- [Platform Documentation]:
  - SentinelOne S1QL docs
  - Microsoft KQL documentation
  - Carbon Black Cloud query syntax
  - Cortex XDR XQL reference

---

**Last Updated**: 2025-11-02
**Version**: 1.0
```

---

### 3. Update `docs/TESTING.md`

Add section on validator testing.

**Insert After**: Existing test documentation

**Content to Add**:

```markdown
## Validator Testing

### Overview

The QueryForge validation feature includes comprehensive validators for all platforms (S1, KQL, CBC, Cortex). Testing validators ensures they correctly identify errors, warnings, and best practice violations.

### Test Structure

Validator tests follow the same patterns as query builder tests:

```
tests/
├── test_shared_validation.py    # Shared framework tests
├── test_s1_validator.py          # S1 validator tests
├── test_kql_validator.py         # KQL validator tests
├── test_cbc_validator.py         # CBC validator tests
└── test_cortex_validator.py      # Cortex validator tests
```

### Running Validator Tests

```bash
# All validator tests
pytest tests/test_*_validator.py -v

# Specific platform
pytest tests/test_s1_validator.py -v

# With coverage
pytest tests/test_*_validator.py --cov=queryforge.s1.validator --cov-report=html

# Specific validation category
pytest tests/test_s1_validator.py -k "syntax" -v
pytest tests/test_s1_validator.py -k "performance" -v
```

### Writing Validator Tests

#### Test Template

```python
import pytest
from queryforge.s1.validator import S1Validator

class TestS1ValidatorSyntax:
    @pytest.fixture
    def validator(self):
        return S1Validator(MOCK_S1_SCHEMA)

    def test_valid_query(self, validator):
        """Test that valid query passes validation."""
        query = "tgt.process.name = 'cmd.exe'"
        result = validator.validate(query, {"dataset": "processes"})

        assert result["valid"] is True
        assert result["validation_results"]["syntax"]["error_count"] == 0

    def test_specific_error(self, validator):
        """Test detection of specific error."""
        query = "invalid query"
        result = validator.validate(query, {})

        assert result["valid"] is False
        # Check for specific error
        errors = result["validation_results"]["syntax"]["errors"]
        assert any("expected text" in e["message"].lower() for e in errors)
```

#### Test Categories

Each validator should have tests for:

1. **Syntax Validation**
   - Valid queries
   - Unbalanced quotes
   - Unbalanced parentheses
   - Dangerous characters
   - Platform-specific syntax

2. **Schema Validation**
   - Valid fields
   - Unknown fields
   - Unknown datasets
   - Type mismatches
   - Field suggestions

3. **Operator Validation**
   - Valid operators
   - Invalid operators
   - Type compatibility
   - Boolean operators

4. **Performance Validation**
   - Unbounded queries
   - Missing time filters
   - Expensive operations
   - Large limits

5. **Best Practices**
   - Optimization suggestions
   - Security recommendations
   - Platform-specific tips

6. **Metadata**
   - Complexity scoring
   - Result size estimation
   - Platform-specific metadata

### Test Fixtures

Use the same mock schemas as query builder tests:

```python
# From test_s1_query_builder.py
from tests.test_s1_query_builder import MOCK_S1_SCHEMA

@pytest.fixture
def validator():
    return S1Validator(MOCK_S1_SCHEMA)
```

### Coverage Goals

- **Line Coverage**: > 95% for validator modules
- **Branch Coverage**: > 90% for validation logic
- **Test Count**: ~25 tests per platform validator
- **Edge Cases**: Test empty inputs, malformed data, boundary conditions

### Common Test Patterns

#### Testing Error Detection

```python
def test_error_detected(validator):
    """Test that error is properly detected."""
    query = "bad query"
    result = validator.validate(query, {})

    # Should be invalid
    assert result["valid"] is False

    # Should have error in correct category
    errors = result["validation_results"]["syntax"]["errors"]
    assert len(errors) > 0

    # Error should have helpful message
    error = errors[0]
    assert error["severity"] == "error"
    assert error["message"]  # Non-empty message
    assert error["suggestion"]  # Helpful suggestion
```

#### Testing Suggestions

```python
def test_field_suggestions(validator):
    """Test that field suggestions are provided."""
    query = "unknown_field = 'test'"
    metadata = {"dataset": "processes"}
    result = validator.validate(query, metadata)

    errors = result["validation_results"]["schema"]["errors"]
    error = next(e for e in errors if "unknown_field" in e["message"])

    # Should suggest similar fields
    assert error["suggestion"]
    assert "did you mean" in error["suggestion"].lower()
```

#### Testing Metadata

```python
def test_complexity_score(validator):
    """Test complexity score calculation."""
    simple_query = "field = 'value'"
    complex_query = " AND ".join([f"field{i} = 'val{i}'" for i in range(20)])

    simple_result = validator.validate(simple_query, {})
    complex_result = validator.validate(complex_query, {})

    # Complex query should have higher score
    assert complex_result["metadata"]["complexity_score"] > simple_result["metadata"]["complexity_score"]

    # Scores should be in valid range
    assert 1 <= simple_result["metadata"]["complexity_score"] <= 10
    assert 1 <= complex_result["metadata"]["complexity_score"] <= 10
```

### Performance Testing

See [Performance Benchmarking](#phase-4-performance-benchmarking) for benchmark tests.
```

---

### 4. Update `README.md`

Add validation feature to main features list.

**Location**: In the "Features" section

**Content to Add**:

```markdown
### ✨ Query Validation

Pre-execution validation with comprehensive feedback:

- **Syntax Checking**: Detect unbalanced quotes, dangerous characters, malformed syntax
- **Schema Compliance**: Validate field existence, data types, and dataset compatibility
- **Performance Warnings**: Identify unbounded queries, missing filters, expensive operations
- **Best Practice Suggestions**: Platform-specific optimization recommendations
- **Complexity Scoring**: Query complexity assessment (1-10 scale)
- **Result Size Estimation**: Predict result set size (small/medium/large/unbounded)

Supports all platforms: SentinelOne, Microsoft Defender KQL, Carbon Black Cloud, Cortex XDR

```python
# Validate before execution
result = client.call_tool("s1_validate_query", {
    "query": "tgt.process.name = 'cmd.exe'",
    "dataset": "processes"
})

if not result["valid"]:
    for error in result["validation_results"]["syntax"]["errors"]:
        print(f"❌ {error['message']}")
        print(f"💡 {error['suggestion']}")
```
```

---

## Phase 3: Integration Tests

**Priority**: MEDIUM
**Estimated Effort**: 6-8 hours

### File to Create: `tests/test_mcp_validation_integration.py`

Test MCP tool integration for validation tools.

**Structure**:

```python
"""
Integration tests for MCP validation tools.

Tests the MCP layer integration, tool registration, and end-to-end validation workflows.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from typing import Dict, Any

from fastmcp import FastMCP
from queryforge.server.server_runtime import ServerRuntime
from queryforge.server.server_tools_s1 import register_s1_tools
from queryforge.server.server_tools_kql import register_kql_tools
from queryforge.server.server_tools_cbc import register_cbc_tools
from queryforge.server.server_tools_cortex import register_cortex_tools

# Mock schemas
from tests.test_s1_query_builder import MOCK_S1_SCHEMA
from tests.test_cortex_query_builder import MOCK_CORTEX_SCHEMA


class TestMCPValidationToolRegistration:
    """Test that validation tools are properly registered with MCP."""

    @pytest.fixture
    def mock_runtime_s1(self):
        """Create mock ServerRuntime for S1."""
        runtime = Mock(spec=ServerRuntime)
        runtime.s1_cache = Mock()
        runtime.s1_cache.load = Mock(return_value=MOCK_S1_SCHEMA)
        runtime.ensure_rag_initialized = Mock(return_value=False)
        return runtime

    @pytest.fixture
    def mcp_with_s1(self, mock_runtime_s1):
        """Create MCP instance with S1 tools registered."""
        mcp = FastMCP("test-server")
        register_s1_tools(mcp, mock_runtime_s1)
        return mcp, mock_runtime_s1

    def test_s1_validate_query_tool_registered(self, mcp_with_s1):
        """Test that s1_validate_query tool is registered."""
        mcp, _ = mcp_with_s1
        tool_names = [tool.name for tool in mcp.list_tools()]

        assert "s1_validate_query" in tool_names

    def test_s1_validate_query_has_correct_params(self, mcp_with_s1):
        """Test that s1_validate_query has expected parameters."""
        mcp, _ = mcp_with_s1
        tools = {tool.name: tool for tool in mcp.list_tools()}
        validate_tool = tools["s1_validate_query"]

        # Check required parameters
        assert "query" in validate_tool.parameters
        # Optional parameters
        assert "dataset" in validate_tool.parameters or True  # May be optional

    def test_kql_validate_query_tool_registered(self):
        """Test KQL validation tool registration."""
        runtime = Mock(spec=ServerRuntime)
        runtime.kql_cache = Mock()
        runtime.kql_cache.load_or_refresh = Mock(return_value={})

        mcp = FastMCP("test-server")
        register_kql_tools(mcp, runtime)

        tool_names = [tool.name for tool in mcp.list_tools()]
        assert "kql_validate_query" in tool_names

    def test_cbc_validate_query_tool_registered(self):
        """Test CBC validation tool registration."""
        runtime = Mock(spec=ServerRuntime)
        runtime.cbc_cache = Mock()
        runtime.cbc_cache.load = Mock(return_value={})

        mcp = FastMCP("test-server")
        register_cbc_tools(mcp, runtime)

        tool_names = [tool.name for tool in mcp.list_tools()]
        assert "cbc_validate_query" in tool_names

    def test_cortex_validate_query_tool_registered(self):
        """Test Cortex validation tool registration."""
        runtime = Mock(spec=ServerRuntime)
        runtime.cortex_cache = Mock()
        runtime.cortex_cache.load = Mock(return_value=MOCK_CORTEX_SCHEMA)
        runtime.cortex_cache.datasets = Mock(return_value={"xdr_data": {}})

        mcp = FastMCP("test-server")
        register_cortex_tools(mcp, runtime)

        tool_names = [tool.name for tool in mcp.list_tools()]
        assert "cortex_validate_query" in tool_names


class TestS1ValidationToolExecution:
    """Test S1 validation tool execution."""

    @pytest.fixture
    def mock_runtime(self):
        runtime = Mock(spec=ServerRuntime)
        runtime.s1_cache = Mock()
        runtime.s1_cache.load = Mock(return_value=MOCK_S1_SCHEMA)
        return runtime

    def test_valid_query_returns_success(self, mock_runtime):
        """Test validation of valid query."""
        # This is a simplified test - actual MCP tool execution would require
        # more complex setup with FastMCP's testing utilities

        from queryforge.platforms.s1.validator import S1Validator

        validator = S1Validator(MOCK_S1_SCHEMA)
        result = validator.validate(
            "tgt.process.name = 'cmd.exe'",
            {"dataset": "processes"}
        )

        assert result["valid"] is True
        assert "validation_results" in result
        assert "metadata" in result

    def test_invalid_query_returns_errors(self, mock_runtime):
        """Test validation of invalid query."""
        from queryforge.platforms.s1.validator import S1Validator

        validator = S1Validator(MOCK_S1_SCHEMA)
        result = validator.validate(
            "invalid query with unbalanced quotes: '",
            {}
        )

        assert result["valid"] is False
        assert len(result["validation_results"]["syntax"]["errors"]) > 0

    def test_validation_with_metadata(self, mock_runtime):
        """Test validation with query metadata."""
        from queryforge.platforms.s1.validator import S1Validator

        validator = S1Validator(MOCK_S1_SCHEMA)

        metadata = {
            "dataset": "processes",
            "inferred_conditions": [
                {"field": "tgt.process.name", "operator": "=", "value": "cmd.exe"}
            ],
            "conditions_count": 1
        }

        result = validator.validate("tgt.process.name = 'cmd.exe'", metadata)

        assert "metadata" in result
        assert result["metadata"]["dataset"] == "processes"


class TestValidationWorkflows:
    """Test common validation workflows."""

    def test_build_then_validate_workflow(self):
        """Test building a query then validating it."""
        from queryforge.platforms.s1.query_builder import build_s1_query
        from queryforge.platforms.s1.validator import S1Validator

        # Build query
        query, metadata = build_s1_query(
            schema=MOCK_S1_SCHEMA,
            dataset="processes",
            filters=[{"field": "tgt.process.name", "value": "cmd.exe"}]
        )

        # Validate query
        validator = S1Validator(MOCK_S1_SCHEMA)
        result = validator.validate(query, metadata)

        # Should be valid since it was built correctly
        assert result["valid"] is True

    def test_validation_catches_manual_query_errors(self):
        """Test that validation catches errors in manually written queries."""
        from queryforge.platforms.s1.validator import S1Validator

        validator = S1Validator(MOCK_S1_SCHEMA)

        # Manually written query with syntax error
        bad_query = "tgt.process.name = 'unclosed quote"
        result = validator.validate(bad_query, {})

        assert result["valid"] is False
        assert len(result["validation_results"]["syntax"]["errors"]) > 0


class TestValidationErrorHandling:
    """Test error handling in validation tools."""

    def test_validation_handles_schema_load_failure(self):
        """Test graceful handling of schema loading failures."""
        from queryforge.platforms.s1.validator import S1Validator

        # Empty schema
        validator = S1Validator({})

        # Should not crash, but may return validation warnings
        result = validator.validate("query", {"dataset": "unknown"})

        # Should complete without exception
        assert "validation_results" in result

    def test_validation_handles_malformed_input(self):
        """Test handling of malformed input."""
        from queryforge.platforms.s1.validator import S1Validator

        validator = S1Validator(MOCK_S1_SCHEMA)

        # Empty query
        result = validator.validate("", {})
        assert "validation_results" in result

        # Very long query
        long_query = "a" * 20000
        result = validator.validate(long_query, {})
        assert "validation_results" in result


class TestValidationResponseFormat:
    """Test that validation responses match expected format."""

    def test_response_has_required_fields(self):
        """Test that validation response has all required fields."""
        from queryforge.platforms.s1.validator import S1Validator

        validator = S1Validator(MOCK_S1_SCHEMA)
        result = validator.validate("test", {})

        # Top-level fields
        assert "valid" in result
        assert isinstance(result["valid"], bool)
        assert "query" in result
        assert "validation_results" in result
        assert "metadata" in result

        # Validation results categories
        categories = ["syntax", "schema", "operators", "performance", "best_practices"]
        for category in categories:
            assert category in result["validation_results"]
            cat_result = result["validation_results"][category]
            assert "valid" in cat_result
            assert "errors" in cat_result
            assert "warnings" in cat_result
            assert "info" in cat_result

    def test_issue_structure(self):
        """Test that validation issues have correct structure."""
        from queryforge.platforms.s1.validator import S1Validator

        validator = S1Validator(MOCK_S1_SCHEMA)
        result = validator.validate("bad query with 'unbalanced quotes", {})

        # Get an error
        errors = result["validation_results"]["syntax"]["errors"]
        assert len(errors) > 0

        error = errors[0]
        assert "severity" in error
        assert error["severity"] == "error"
        assert "category" in error
        assert "message" in error
        assert isinstance(error["message"], str)
        # location and suggestion are optional
        assert "location" in error
        assert "suggestion" in error


# Run with: pytest tests/test_mcp_validation_integration.py -v
```

**Estimated Tests**: ~20 test methods

---

## Phase 4: Performance Benchmarking

**Priority**: LOW
**Estimated Effort**: 4-6 hours

### 1. Add Dependency

**Update**: `requirements.txt` or create `requirements-dev.txt`

```
# Development dependencies
pytest>=7.0.0
pytest-cov>=4.0.0
pytest-benchmark>=4.0.0  # NEW: For performance benchmarks
```

### 2. Create Benchmark File

**File**: `tests/benchmarks/test_validator_performance.py`

```python
"""
Performance benchmarks for query validators.

Run with:
    pytest tests/benchmarks/ --benchmark-only
    pytest tests/benchmarks/ --benchmark-only --benchmark-verbose
    pytest tests/benchmarks/ --benchmark-autosave
"""

import pytest
from queryforge.platforms.s1.validator import S1Validator
from queryforge.platforms.kql.validator import KQLValidator
from queryforge.platforms.cbc.validator import CBCValidator
from queryforge.platforms.cortex.validator import CortexValidator

# Mock schemas (reuse from test files)
from tests.test_s1_query_builder import MOCK_S1_SCHEMA
from tests.test_cortex_query_builder import MOCK_CORTEX_SCHEMA

# Mock CBC and KQL schemas
MOCK_CBC_SCHEMA = {
    "search_types": {"process_search": "Process events"},
    "process_search_fields": {"process_name": {"type": "string"}}
}

MOCK_KQL_SCHEMA = {
    "DeviceProcessEvents": {
        "columns": [{"name": "FileName", "type": "string"}]
    }
}


# ============================================================================
# S1 Validator Benchmarks
# ============================================================================

@pytest.fixture
def s1_validator():
    return S1Validator(MOCK_S1_SCHEMA)


@pytest.fixture
def simple_s1_query():
    return "tgt.process.name = 'cmd.exe'"


@pytest.fixture
def complex_s1_query():
    """Query with 50 filters."""
    filters = [f"tgt.process.field{i} = 'value{i}'" for i in range(50)]
    return " AND ".join(filters)


def test_s1_validation_simple_query(benchmark, s1_validator, simple_s1_query):
    """Benchmark validation of simple S1 query."""
    result = benchmark(s1_validator.validate, simple_s1_query, {})
    assert "valid" in result


def test_s1_validation_complex_query(benchmark, s1_validator, complex_s1_query):
    """Benchmark validation of complex S1 query with 50 filters."""
    result = benchmark(s1_validator.validate, complex_s1_query, {})
    assert "valid" in result


def test_s1_syntax_validation_only(benchmark, s1_validator, simple_s1_query):
    """Benchmark S1 syntax validation in isolation."""
    result = benchmark(s1_validator.validate_syntax, simple_s1_query)
    assert isinstance(result, list)


def test_s1_schema_validation_only(benchmark, s1_validator, simple_s1_query):
    """Benchmark S1 schema validation in isolation."""
    metadata = {"dataset": "processes"}
    result = benchmark(s1_validator.validate_schema, simple_s1_query, metadata)
    assert isinstance(result, list)


def test_s1_performance_validation_only(benchmark, s1_validator, simple_s1_query):
    """Benchmark S1 performance validation in isolation."""
    result = benchmark(s1_validator.validate_performance, simple_s1_query, {})
    assert isinstance(result, list)


# ============================================================================
# KQL Validator Benchmarks
# ============================================================================

@pytest.fixture
def kql_validator():
    return KQLValidator(MOCK_KQL_SCHEMA)


@pytest.fixture
def simple_kql_query():
    return "DeviceProcessEvents | where FileName == 'cmd.exe'"


@pytest.fixture
def complex_kql_query():
    """KQL query with many filters."""
    filters = [f"Field{i} == 'value{i}'" for i in range(50)]
    return f"DeviceProcessEvents | where {' and '.join(filters)}"


def test_kql_validation_simple_query(benchmark, kql_validator, simple_kql_query):
    """Benchmark validation of simple KQL query."""
    result = benchmark(kql_validator.validate, simple_kql_query, {"table": "DeviceProcessEvents"})
    assert "valid" in result


def test_kql_validation_complex_query(benchmark, kql_validator, complex_kql_query):
    """Benchmark validation of complex KQL query."""
    result = benchmark(kql_validator.validate, complex_kql_query, {"table": "DeviceProcessEvents"})
    assert "valid" in result


# ============================================================================
# CBC Validator Benchmarks
# ============================================================================

@pytest.fixture
def cbc_validator():
    return CBCValidator(MOCK_CBC_SCHEMA)


@pytest.fixture
def simple_cbc_query():
    return "process_name:cmd.exe"


@pytest.fixture
def complex_cbc_query():
    """CBC query with many terms."""
    terms = [f"field{i}:value{i}" for i in range(50)]
    return " AND ".join(terms)


def test_cbc_validation_simple_query(benchmark, cbc_validator, simple_cbc_query):
    """Benchmark validation of simple CBC query."""
    result = benchmark(cbc_validator.validate, simple_cbc_query, {"search_type": "process_search"})
    assert "valid" in result


def test_cbc_validation_complex_query(benchmark, cbc_validator, complex_cbc_query):
    """Benchmark validation of complex CBC query."""
    result = benchmark(cbc_validator.validate, complex_cbc_query, {"search_type": "process_search"})
    assert "valid" in result


# ============================================================================
# Cortex Validator Benchmarks
# ============================================================================

@pytest.fixture
def cortex_validator():
    return CortexValidator(MOCK_CORTEX_SCHEMA)


@pytest.fixture
def simple_cortex_query():
    return "dataset = xdr_data | filter agent_hostname = 'test'"


@pytest.fixture
def complex_cortex_query():
    """Cortex query with many filters."""
    filters = [f"filter field{i} = 'value{i}'" for i in range(50)]
    return f"dataset = xdr_data | {' | '.join(filters)}"


def test_cortex_validation_simple_query(benchmark, cortex_validator, simple_cortex_query):
    """Benchmark validation of simple Cortex query."""
    result = benchmark(cortex_validator.validate, simple_cortex_query, {"dataset": "xdr_data"})
    assert "valid" in result


def test_cortex_validation_complex_query(benchmark, cortex_validator, complex_cortex_query):
    """Benchmark validation of complex Cortex query."""
    result = benchmark(cortex_validator.validate, complex_cortex_query, {"dataset": "xdr_data"})
    assert "valid" in result


# ============================================================================
# Cross-Platform Comparison
# ============================================================================

@pytest.mark.parametrize("platform,validator,query", [
    ("s1", pytest.lazy_fixture("s1_validator"), pytest.lazy_fixture("simple_s1_query")),
    ("kql", pytest.lazy_fixture("kql_validator"), pytest.lazy_fixture("simple_kql_query")),
    ("cbc", pytest.lazy_fixture("cbc_validator"), pytest.lazy_fixture("simple_cbc_query")),
    ("cortex", pytest.lazy_fixture("cortex_validator"), pytest.lazy_fixture("simple_cortex_query")),
])
def test_cross_platform_validation_comparison(benchmark, platform, validator, query):
    """Compare validation performance across all platforms."""
    result = benchmark(validator.validate, query, {})
    assert "valid" in result
    print(f"\n{platform} validation completed")


# ============================================================================
# Run Instructions
# ============================================================================
"""
To run benchmarks:

# All benchmarks
pytest tests/benchmarks/ --benchmark-only

# Verbose output with statistics
pytest tests/benchmarks/ --benchmark-only --benchmark-verbose

# Save results for comparison
pytest tests/benchmarks/ --benchmark-only --benchmark-autosave

# Compare with previous run
pytest tests/benchmarks/ --benchmark-only --benchmark-compare

# Only S1 benchmarks
pytest tests/benchmarks/ --benchmark-only -k "s1"

# Generate histogram
pytest tests/benchmarks/ --benchmark-only --benchmark-histogram

Performance Targets:
- Simple query validation: < 10ms
- Complex query validation (50 filters): < 50ms
- Syntax validation only: < 2ms
- Schema validation only: < 5ms
"""
```

### 3. Running Benchmarks

```bash
# Basic benchmark run
pytest tests/benchmarks/ --benchmark-only

# With detailed statistics
pytest tests/benchmarks/ --benchmark-only --benchmark-verbose

# Save results
pytest tests/benchmarks/ --benchmark-only --benchmark-autosave

# Compare with previous run
pytest tests/benchmarks/ --benchmark-only --benchmark-compare

# Generate HTML report
pytest tests/benchmarks/ --benchmark-only --benchmark-histogram
```

### 4. Performance Targets

**Targets to Validate**:
- Simple query validation: **< 10ms**
- Complex query (50 filters): **< 50ms**
- Syntax validation only: **< 2ms**
- Schema validation only: **< 5ms**
- Performance validation only: **< 3ms**

**If targets not met**:
1. Profile slow validation methods
2. Optimize regex patterns
3. Cache expensive operations
4. Consider lazy evaluation

---

## Implementation Timeline

### Recommended Schedule

**Week 1: Unit Tests Foundation**
- Day 1-2: `test_shared_validation.py` (15 tests)
- Day 3-4: `test_s1_validator.py` (25 tests)
- Day 5: `test_kql_validator.py` (start, 15 tests)

**Week 2: Complete Unit Tests**
- Day 1-2: `test_kql_validator.py` (complete, 25 total)
- Day 3-4: `test_cbc_validator.py` (25 tests)
- Day 5: `test_cortex_validator.py` (start, 15 tests)

**Week 3: Documentation**
- Day 1: `test_cortex_validator.py` (complete, 25 total)
- Day 2: Update `API_REFERENCE.md`
- Day 3-4: Create `VALIDATION.md`
- Day 5: Update `TESTING.md` and `README.md`

**Week 4: Integration & Performance**
- Day 1-2: `test_mcp_validation_integration.py` (20 tests)
- Day 3: `test_validator_performance.py` (benchmarks)
- Day 4: Run benchmarks, optimize if needed
- Day 5: Final review, bug fixes

**Total**: 4 weeks (part-time) or 1 week (full-time focus)

---

## Success Criteria

### Testing
- ✅ **115+ unit tests** created and passing
- ✅ **20+ integration tests** created and passing
- ✅ **>95% code coverage** for validator modules
- ✅ All validation categories tested (syntax, schema, operators, performance, best practices)
- ✅ Edge cases covered (empty queries, malformed input, missing metadata)

### Documentation
- ✅ All 4 validation tools documented in `API_REFERENCE.md`
- ✅ Comprehensive `VALIDATION.md` guide created (~300 lines)
- ✅ Testing documentation updated in `TESTING.md`
- ✅ README updated with validation features
- ✅ Code examples provided for each platform

### Performance
- ✅ Benchmarks created for all validators (20+ benchmark functions)
- ✅ Simple query validation < 10ms
- ✅ Complex query validation < 50ms
- ✅ Syntax validation < 2ms
- ✅ Schema validation < 5ms
- ✅ No performance regressions introduced

### Quality
- ✅ All tests use pytest best practices
- ✅ Test names are descriptive and clear
- ✅ Fixtures used appropriately
- ✅ Mocks isolate units under test
- ✅ Documentation is clear and has examples
- ✅ Benchmarks are reproducible

---

## Reference Information

### Existing Test Patterns

**From `tests/base_query_builder_test.py`**:
- `BaseQueryBuilderTest` - Core test class
- `SecurityValidationMixin` - Injection prevention tests
- `IOCExtractionMixin` - IOC extraction tests
- `LimitValidationMixin` - Limit boundary tests
- `BooleanOperatorMixin` - Boolean operator tests

**Test Inheritance Example**:
```python
class TestCortexQueryBuilder(
    BaseQueryBuilderTest,
    SecurityValidationMixin,
    IOCExtractionMixin,
    LimitValidationMixin,
    BooleanOperatorMixin
):
    """Inherits all base tests + adds platform-specific tests."""
```

### Mock Schema Examples

**S1 Mock Schema** (from `test_s1_query_builder.py`):
```python
MOCK_S1_SCHEMA = {
    "datasets": {
        "processes": {
            "name": "processes",
            "fields": {
                "tgt.process.name": {"data_type": "string"},
                "tgt.file.md5": {"data_type": "string"}
            }
        }
    },
    "common_fields": {},
    "operators": {
        "operators": [
            {"name": "equals", "symbols": ["="]}
        ]
    }
}
```

**Cortex Mock Schema** (from `test_cortex_query_builder.py`):
```python
MOCK_CORTEX_SCHEMA = {
    "datasets": {
        "xdr_data": {
            "name": "xdr_data",
            "default_fields": ["_time", "agent_hostname"]
        }
    },
    "xdr_data_fields": {
        "_time": {"type": "datetime"},
        "agent_hostname": {"type": "string"}
    }
}
```

### Common Test Helpers

**Injection Test Cases**:
```python
[
    "; DROP TABLE users",
    "' OR '1'='1",
    "1' UNION SELECT * FROM passwords--",
    "<script>alert('xss')</script>",
    "../../../etc/passwd"
]
```

**IOC Test Cases**:
```python
{
    "ipv4": "192.168.1.100",
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
}
```

### Running Tests

```bash
# All tests
pytest tests/

# Specific file
pytest tests/test_cortex_validator.py

# Specific test
pytest tests/test_cortex_validator.py::TestCortexValidator::test_valid_query

# With coverage
pytest tests/ --cov=queryforge --cov-report=html

# Pattern matching
pytest tests/ -k "syntax"
pytest tests/ -k "validation"

# Verbose
pytest tests/ -v

# Stop on first failure
pytest tests/ -x
```

---

## Files Summary

### New Files to Create (9)

**Tests** (7 files):
1. `tests/test_shared_validation.py` (~15 tests)
2. `tests/test_s1_validator.py` (~25 tests)
3. `tests/test_kql_validator.py` (~25 tests)
4. `tests/test_cbc_validator.py` (~25 tests)
5. `tests/test_cortex_validator.py` (~25 tests)
6. `tests/test_mcp_validation_integration.py` (~20 tests)
7. `tests/benchmarks/test_validator_performance.py` (~20 benchmarks)

**Documentation** (2 files):
8. `docs/VALIDATION.md` (~300 lines)
9. `requirements-dev.txt` or update `requirements.txt`

### Files to Modify (4)

1. `docs/API_REFERENCE.md` - Add 4 validation tool sections
2. `docs/TESTING.md` - Add validator testing section
3. `README.md` - Update features list
4. `requirements.txt` - Add pytest-benchmark (or use requirements-dev.txt)

---

## Estimated Effort

**Phase 1 (Unit Tests)**: 16-20 hours
- Shared framework tests: 3 hours
- S1 validator tests: 4 hours
- KQL validator tests: 4 hours
- CBC validator tests: 4 hours
- Cortex validator tests: 4 hours
- Bug fixes from test findings: 2 hours

**Phase 2 (Documentation)**: 8-10 hours
- API_REFERENCE.md updates: 3 hours
- VALIDATION.md creation: 4 hours
- TESTING.md updates: 1 hour
- README.md updates: 0.5 hours
- Review and polish: 1.5 hours

**Phase 3 (Integration Tests)**: 6-8 hours
- Test infrastructure setup: 2 hours
- Tool registration tests: 2 hours
- Workflow tests: 2 hours
- Error handling tests: 2 hours

**Phase 4 (Performance)**: 4-6 hours
- Benchmark setup: 1 hour
- Writing benchmarks: 2 hours
- Running and analyzing: 1 hour
- Optimization if needed: 2 hours

**Total**: 34-44 hours (~4-5 weeks part-time or 1 week full-time)

---

## Notes

- All new code follows existing QueryForge patterns and conventions
- Tests use pytest with same structure as existing tests
- Documentation matches existing documentation style
- Performance targets are realistic based on validator complexity
- Can be implemented incrementally (phase by phase)
- Each phase delivers standalone value

---

**Plan Created**: 2025-11-02
**For**: QueryForge Query Validation Feature
**Status**: Ready for implementation
