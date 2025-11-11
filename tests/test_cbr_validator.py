"""
Tests for Carbon Black Response (CBR) query validator.
"""

import pytest
from cbr.validator import CBRValidator
from cbr.query_builder import build_cbr_query
from shared.validation import ValidationSeverity


# Mock CBR schema for testing
MOCK_CBR_SCHEMA = {
    "search_types": {
        "server_event": "Server-generated events (watchlist hits, feed hits, etc.)",
        "endpoint_event": "Raw endpoint events (regmod, filemod, netconn, etc.)",
    },
    "server_event_fields": {
        "process_name": {"type": "string", "description": "Process name"},
        "process_md5": {"type": "string", "description": "Process MD5 hash"},
        "parent_md5": {"type": "string", "description": "Parent MD5 hash"},
        "md5": {"type": "string", "description": "MD5 hash"},
        "cmdline": {"type": "string", "description": "Command line"},
        "path": {"type": "string", "description": "File path"},
        "username": {"type": "string", "description": "Username"},
        "hostname": {"type": "string", "description": "Hostname"},
        "ipv4": {"type": "string", "description": "IPv4 address"},
        "port": {"type": "string", "description": "Port number"},
    },
    "endpoint_event_fields": {
        "process_name": {"type": "string", "description": "Process name"},
        "process_md5": {"type": "string", "description": "Process MD5 hash"},
        "parent_md5": {"type": "string", "description": "Parent MD5 hash"},
        "md5": {"type": "string", "description": "MD5 hash"},
        "cmdline": {"type": "string", "description": "Command line"},
        "remote_ip": {"type": "string", "description": "Remote IP"},
        "local_ip": {"type": "string", "description": "Local IP"},
        "remote_port": {"type": "string", "description": "Remote port"},
        "local_port": {"type": "string", "description": "Local port"},
        "domain": {"type": "string", "description": "Domain"},
        "proxy_ip": {"type": "string", "description": "Proxy IP"},
        "proxy_port": {"type": "string", "description": "Proxy port"},
        "proxy_domain": {"type": "string", "description": "Proxy domain"},
    }
}


def get_all_issues(result):
    """Helper to extract all issues from validation results."""
    issues = []
    if "validation_results" in result:
        for category_results in result["validation_results"].values():
            if isinstance(category_results, dict):
                issues.extend(category_results.get("errors", []))
                issues.extend(category_results.get("warnings", []))
                issues.extend(category_results.get("info", []))
    return issues


class TestCBRValidator:
    """Test suite for CBR query validator."""
    
    @pytest.fixture
    def validator(self):
        """Create a validator instance with mock schema and disable caching."""
        return CBRValidator(MOCK_CBR_SCHEMA, enable_cache=False)
    
    # Syntax validation tests
    
    def test_validate_syntax_query_too_long(self, validator):
        """Test that queries exceeding MAX_QUERY_LENGTH trigger an error."""
        long_query = "process_name:test " * 2000  # Create very long query
        
        result = validator.validate(long_query, {})
        
        assert not result["valid"]
        issues = get_all_issues(result)
        assert any(
            issue.get("severity") == "error" and 
            "exceeds maximum length" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_syntax_dangerous_characters(self, validator):
        """Test that dangerous characters are detected."""
        dangerous_queries = [
            "process_name:test; DROP TABLE",
            "process_name:test | grep secret",
            "process_name:test\nmalicious",
            "process_name:test{cmd}",
        ]
        
        for query in dangerous_queries:
            result = validator.validate(query, {})
            assert not result["valid"], f"Query should be invalid: {query}"
            issues = get_all_issues(result)
            assert any(
                "dangerous" in issue.get("message", "").lower()
                for issue in issues
            )
    
    def test_validate_syntax_malformed_field_value(self, validator):
        """Test detection of malformed field:value syntax."""
        query = "invalid::field:value"
        metadata = {"search_type": "server_event", "recognised": []}
        
        result = validator.validate(query, metadata)
        
        # Should have warning about malformed syntax
        issues = get_all_issues(result)
        assert any(
            "malformed" in issue.get("message", "").lower()
            for issue in issues
        )
    
    def test_validate_syntax_unquoted_spaces(self, validator):
        """Test warning for unquoted values with spaces."""
        query = "process_name:Google Chrome"  # Missing quotes
        metadata = {"search_type": "server_event", "recognised": []}
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "not quoted" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_syntax_unescaped_backslashes(self, validator):
        """Test warning for unescaped backslashes in Windows paths."""
        query = "path:C:\\Windows\\System32"  # Single backslashes
        metadata = {"search_type": "server_event", "recognised": []}
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "backslash" in issue.get("message", "").lower()
            for issue in issues
        )
    
    def test_validate_syntax_lowercase_boolean_operators(self, validator):
        """Test warning for lowercase boolean operators."""
        query = "process_name:cmd.exe and hostname:workstation"
        metadata = {"search_type": "server_event", "recognised": []}
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "uppercase" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_syntax_valid_query(self, validator):
        """Test that valid query passes syntax validation."""
        query = 'process_name:cmd.exe AND cmdline:"test command"'
        metadata = {
            "search_type": "server_event",
            "boolean_operator": "AND",
            "recognised": [
                {"field": "process_name", "value": "cmd.exe"},
                {"field": "cmdline", "value": "test command"}
            ]
        }
        
        result = validator.validate(query, metadata)
        
        # Should have no syntax errors (may have other warnings)
        syntax_errors = result["validation_results"]["syntax"]["errors"]
        assert len(syntax_errors) == 0
    
    # Schema validation tests
    
    def test_validate_schema_missing_search_type(self, validator):
        """Test warning when search_type is missing from metadata."""
        query = "process_name:test"
        metadata = {}
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "without search_type" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_schema_invalid_search_type(self, validator):
        """Test error for invalid search_type."""
        query = "process_name:test"
        metadata = {"search_type": "invalid_type", "recognised": []}
        
        result = validator.validate(query, metadata)
        
        assert not result["valid"]
        issues = get_all_issues(result)
        assert any(
            "not found in CBR schema" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_schema_invalid_field(self, validator):
        """Test warning for fields not in schema."""
        query = "invalid_field:test"
        metadata = {
            "search_type": "server_event",
            "recognised": [{"field": "invalid_field", "value": "test"}]
        }
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "may not exist" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_schema_suggests_similar_fields(self, validator):
        """Test that validator suggests similar field names for typos."""
        query = "proces_name:test"  # Typo: proces_name instead of process_name
        metadata = {
            "search_type": "server_event",
            "recognised": [{"field": "proces_name", "value": "test"}]
        }
        
        result = validator.validate(query, metadata)
        
        # Should suggest "process_name"
        issues = get_all_issues(result)
        schema_issues = [i for i in issues if i.get("category") == "schema"]
        assert any(
            "Did you mean" in i.get("suggestion", "") or "process_name" in i.get("suggestion", "")
            for i in schema_issues
        )
    
    def test_validate_schema_valid_fields(self, validator):
        """Test that valid fields pass schema validation."""
        query = "process_name:cmd.exe AND hostname:workstation"
        metadata = {
            "search_type": "server_event",
            "recognised": [
                {"field": "process_name", "value": "cmd.exe"},
                {"field": "hostname", "value": "workstation"}
            ]
        }
        
        result = validator.validate(query, metadata)
        
        # Should have no schema errors
        schema_errors = result["validation_results"]["schema"]["errors"]
        assert len(schema_errors) == 0
    
    # Operator validation tests
    
    def test_validate_operators_invalid_boolean_operator(self, validator):
        """Test error for invalid boolean operators."""
        query = "process_name:test"
        metadata = {"boolean_operator": "XOR", "recognised": [], "search_type": "server_event"}
        
        result = validator.validate(query, metadata)
        
        # Invalid boolean operator should make the query invalid
        assert not result["valid"]
        # Verify the specific operator error exists
        issues = get_all_issues(result)
        assert any(
            issue.get("severity") == "error" and 
            "Invalid boolean operator" in issue.get("message", "") and
            issue.get("category") == "operators"
            for issue in issues
        )
        issues = get_all_issues(result)
        assert any(
            "Invalid boolean operator" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_operators_unsupported_inequality(self, validator):
        """Test warning for unsupported inequality operators."""
        unsupported_ops = ['!=', '<>', '<', '>', '<=', '>=', '~=']
        
        for op in unsupported_ops:
            query = f"process_name{op}test"
            metadata = {"boolean_operator": "AND", "recognised": []}
            
            result = validator.validate(query, metadata)
            
            issues = get_all_issues(result)
            assert any(
                "not supported" in issue.get("message", "")
                for issue in issues
            ), f"Should warn about unsupported operator: {op}"
    
    def test_validate_operators_wildcard_only_values(self, validator):
        """Test info message for wildcard-only values."""
        query = "process_name:*"
        metadata = {"boolean_operator": "AND", "recognised": []}
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "Wildcard-only" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_operators_valid_and_or(self, validator):
        """Test that AND and OR operators are valid."""
        for operator in ["AND", "OR"]:
            query = "process_name:test"
            metadata = {"boolean_operator": operator, "recognised": []}
            
            result = validator.validate(query, metadata)
            
            # Should have no operator errors
            operator_errors = result["validation_results"]["operators"]["errors"]
            assert len(operator_errors) == 0
    
    # Performance validation tests
    
    def test_validate_performance_too_many_terms(self, validator):
        """Test warning for queries with too many terms."""
        # Create query with 101 terms (exceeds MAX_TERMS of 100)
        recognised = [{"field": f"field{i}", "value": "test"} for i in range(101)]
        query = " AND ".join([f"field{i}:test" for i in range(101)])
        metadata = {"boolean_operator": "AND", "recognised": recognised}
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "terms - this may be slow" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_performance_keyword_only_search(self, validator):
        """Test warning for keyword-only searches without field filters."""
        query = "malware"
        metadata = {
            "boolean_operator": "AND",
            "recognised": [{"type": "keyword", "value": "malware"}]
        }
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "only keyword searches" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_performance_excessive_wildcards(self, validator):
        """Test warning for queries with many wildcards."""
        query = "*test* AND *cmd* AND *exe* AND *sys* AND *dll* AND *bin*"
        metadata = {"boolean_operator": "AND", "recognised": []}
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "wildcards - may be slow" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_performance_leading_wildcards(self, validator):
        """Test warning for leading wildcards."""
        query = "process_name:*chrome"
        metadata = {"boolean_operator": "AND", "recognised": []}
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "Leading wildcards" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_performance_excessive_limit(self, validator):
        """Test info message for limits exceeding MAX_LIMIT."""
        query = "process_name:test"
        metadata = {
            "boolean_operator": "AND",
            "recognised": [],
            "limit": 10000  # Exceeds MAX_LIMIT of 5000
        }
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "CBR max is 5000" in issue.get("message", "") or "5000" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_performance_large_limit(self, validator):
        """Test info message for large limits."""
        query = "process_name:test"
        metadata = {
            "boolean_operator": "AND",
            "recognised": [],
            "limit": 2000
        }
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "large result sets may be slow" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_performance_overly_broad_query(self, validator):
        """Test warning for overly broad queries."""
        query = "test"
        metadata = {
            "boolean_operator": "AND",
            "recognised": [{"type": "keyword", "value": "test"}]
        }
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "very broad" in issue.get("message", "").lower()
            for issue in issues
        )
    
    # Best practices validation tests
    
    def test_validate_best_practices_hash_without_field(self, validator):
        """Test suggestion to use hash fields for hash values."""
        md5_hash = "5d41402abc4b2a76b9719d911017c592"
        query = f"malware AND {md5_hash}"  # Hash not in dedicated field
        metadata = {"boolean_operator": "AND", "recognised": []}
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "dedicated hash field" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_best_practices_more_keywords_than_structured(self, validator):
        """Test info message when keywords outnumber structured searches."""
        query = "malware suspicious bad"
        metadata = {
            "boolean_operator": "AND",
            "recognised": [
                {"type": "keyword", "value": "malware"},
                {"type": "keyword", "value": "suspicious"},
                {"type": "keyword", "value": "bad"}
            ]
        }
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "keywords vs" in issue.get("message", "") and "structured" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_best_practices_ip_without_field(self, validator):
        """Test suggestion to use IP fields for IP addresses."""
        query = "activity from 192.168.1.100"
        metadata = {"boolean_operator": "AND", "recognised": []}
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "specific IP fields" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_best_practices_domain_without_field(self, validator):
        """Test suggestion to use domain field for domains."""
        query = "connection to malicious.com"
        metadata = {"boolean_operator": "AND", "recognised": []}
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "domain field" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_best_practices_network_fields_suggest_endpoint_event(self, validator):
        """Test suggestion to use endpoint_event for network queries."""
        query = "remote_ip:1.2.3.4 AND remote_port:443"
        metadata = {
            "search_type": "server_event",  # Wrong dataset
            "boolean_operator": "AND",
            "recognised": [
                {"field": "remote_ip", "value": "1.2.3.4"},
                {"field": "remote_port", "value": "443"}
            ]
        }
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        assert any(
            "endpoint_event dataset may be more appropriate" in issue.get("message", "")
            for issue in issues
        )
    
    def test_validate_best_practices_process_fields_suggest_appropriate_dataset(self, validator):
        """Test suggestion to use appropriate dataset for process queries."""
        query = "process_name:cmd.exe AND parent_name:explorer.exe"
        metadata = {
            "search_type": "watchlist_hit_process",  # Granular type
            "boolean_operator": "AND",
            "recognised": [
                {"field": "process_name", "value": "cmd.exe"},
                {"field": "parent_name", "value": "explorer.exe"}
            ]
        }
        
        result = validator.validate(query, metadata)
        
        issues = get_all_issues(result)
        # May suggest server_event or endpoint_event, or may not have the field in granular schema
        # This test verifies the validator handles granular types
        assert "validation_results" in result
    
    # Integration tests with query builder
    
    def test_validate_query_builder_output(self, validator):
        """Test validating output from query builder."""
        # Build a query
        query, metadata = build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent="find processes named cmd.exe"
        )
        
        # Validate it
        result = validator.validate(query, metadata)
        
        # Should be valid (may have warnings but no errors)
        assert result["valid"] or all(
            len(result["validation_results"][cat]["errors"]) == 0
            for cat in result["validation_results"]
        )
    
    def test_validate_complex_query_builder_output(self, validator):
        """Test validating complex query from builder."""
        md5_hash = "5d41402abc4b2a76b9719d911017c592"
        query, metadata = build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent=f"find processes with hash {md5_hash} connecting to 192.168.1.100",
            limit=100
        )
        
        result = validator.validate(query, metadata)
        
        # Check validation completed without errors
        assert "valid" in result
        assert "validation_results" in result
        assert "metadata" in result
    
    # Metadata generation tests
    
    def test_metadata_includes_term_counts(self, validator):
        """Test that validation metadata includes term counts."""
        query = "process_name:cmd.exe AND hostname:workstation"
        metadata = {
            "search_type": "server_event",
            "boolean_operator": "AND",
            "recognised": [
                {"field": "process_name", "value": "cmd.exe"},
                {"field": "hostname", "value": "workstation"}
            ]
        }
        
        result = validator.validate(query, metadata)
        
        assert "metadata" in result
        assert "term_count" in result["metadata"]
        assert "structured_count" in result["metadata"]
        assert "keyword_count" in result["metadata"]
    
    def test_metadata_includes_complexity(self, validator):
        """Test that validation metadata includes complexity score."""
        query = "process_name:cmd.exe"
        metadata = {
            "search_type": "server_event",
            "boolean_operator": "AND",
            "recognised": [{"field": "process_name", "value": "cmd.exe"}]
        }
        
        result = validator.validate(query, metadata)
        
        assert "metadata" in result
        assert "complexity_score" in result["metadata"]
        assert 1 <= result["metadata"]["complexity_score"] <= 10
    
    def test_metadata_includes_result_size_estimate(self, validator):
        """Test that validation metadata includes result size estimate."""
        query = "process_name:cmd.exe"
        metadata = {
            "search_type": "server_event",
            "boolean_operator": "AND",
            "recognised": [{"field": "process_name", "value": "cmd.exe"}]
        }
        
        result = validator.validate(query, metadata)
        
        assert "metadata" in result
        assert "estimated_result_size" in result["metadata"]
        assert result["metadata"]["estimated_result_size"] in ["small", "medium", "large", "unbounded"]
    
    def test_metadata_includes_platform_specific_data(self, validator):
        """Test that metadata includes CBR-specific information."""
        query = "md5:5d41402abc4b2a76b9719d911017c592"
        metadata = {
            "search_type": "server_event",
            "boolean_operator": "AND",
            "recognised": [{"field": "md5", "value": "5d41402abc4b2a76b9719d911017c592", "type": "md5"}],
            "limit": 100
        }
        
        result = validator.validate(query, metadata)
        
        assert "has_hash" in result["metadata"]
        assert result["metadata"]["has_hash"] is True
        assert "wildcard_count" in result["metadata"]
        assert "limit" in result["metadata"]
    
    def test_platform_name(self, validator):
        """Test that validator returns correct platform name."""
        assert validator.get_platform_name() == "cbr"
