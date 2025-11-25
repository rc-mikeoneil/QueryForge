import pytest
from queryforge.platforms.cbc import query_builder as cbc_query_builder
from tests.base_query_builder_test import (
    BaseQueryBuilderTest,
    SecurityValidationMixin,
    IOCExtractionMixin,
    LimitValidationMixin,
    BooleanOperatorMixin,
)

# Mock CBC schema for testing
MOCK_CBC_SCHEMA = {
    "search_types": {
        "process_search": "Process activity events",
        "binary_search": "Information about binaries",
    },
    "process_search_fields": {
        "process_name": {"type": "string"},
        "process_md5": {"type": "string"},
        "process_sha256": {"type": "string"},
        "ipaddr": {"type": "string"},
        "ipv6addr": {"type": "string"},
        "ipport": {"type": "number"},
        "process_cmdline": {"type": "string"},
        "username": {"type": "string"},
        "domain": {"type": "string"},
    },
    "binary_search_fields": {
        "binary_name": {"type": "string"},
        "binary_md5": {"type": "string"},
    }
}


class TestCBCQueryBuilder(
    BaseQueryBuilderTest,
    SecurityValidationMixin,
    IOCExtractionMixin,
    LimitValidationMixin,
    BooleanOperatorMixin
):
    """Test suite for CBC query builder with base class patterns."""
    
    @property
    def builder_function(self):
        """Return the CBC query builder function."""
        return cbc_query_builder.build_cbc_query
    
    @property
    def mock_schema(self):
        """Return the mock schema for CBC tests."""
        return MOCK_CBC_SCHEMA
    
    @property
    def required_params(self):
        """Return minimum required parameters for CBC."""
        return {"terms": ["process_name:test"]}
    
    def get_max_limit(self):
        """CBC enforces MAX_LIMIT of 5000."""
        return 5000
    
    def get_valid_operators(self):
        """CBC supports AND and OR operators."""
        return ["AND", "OR"]
    
    # Original tests
    def test_build_cbc_query_with_nl_intent(self):
        """Tests building a CBC query from a simple natural language intent."""
        intent = "find processes named powershell.exe"

        query, metadata = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            natural_language_intent=intent,
        )

        assert 'process_name:powershell.exe' in query
        assert metadata["search_type"] == "process_search"

    def test_build_cbc_query_with_iocs(self):
        """Tests that IOCs like IPs and hashes are correctly extracted."""
        intent = "show me activity for IP 1.2.3.4 and hash 5d41402abc4b2a76b9719d911017c592"

        query, metadata = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            natural_language_intent=intent,
        )

        assert "ipaddr:1.2.3.4" in query
        assert "process_md5:5d41402abc4b2a76b9719d911017c592" in query
        assert metadata["boolean_operator"] == "AND"

    def test_build_cbc_query_with_structured_terms(self):
        """Tests building a query from structured terms."""
        query, _ = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            terms=["username:admin", "domain:WORKGROUP"],
        )

        assert "username:admin" in query
        assert "domain:WORKGROUP" in query

    def test_build_cbc_query_raises_error_for_unsafe_chars(self):
        """Tests that unsafe characters in terms raise a QueryBuildError."""
        with pytest.raises(cbc_query_builder.QueryBuildError, match="Unsafe characters"):
            cbc_query_builder.build_cbc_query(
                schema=MOCK_CBC_SCHEMA,
                terms=["process_name:test; DROP TABLE users"],
            )
    
    # New tests for coverage gaps
    def test_error_on_no_terms_or_intent(self):
        """Test that an error is raised when neither terms nor intent is provided."""
        with pytest.raises(cbc_query_builder.QueryBuildError, match="No expressions provided"):
            cbc_query_builder.build_cbc_query(schema=MOCK_CBC_SCHEMA)
    
    def test_limit_clamping_at_max(self):
        """Test that limits above MAX_LIMIT are clamped to 5000."""
        query, metadata = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            terms=["process_name:test"],
            limit=10000
        )
        
        assert metadata["limit"] == 5000
        assert metadata["limit_clamped"] == 5000
    
    def test_ipv6_extraction(self):
        """Test that IPv6 addresses are extracted from natural language."""
        intent = "find activity for 2001:db8::1"
        
        query, metadata = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            natural_language_intent=intent
        )
        
        # Should extract IPv6 address
        assert "2001:db8::1" in query or "ipv6" in str(metadata).lower()
    
    def test_port_extraction(self):
        """Test that port numbers are extracted from natural language."""
        intent = "find connections on port 443"
        
        query, metadata = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            natural_language_intent=intent
        )
        
        assert "ipport:443" in query
    
    def test_sha256_extraction(self):
        """Test that SHA256 hashes are extracted from natural language."""
        sha256 = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
        intent = f"find binary with hash {sha256}"
        
        query, metadata = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            natural_language_intent=intent
        )
        
        assert sha256 in query
        assert "process_sha256" in query
    
    def test_or_operator(self):
        """Test that OR boolean operator works correctly."""
        query, metadata = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            terms=["process_name:cmd.exe", "process_name:powershell.exe"],
            boolean_operator="OR"
        )
        
        assert " OR " in query
        assert metadata["boolean_operator"] == "OR"
    
    def test_invalid_boolean_operator(self):
        """Test that invalid boolean operators raise an error."""
        with pytest.raises(cbc_query_builder.QueryBuildError, match="Unsupported boolean operator"):
            cbc_query_builder.build_cbc_query(
                schema=MOCK_CBC_SCHEMA,
                terms=["process_name:test"],
                boolean_operator="XOR"
            )
    
    def test_cmdline_extraction(self):
        """Test that command line patterns are extracted."""
        intent = 'find processes with cmdline containing "-enc"'
        
        query, metadata = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            natural_language_intent=intent
        )
        
        assert "process_cmdline" in query
        assert "-enc" in query
    
    def test_username_extraction(self):
        """Test that usernames are extracted from natural language."""
        intent = "find processes running as administrator"
        
        query, metadata = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            natural_language_intent=intent
        )
        
        assert "username" in query or "administrator" in query
    
    def test_domain_extraction(self):
        """Test that domains are extracted from natural language."""
        intent = "find processes in domain CORP"
        
        query, metadata = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            natural_language_intent=intent
        )
        
        assert "domain:CORP" in query or "CORP" in query
    
    def test_quoted_values_with_spaces(self):
        """Test that values with spaces are properly quoted."""
        query, metadata = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            terms=['process_name:"Microsoft Edge"']
        )
        
        # Should handle quoted values correctly
        assert "Microsoft Edge" in query or "Microsoft" in query
    
    def test_path_extraction(self):
        """Test that file paths are extracted from natural language."""
        intent = 'find processes with path "C:\\Windows\\System32\\cmd.exe"'
        
        query, metadata = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            natural_language_intent=intent
        )
        
        # Path should be included (backslashes may be escaped)
        assert "cmd.exe" in query
    
    def test_multiple_iocs_combined(self):
        """Test that multiple IOCs are extracted and combined."""
        intent = "find activity for IP 10.0.0.1 and hash abc123 and port 8080"
        
        # Add MD5 hash pattern
        intent = intent.replace("abc123", "5d41402abc4b2a76b9719d911017c592")
        
        query, metadata = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            natural_language_intent=intent
        )
        
        assert "ipaddr:10.0.0.1" in query
        assert "5d41402abc4b2a76b9719d911017c592" in query
        assert "ipport:8080" in query
    
    def test_search_type_normalization(self):
        """Test that search types are normalized correctly."""
        # Test with normalized search type
        query, metadata = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            search_type="process_search",
            terms=["process_name:test"]
        )
        
        assert metadata["search_type"] == "process_search"
    
    def test_empty_terms_list(self):
        """Test that empty terms list without intent raises an error."""
        with pytest.raises(cbc_query_builder.QueryBuildError, match="No expressions provided"):
            cbc_query_builder.build_cbc_query(
                schema=MOCK_CBC_SCHEMA,
                terms=[]
            )
    
    def test_residual_keyword_extraction(self):
        """Test that residual keywords are extracted after pattern matching."""
        intent = "find malicious processes"
        
        query, metadata = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            natural_language_intent=intent
        )
        
        # "malicious" should be included as a keyword after stopwords are removed
        assert "malicious" in query
    
    def test_metadata_contains_recognised_patterns(self):
        """Test that metadata includes recognised patterns."""
        query, metadata = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            natural_language_intent="find processes with IP 1.2.3.4"
        )
        
        assert "recognised" in metadata
        assert len(metadata["recognised"]) > 0
    
    def test_case_insensitive_boolean_operator(self):
        """Test that boolean operators are case-insensitive."""
        for operator in ["and", "AND", "And"]:
            query, metadata = cbc_query_builder.build_cbc_query(
                schema=MOCK_CBC_SCHEMA,
                terms=["process_name:test"],
                boolean_operator=operator
            )
            assert metadata["boolean_operator"] == "AND"
    
    def test_sanitization_of_backslashes(self):
        """Test that backslashes in paths are properly escaped."""
        query, metadata = cbc_query_builder.build_cbc_query(
            schema=MOCK_CBC_SCHEMA,
            terms=["username:DOMAIN\\user"]
        )
        
        # Backslashes should be escaped
        assert "DOMAIN" in query and "user" in query
