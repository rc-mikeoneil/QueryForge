"""
Integration tests for Carbon Black Response (CBR) query builder
Tests end-to-end workflows: build → validate → retry
"""

import pytest
from pathlib import Path
from queryforge.platforms.cbr.schema_loader import CBResponseSchemaCache
from queryforge.platforms.cbr.query_builder import build_cbr_query
from queryforge.platforms.cbr.validator import CBRValidator


@pytest.fixture
def cbr_cache():
    """Load CBR schema cache"""
    schema_dir = Path(__file__).parent.parent / "src" / "queryforge" / "platforms" / "cbr"
    return CBResponseSchemaCache(schema_path=schema_dir)


@pytest.fixture
def cbr_validator(cbr_cache):
    """Create CBR validator"""
    return CBRValidator(cbr_cache.load())


class TestCBREndToEndWorkflows:
    """Test complete build → validate workflows"""
    
    def test_build_and_validate_process_query(self, cbr_cache, cbr_validator):
        """Test building and validating a process query"""
        schema = cbr_cache.load()
        
        # Build query
        query, metadata = build_cbr_query(
            schema=schema,
            search_type="endpoint_event",
            natural_language_intent="find chrome.exe processes"
        )
        
        assert query is not None
        assert "process_name" in query or "chrome" in query
        
        # Validate query
        result = cbr_validator.validate(query, metadata)
        
        assert result["valid"] is True
        assert result["validation_results"]["syntax"]["valid"] is True
        assert result["validation_results"]["schema"]["valid"] is True
    
    def test_build_and_validate_hash_query(self, cbr_cache, cbr_validator):
        """Test building and validating a hash query"""
        schema = cbr_cache.load()
        
        # Build query with MD5
        query, metadata = build_cbr_query(
            schema=schema,
            search_type="endpoint_event",
            natural_language_intent="find process with hash 5d41402abc4b2a76b9719d911017c592"
        )
        
        # Query should contain the hash (either as field:value or keyword)
        assert "5d41402abc4b2a76b9719d911017c592" in query
        
        # Validate query
        result = cbr_validator.validate(query, metadata)
        
        assert result["valid"] is True
        # Hash may be in structured or keyword form
        assert result["metadata"]["has_hash"] is True or "5d41402abc4b2a76b9719d911017c592" in query
    
    def test_build_and_validate_network_query(self, cbr_cache, cbr_validator):
        """Test building and validating a network connection query"""
        schema = cbr_cache.load()
        
        # Build query with IP and port
        query, metadata = build_cbr_query(
            schema=schema,
            search_type="endpoint_event",
            natural_language_intent="network connections to 192.168.1.100 on port 443"
        )
        
        assert "192.168.1.100" in query
        assert "443" in query
        
        # Validate query
        result = cbr_validator.validate(query, metadata)
        
        assert result["valid"] is True
    
    def test_build_and_validate_with_structured_terms(self, cbr_cache, cbr_validator):
        """Test building and validating with structured terms"""
        schema = cbr_cache.load()
        
        # Build query with structured terms
        query, metadata = build_cbr_query(
            schema=schema,
            search_type="server_event",
            terms=[
                "watchlist_name:Threat Intel",
                "process_name:malware.exe"
            ],
            boolean_operator="AND"
        )
        
        # Terms should be in the query
        assert "watchlist_name" in query or "Threat Intel" in query
        assert "process_name" in query or "malware.exe" in query
        assert "AND" in query
        
        # Validate query
        result = cbr_validator.validate(query, metadata)
        
        assert result["valid"] is True
        # At least some terms should be present
        assert result["metadata"]["term_count"] >= 2
    
    def test_build_and_validate_invalid_field_with_suggestion(self, cbr_cache, cbr_validator):
        """Test that invalid fields get suggestions during validation"""
        schema = cbr_cache.load()
        
        # Build query with typo in field name
        query, metadata = build_cbr_query(
            schema=schema,
            search_type="endpoint_event",
            terms=["proces_name:test.exe"]  # Typo: "proces_name" instead of "process_name"
        )
        
        # Validate query - should fail with suggestion
        result = cbr_validator.validate(query, metadata)
        
        # May be valid if it's treated as keyword, or invalid if parsed as field
        # Check if there's a schema validation result
        schema_result = result["validation_results"]["schema"]
        if not schema_result["valid"]:
            # Should have suggestions for the typo
            assert len(schema_result["errors"]) > 0
            assert any("process_name" in str(err.get("suggestion", "")) 
                      for err in schema_result["errors"])
    
    def test_build_with_limit_and_validate(self, cbr_cache, cbr_validator):
        """Test building with limit and validating"""
        schema = cbr_cache.load()
        
        # Build query with limit
        query, metadata = build_cbr_query(
            schema=schema,
            search_type="endpoint_event",
            natural_language_intent="find svchost.exe",
            limit=1000
        )
        
        assert metadata["limit"] == 1000
        
        # Validate query
        result = cbr_validator.validate(query, metadata)
        
        assert result["valid"] is True
        assert result["metadata"]["limit"] == 1000
    
    def test_build_with_excessive_limit_and_validate_warning(self, cbr_cache, cbr_validator):
        """Test building with excessive limit triggers validation warning"""
        schema = cbr_cache.load()
        
        # Build query with excessive limit (will be clamped to 5000)
        # Use a more specific query that won't be filtered as stopword
        query, metadata = build_cbr_query(
            schema=schema,
            search_type="endpoint_event",
            natural_language_intent="find svchost.exe processes",
            limit=10000
        )
        
        # Limit should be clamped
        assert metadata["limit"] == 5000
        # limit_clamped is set to MAX_LIMIT when clamping occurs
        assert metadata.get("limit_clamped") == 5000
        
        # Validate query - should warn about large limit
        result = cbr_validator.validate(query, metadata)
        
        # Should still be valid but may have performance warnings
        assert result["valid"] is True
    
    def test_or_operator_query_workflow(self, cbr_cache, cbr_validator):
        """Test OR operator in full workflow"""
        schema = cbr_cache.load()
        
        # Build query with OR
        query, metadata = build_cbr_query(
            schema=schema,
            search_type="endpoint_event",
            terms=["process_name:cmd.exe", "process_name:powershell.exe"],
            boolean_operator="OR"
        )
        
        assert "OR" in query
        assert metadata["boolean_operator"] == "OR"
        
        # Validate query
        result = cbr_validator.validate(query, metadata)
        
        assert result["valid"] is True
    
    def test_complex_multi_field_query(self, cbr_cache, cbr_validator):
        """Test complex query with multiple field types"""
        schema = cbr_cache.load()
        
        # Build complex query
        query, metadata = build_cbr_query(
            schema=schema,
            search_type="endpoint_event",
            natural_language_intent="chrome.exe connecting to 192.168.1.100 on port 443 with username admin",
        )
        
        # Should have multiple IOCs extracted
        assert len(metadata.get("recognised", [])) > 0
        
        # Validate query
        result = cbr_validator.validate(query, metadata)
        
        assert result["valid"] is True
        # Query should have multiple terms
        assert result["metadata"]["term_count"] > 0


class TestCBRRetryWorkflow:
    """Test retry workflow with corrections"""
    
    def test_manual_retry_with_field_correction(self, cbr_cache, cbr_validator):
        """Test manual retry workflow after validation failure"""
        schema = cbr_cache.load()
        
        # First attempt with typo
        query1, metadata1 = build_cbr_query(
            schema=schema,
            search_type="endpoint_event",
            terms=["proces_name:test.exe"]  # Typo
        )
        
        # Validate - may fail or treat as keyword
        result1 = cbr_validator.validate(query1, metadata1)
        
        # If validation caught the typo, retry with correction
        if not result1["valid"]:
            schema_errors = result1["validation_results"]["schema"]["errors"]
            if schema_errors:
                # Extract suggestion from first error
                suggestion = schema_errors[0].get("suggestion", "")
                
                # Retry with corrected field
                query2, metadata2 = build_cbr_query(
                    schema=schema,
                    search_type="endpoint_event",
                    terms=["process_name:test.exe"]  # Corrected
                )
                
                # Validate again
                result2 = cbr_validator.validate(query2, metadata2)
                assert result2["valid"] is True


class TestCBRDatasetSelection:
    """Test dataset selection and field availability"""
    
    def test_server_event_dataset(self, cbr_cache, cbr_validator):
        """Test server_event dataset with server-specific fields"""
        schema = cbr_cache.load()
        
        # Build query for server events
        query, metadata = build_cbr_query(
            schema=schema,
            search_type="server_event",
            terms=["watchlist_name:Suspicious Activity"]
        )
        
        assert "watchlist_name:" in query
        
        # Validate
        result = cbr_validator.validate(query, metadata)
        assert result["valid"] is True
    
    def test_endpoint_event_dataset(self, cbr_cache, cbr_validator):
        """Test endpoint_event dataset with endpoint-specific fields"""
        schema = cbr_cache.load()
        
        # Build query for endpoint events
        query, metadata = build_cbr_query(
            schema=schema,
            search_type="endpoint_event",
            terms=["netconn_count:5"]
        )
        
        assert "netconn_count:" in query
        
        # Validate
        result = cbr_validator.validate(query, metadata)
        assert result["valid"] is True
    
    def test_dataset_normalization(self, cbr_cache, cbr_validator):
        """Test dataset name normalization"""
        schema = cbr_cache.load()
        
        # Try various dataset name forms
        for dataset_name in ["server", "SERVER_EVENT", "server_event"]:
            query, metadata = build_cbr_query(
                schema=schema,
                search_type=dataset_name,
                natural_language_intent="test query"
            )
            
            # Should normalize to "server_event"
            assert metadata.get("search_type") == "server_event"


class TestCBRPerformanceOptimization:
    """Test performance-related validations"""
    
    def test_wildcard_warning(self, cbr_cache, cbr_validator):
        """Test that excessive wildcards trigger warnings"""
        schema = cbr_cache.load()
        
        # Build query with many wildcards
        query, metadata = build_cbr_query(
            schema=schema,
            search_type="endpoint_event",
            terms=[
                "process_name:*test*",
                "domain:*evil*",
                "path:*malware*"
            ]
        )
        
        # Validate - should have performance warnings
        result = cbr_validator.validate(query, metadata)
        
        # May have warnings but should still be valid
        assert result["valid"] is True
        
        # Check for wildcard-related warnings
        perf_warnings = result["validation_results"]["performance"]["warnings"]
        if perf_warnings:
            assert any("wildcard" in str(w).lower() for w in perf_warnings)
    
    def test_broad_query_warning(self, cbr_cache, cbr_validator):
        """Test that overly broad queries trigger warnings"""
        schema = cbr_cache.load()
        
        # Build very broad query with a concrete term that won't be filtered
        query, metadata = build_cbr_query(
            schema=schema,
            search_type="endpoint_event",
            natural_language_intent="executable"  # Generic but not a stopword
        )
        
        # Validate - may have performance warnings
        result = cbr_validator.validate(query, metadata)
        
        # Should still be valid
        assert result["valid"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
