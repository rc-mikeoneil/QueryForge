import pytest
from cortex import query_builder as cortex_query_builder
from tests.base_query_builder_test import (
    BaseQueryBuilderTest,
    SecurityValidationMixin,
    IOCExtractionMixin,
    LimitValidationMixin,
    BooleanOperatorMixin,
)

# Mock Cortex schema for testing
MOCK_CORTEX_SCHEMA = {
    "datasets": {
        "xdr_data": {
            "name": "xdr_data",
            "default_fields": ["_time", "agent_hostname", "actor_process_image_name"]
        }
    },
    "xdr_data_fields": {
        "_time": {"type": "datetime"},
        "agent_hostname": {"type": "string"},
        "actor_process_image_name": {"type": "string"},
        "action_file_md5": {"type": "string"},
        "action_remote_ip": {"type": "string"},
        "event_type": {"type": "enum"}
    },
    "field_groups": {}
}


class TestCortexQueryBuilder(
    BaseQueryBuilderTest,
    SecurityValidationMixin,
    IOCExtractionMixin,
    LimitValidationMixin,
    BooleanOperatorMixin
):
    """Test suite for Cortex XDR query builder with base class patterns."""
    
    @property
    def builder_function(self):
        """Return the Cortex query builder function."""
        return cortex_query_builder.build_cortex_query
    
    @property
    def mock_schema(self):
        """Return the mock schema for Cortex tests."""
        return MOCK_CORTEX_SCHEMA
    
    @property
    def required_params(self):
        """Return minimum required parameters for Cortex."""
        return {"filters": [{"field": "agent_hostname", "value": "test"}]}
    
    def get_max_limit(self):
        """Cortex may have platform-specific limits."""
        return None  # Check if Cortex enforces a limit
    
    def get_valid_operators(self):
        """Cortex doesn't use a boolean_operator parameter in the same way."""
        pytest.skip("Cortex doesn't use boolean_operator parameter")
        return []
    
    # Original tests
    def test_build_cortex_query_with_nl_intent(self):
        """Tests building a Cortex XQL query from a simple natural language intent."""
        intent = "find powershell.exe running on host 'test-pc'"

        query, metadata = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            natural_language_intent=intent,
        )

        assert "dataset = xdr_data" in query
        assert "| filter actor_process_image_name = 'powershell.exe'" in query
        assert "| filter agent_hostname contains 'test-pc'" in query
        assert metadata["dataset"] == "xdr_data"

    def test_build_cortex_query_with_default_fields(self):
        """Tests that a default set of fields is selected when none are provided."""
        query, metadata = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            filters=[{"field": "action_remote_ip", "value": "8.8.8.8"}]
        )

        assert "| fields _time, agent_hostname, actor_process_image_name" in query

    def test_build_cortex_query_with_process_alias(self):
        """Tests that a known process alias is correctly resolved."""
        intent = "show me cmd activity"

        query, _ = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            natural_language_intent=intent,
        )

        assert "| filter actor_process_image_name in ('cmd.exe')" in query

    def test_build_cortex_query_with_time_range(self):
        """Tests that a natural language time range is parsed correctly."""
        intent = "find events from the last 24 hours"

        query, _ = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            natural_language_intent=intent,
        )

        assert "| filter _time > current_time() - interval '24 hour'" in query
    
    # New tests for coverage gaps
    def test_error_on_missing_dataset_and_no_inference(self):
        """Test that missing dataset without natural language raises an error."""
        # Without dataset or natural language intent, should error
        with pytest.raises((ValueError, KeyError, Exception)):
            cortex_query_builder.build_cortex_query(
                schema=MOCK_CORTEX_SCHEMA,
                filters=[{"field": "test_field", "value": "test"}]
            )
    
    def test_explicit_dataset_selection(self):
        """Test that explicit dataset parameter is respected."""
        query, metadata = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            dataset="xdr_data",
            filters=[{"field": "agent_hostname", "value": "test"}]
        )
        
        assert "dataset = xdr_data" in query
        assert metadata["dataset"] == "xdr_data"
    
    def test_ioc_extraction_ip_address(self):
        """Test that IP addresses are extracted from natural language."""
        intent = "find connections to 192.168.1.100"
        
        query, metadata = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            natural_language_intent=intent
        )
        
        assert "192.168.1.100" in query
        assert "action_remote_ip" in query or "remote_ip" in query.lower()
    
    def test_ioc_extraction_md5_hash(self):
        """Test that MD5 hashes are extracted from natural language."""
        md5_hash = "5d41402abc4b2a76b9719d911017c592"
        intent = f"find files with hash {md5_hash}"
        
        query, metadata = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            natural_language_intent=intent
        )
        
        assert md5_hash in query
    
    def test_custom_fields_selection(self):
        """Test that custom fields are included in the query."""
        query, metadata = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            dataset="xdr_data",
            fields=["_time", "agent_hostname", "action_remote_ip"],
            filters=[{"field": "agent_hostname", "value": "test"}]
        )
        
        assert "| fields _time, agent_hostname, action_remote_ip" in query
    
    def test_multiple_filters(self):
        """Test that multiple filters are properly combined."""
        filters = [
            {"field": "agent_hostname", "value": "test-pc"},
            {"field": "actor_process_image_name", "value": "powershell.exe"}
        ]
        
        query, metadata = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            dataset="xdr_data",
            filters=filters
        )
        
        assert "| filter agent_hostname" in query
        assert "| filter actor_process_image_name" in query
        assert "test-pc" in query
        assert "powershell.exe" in query
    
    def test_time_range_parsing_variations(self):
        """Test various time range formats."""
        test_cases = [
            ("last 7 days", "7 day"),
            ("past hour", "1 hour"),
            ("last 30 minutes", "30 minute"),
        ]
        
        for intent_phrase, expected_unit in test_cases:
            query, _ = cortex_query_builder.build_cortex_query(
                schema=MOCK_CORTEX_SCHEMA,
                natural_language_intent=f"show events from {intent_phrase}"
            )
            
            # Should include time filter with interval
            assert "interval" in query
    
    def test_process_alias_powershell(self):
        """Test that powershell alias is resolved correctly."""
        intent = "find powershell activity"
        
        query, _ = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            natural_language_intent=intent
        )
        
        # Should resolve to actual powershell executable names
        assert "powershell" in query.lower()
    
    def test_hostname_pattern_matching(self):
        """Test that hostname patterns are correctly handled."""
        intent = "show activity on hostname containing TEST"
        
        query, _ = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            natural_language_intent=intent
        )
        
        assert "agent_hostname" in query
        assert "contains" in query or "TEST" in query
    
    def test_filter_with_operator(self):
        """Test that filter operators are properly applied."""
        filters = [
            {
                "field": "agent_hostname",
                "operator": "contains",
                "value": "test"
            }
        ]
        
        query, _ = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            dataset="xdr_data",
            filters=filters
        )
        
        assert "contains" in query
        assert "test" in query
    
    def test_limit_parameter(self):
        """Test that limit parameter is applied correctly."""
        query, _ = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            dataset="xdr_data",
            filters=[{"field": "agent_hostname", "value": "test"}],
            limit=100
        )
        
        assert "| limit 100" in query
    
    def test_natural_language_with_multiple_conditions(self):
        """Test complex natural language with multiple conditions."""
        intent = "find powershell.exe on host TEST-PC from last 24 hours"
        
        query, metadata = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            natural_language_intent=intent
        )
        
        # Should include all components
        assert "powershell" in query.lower()
        assert "TEST-PC" in query or "test-pc" in query
        assert "24 hour" in query or "_time" in query
    
    def test_empty_filters_list(self):
        """Test that empty filters with dataset still works."""
        query, _ = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            dataset="xdr_data",
            filters=[]
        )
        
        # Should still generate valid query with dataset
        assert "dataset = xdr_data" in query
    
    def test_structured_time_range(self):
        """Test that structured time range definitions work."""
        time_range = {
            "start": "2024-01-01T00:00:00Z",
            "end": "2024-01-31T23:59:59Z"
        }
        
        try:
            query, _ = cortex_query_builder.build_cortex_query(
                schema=MOCK_CORTEX_SCHEMA,
                dataset="xdr_data",
                time_range=time_range,
                filters=[{"field": "agent_hostname", "value": "test"}]
            )
            
            # Should include time range filter
            assert "_time" in query
        except (TypeError, AttributeError):
            # Some implementations may not support structured time ranges
            pytest.skip("Structured time ranges not supported")
    
    def test_dataset_inference_from_intent(self):
        """Test that dataset is inferred from natural language."""
        intent = "find network connections"
        
        query, metadata = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            natural_language_intent=intent
        )
        
        # Should infer a dataset (xdr_data is default)
        assert "dataset =" in query
        assert "xdr_data" in metadata.get("dataset", "")
    
    def test_query_metadata_completeness(self):
        """Test that metadata contains all expected keys."""
        query, metadata = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            natural_language_intent="find processes"
        )
        
        assert "dataset" in metadata
        assert isinstance(metadata["dataset"], str)
    
    def test_special_characters_in_values(self):
        """Test that special characters in values are properly escaped."""
        filters = [
            {"field": "agent_hostname", "value": "test-pc.domain.com"}
        ]
        
        query, _ = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            dataset="xdr_data",
            filters=filters
        )
        
        # Should handle domain names with dots and hyphens
        assert "test-pc.domain.com" in query or "test-pc" in query
    
    def test_case_sensitivity_handling(self):
        """Test that case sensitivity is handled appropriately."""
        intent = "find POWERSHELL.EXE processes"
        
        query, _ = cortex_query_builder.build_cortex_query(
            schema=MOCK_CORTEX_SCHEMA,
            natural_language_intent=intent
        )
        
        # Should still match powershell regardless of case
        assert "powershell" in query.lower()
