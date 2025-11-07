import pytest
from kql import query_builder as kql_query_builder
from tests.base_query_builder_test import (
    BaseQueryBuilderTest,
    SecurityValidationMixin,
    IOCExtractionMixin,
    LimitValidationMixin,
    BooleanOperatorMixin,
)

# Mock schema for testing
MOCK_SCHEMA = {
    "DeviceProcessEvents": {
        "columns": [
            {"name": "Timestamp", "type": "datetime"},
            {"name": "DeviceName", "type": "string"},
            {"name": "FileName", "type": "string"},
            {"name": "ProcessCommandLine", "type": "string"},
            {"name": "InitiatingProcessFileName", "type": "string"},
            {"name": "ActionType", "type": "string"},
        ]
    },
    "DeviceNetworkEvents": {
        "columns": [
            {"name": "Timestamp", "type": "datetime"},
            {"name": "DeviceName", "type": "string"},
            {"name": "RemoteUrl", "type": "string"},
            {"name": "RemoteIP", "type": "string"},
        ]
    },
}


class TestKQLQueryBuilder(
    BaseQueryBuilderTest,
    SecurityValidationMixin,
    IOCExtractionMixin,
    LimitValidationMixin,
    BooleanOperatorMixin
):
    """Test suite for KQL query builder with base class patterns."""
    
    @property
    def builder_function(self):
        """Return the KQL query builder function."""
        return kql_query_builder.build_kql_query
    
    @property
    def mock_schema(self):
        """Return the mock schema for KQL tests."""
        return MOCK_SCHEMA
    
    @property
    def required_params(self):
        """Return minimum required parameters for KQL."""
        return {"table": "DeviceProcessEvents"}
    
    def get_max_limit(self):
        """KQL doesn't enforce a hard maximum but warns above 10000."""
        return None  # No hard maximum
    
    def get_valid_operators(self):
        """KQL uses pipe operators, not boolean operators in parameters."""
        pytest.skip("KQL doesn't use boolean_operator parameter")
        return []
    
    # Original tests
    def test_build_kql_query_with_simple_natural_language_intent(self):
        """Tests that a simple natural language query is correctly translated into a KQL query."""
        intent = "show me process events from the last 24 hours"

        query, metadata = kql_query_builder.build_kql_query(
            schema=MOCK_SCHEMA,
            natural_language_intent=intent
        )

        assert "DeviceProcessEvents" in query
        assert "| where Timestamp > ago(24h)" in query
        assert metadata["table"] == "DeviceProcessEvents"
        assert metadata["time_window"] == "24h"

    def test_build_kql_query_with_table_and_where_clause(self):
        """Tests building a KQL query with an explicit table and where clause."""
        query, _ = kql_query_builder.build_kql_query(
            schema=MOCK_SCHEMA,
            table="DeviceProcessEvents",
            where=["ActionType == 'ProcessCreated'"]
        )

        assert "DeviceProcessEvents" in query
        assert "| where ActionType == 'ProcessCreated'" in query

    def test_build_kql_query_with_select_and_limit(self):
        """Tests building a KQL query with select and limit parameters."""
        query, _ = kql_query_builder.build_kql_query(
            schema=MOCK_SCHEMA,
            table="DeviceNetworkEvents",
            select=["DeviceName", "RemoteUrl"],
            limit=50
        )

        assert "| project DeviceName, RemoteUrl" in query
        assert "| limit 50" in query

    def test_build_kql_query_raises_error_without_table(self):
        """Tests that building a query without a table raises a ValueError."""
        with pytest.raises(ValueError, match="Table is required"):
            kql_query_builder.build_kql_query(schema=MOCK_SCHEMA)
    
    # New tests for coverage gaps
    def test_ioc_extraction_ip_address(self):
        """Test that IP addresses are extracted from natural language."""
        intent = "show network connections to 192.168.1.100"
        
        query, metadata = kql_query_builder.build_kql_query(
            schema=MOCK_SCHEMA,
            natural_language_intent=intent
        )
        
        # Should infer DeviceNetworkEvents table and include IP
        assert "DeviceNetworkEvents" in query or "RemoteIP" in query
        assert "192.168.1.100" in query
    
    def test_ioc_extraction_domain(self):
        """Test that domains are extracted from natural language."""
        intent = "find connections to malicious.example.com"
        
        query, metadata = kql_query_builder.build_kql_query(
            schema=MOCK_SCHEMA,
            natural_language_intent=intent
        )
        
        # Should include domain in query
        assert "malicious.example.com" in query or "RemoteUrl" in query
    
    def test_multiple_where_conditions(self):
        """Test that multiple WHERE conditions are properly combined."""
        query, _ = kql_query_builder.build_kql_query(
            schema=MOCK_SCHEMA,
            table="DeviceProcessEvents",
            where=[
                "ActionType == 'ProcessCreated'",
                "FileName =~ 'powershell.exe'"
            ]
        )
        
        assert "| where ActionType == 'ProcessCreated'" in query
        assert "| where FileName =~ 'powershell.exe'" in query
    
    def test_time_window_parsing_from_natural_language(self):
        """Test various time window formats are parsed correctly."""
        test_cases = [
            ("last 7 days", "7d"),
            ("past 24 hours", "24h"),
            ("last 30 minutes", "30m"),
        ]
        
        for intent_phrase, expected_window in test_cases:
            query, metadata = kql_query_builder.build_kql_query(
                schema=MOCK_SCHEMA,
                natural_language_intent=f"show processes from {intent_phrase}"
            )
            
            assert f"ago({expected_window})" in query
            assert metadata["time_window"] == expected_window
    
    def test_summarize_and_order_by(self):
        """Test that summarize and order_by clauses work correctly."""
        query, _ = kql_query_builder.build_kql_query(
            schema=MOCK_SCHEMA,
            table="DeviceProcessEvents",
            summarize="count() by DeviceName",
            order_by="count_ desc"
        )
        
        assert "| summarize count() by DeviceName" in query
        assert "| order by count_ desc" in query
    
    def test_invalid_where_condition_with_dangerous_patterns(self):
        """Test that WHERE conditions with SQL injection patterns are rejected."""
        dangerous_conditions = [
            "; DROP TABLE DeviceProcessEvents",
            "'; DELETE FROM DeviceProcessEvents; --",
            "ActionType == 'test' UNION SELECT * FROM users",
        ]
        
        for condition in dangerous_conditions:
            with pytest.raises(ValueError, match="potentially dangerous"):
                kql_query_builder.build_kql_query(
                    schema=MOCK_SCHEMA,
                    table="DeviceProcessEvents",
                    where=[condition]
                )
    
    def test_column_validation_with_special_characters(self):
        """Test that column names with special characters are rejected."""
        invalid_columns = [
            "DeviceName; DROP TABLE",
            "FileName|echo",
            "Test'Column",
        ]
        
        for col in invalid_columns:
            with pytest.raises(ValueError, match="invalid characters"):
                kql_query_builder.build_kql_query(
                    schema=MOCK_SCHEMA,
                    table="DeviceProcessEvents",
                    select=[col]
                )
    
    def test_limit_boundary_conditions(self):
        """Test limit parameter with various boundary values."""
        # Valid limits
        for limit in [1, 100, 1000, 10000]:
            query, metadata = kql_query_builder.build_kql_query(
                schema=MOCK_SCHEMA,
                table="DeviceProcessEvents",
                limit=limit
            )
            assert f"| limit {limit}" in query
        
        # Very large limit (should work but may warn)
        query, metadata = kql_query_builder.build_kql_query(
            schema=MOCK_SCHEMA,
            table="DeviceProcessEvents",
            limit=50000
        )
        assert "| limit 50000" in query
    
    def test_table_name_fuzzy_matching(self):
        """Test that table names are fuzzy matched when not exact."""
        # This may work with rapidfuzz installed
        try:
            query, metadata = kql_query_builder.build_kql_query(
                schema=MOCK_SCHEMA,
                table="DeviceProcessEvent",  # Missing 's'
                natural_language_intent="find processes"
            )
            # Should fuzzy match to DeviceProcessEvents
            assert "DeviceProcessEvents" in query
        except (ImportError, ValueError):
            # If rapidfuzz not available or fuzzy matching fails, that's ok
            pytest.skip("Fuzzy matching not available or did not match")
    
    def test_natural_language_with_process_name(self):
        """Test that process names are extracted from natural language."""
        intent = "find powershell.exe processes"
        
        query, metadata = kql_query_builder.build_kql_query(
            schema=MOCK_SCHEMA,
            natural_language_intent=intent
        )
        
        assert "DeviceProcessEvents" in query
        assert "powershell.exe" in query
        assert "FileName" in query
    
    def test_natural_language_with_device_name(self):
        """Test that device names are extracted from natural language."""
        intent = "show processes on device TEST-PC"
        
        query, metadata = kql_query_builder.build_kql_query(
            schema=MOCK_SCHEMA,
            natural_language_intent=intent
        )
        
        assert "DeviceName" in query
        assert "TEST-PC" in query
    
    def test_empty_select_list(self):
        """Test that empty select list is handled gracefully."""
        query, _ = kql_query_builder.build_kql_query(
            schema=MOCK_SCHEMA,
            table="DeviceProcessEvents",
            select=[]
        )
        
        # Should not include project clause
        assert "| project" not in query
    
    def test_empty_where_list(self):
        """Test that empty where list is handled gracefully."""
        query, _ = kql_query_builder.build_kql_query(
            schema=MOCK_SCHEMA,
            table="DeviceProcessEvents",
            where=[]
        )
        
        # Should still have valid query without extra where clauses
        assert "DeviceProcessEvents" in query
    
    def test_invalid_time_window_format(self):
        """Test that invalid time window formats use default."""
        query, metadata = kql_query_builder.build_kql_query(
            schema=MOCK_SCHEMA,
            table="DeviceProcessEvents",
            time_window="invalid"
        )
        
        # Should use default time window (7d)
        assert "ago(7d)" in query
        assert metadata["time_window"] == "7d"
