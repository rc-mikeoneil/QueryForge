"""
Test CQL query builder fixes for timestamp parsing issues.

This test verifies that the fixes address the syntax errors that occurred
when processing queries with device names, process names, and timestamps.
"""

import pytest
from queryforge.platforms.cql.schema_loader import CQLSchemaLoader
from queryforge.platforms.cql.query_builder import CQLQueryBuilder


class TestCQLTimestampFix:
    """Test fixes for timestamp parsing issues in CQL query builder."""

    @pytest.fixture
    def schema_loader(self):
        """Create a CQL schema loader instance."""
        return CQLSchemaLoader()

    @pytest.fixture
    def query_builder(self, schema_loader):
        """Create a CQL query builder instance."""
        return CQLQueryBuilder(schema_loader)

    def test_original_failing_query(self, query_builder):
        """
        Test the original query that was failing with syntax errors.
        
        Original request:
        "I need assistance creating a query for crowdstrike. I am looking for 
        the device LT-PF3M5XSF being infected by a click to run attack. I want 
        to see any additional activity that occurred after spawning mshta. 
        This activity occurred on 2025-12-01 21:33:06 UTC"
        """
        result = query_builder.build_query(
            dataset="events",
            natural_language_intent=(
                "device LT-PF3M5XSF infected by click to run attack, "
                "activity after spawning mshta on 2025-12-01 21:33:06 UTC"
            ),
            time_range="2025-12-01 21:33:06 UTC",
        )

        query = result["query"]
        metadata = result["metadata"]

        # Verify query was generated
        assert query, "Query should not be empty"
        
        # Verify event type was added
        assert "#event_simpleName=ProcessRollup2" in query, \
            "Query should include ProcessRollup2 event type for process activity"
        
        # Verify process name was extracted correctly (not as IP or other field)
        assert "mshta.exe" in query, "Query should include mshta.exe process name"
        
        # Verify device name filter
        assert "LT-PF3M5XSF" in query, "Query should include device name filter"
        
        # Verify timestamp was processed correctly (not mangled into other fields)
        # The timestamp should be in @timestamp filter, not in LocalAddressIP4 or other fields
        assert "@timestamp" in query, "Query should include timestamp filter"
        
        # Verify NO timestamp components appear as values in wrong fields
        # The bug was: LocalAddressIP4 = '21:33:06' (time in IP field!)
        assert "LocalAddressIP4 = '21:33:06'" not in query, \
            "Timestamp components should NOT appear in IP address fields"
        assert "LocalAddressIP4 = '2025-12-01'" not in query, \
            "Date components should NOT appear in IP address fields"
        
        print(f"\n✓ Generated query:\n{query}")
        print(f"\n✓ Metadata: {metadata}")

    def test_timestamp_sanitization(self, query_builder):
        """Test that timestamp components are not extracted as IPs or other indicators."""
        result = query_builder.build_query(
            dataset="events",
            natural_language_intent="Find processes on 2025-12-01 21:33:06 UTC with IP 192.168.1.100",
        )

        query = result["query"]
        
        # The actual IP should be in the query
        assert "192.168.1.100" in query, "Actual IP address should be extracted"
        
        # Timestamp components should NOT be extracted as separate filters
        # They should only appear in the @timestamp filter context
        assert "= '21:33:06'" not in query or "@timestamp" in query, \
            "Time component should only appear in timestamp context"

    def test_device_name_extraction(self, query_builder):
        """Test that device names are correctly extracted and used."""
        result = query_builder.build_query(
            dataset="events",
            natural_language_intent="device LT-PF3M5XSF running cmd.exe",
        )

        query = result["query"]
        
        # Device name should be in the query
        assert "LT-PF3M5XSF" in query, "Device name should be extracted"
        
        # Process name should be in the query
        assert "cmd.exe" in query, "Process name should be extracted"
        
        print(f"\n✓ Device name query:\n{query}")

    def test_process_name_with_mshta(self, query_builder):
        """Test specific extraction of mshta process name."""
        result = query_builder.build_query(
            dataset="events",
            natural_language_intent="spawning mshta",
        )

        query = result["query"]
        
        # mshta should be extracted as mshta.exe
        assert "mshta.exe" in query, "mshta should be extracted as mshta.exe"
        
        # Event type should be ProcessRollup2 for process queries
        assert "#event_simpleName=ProcessRollup2" in query, \
            "Process queries should include event type filter"
        
        print(f"\n✓ mshta query:\n{query}")

    def test_time_range_formats(self, query_builder):
        """Test various time range input formats."""
        # Test relative time
        result = query_builder.build_query(
            dataset="events",
            natural_language_intent="cmd.exe processes",
            time_range="24h",
        )
        assert "@timestamp >= now() - 24h" in result["query"], \
            "Relative time range should be converted correctly"
        
        # Test ISO format with space
        result = query_builder.build_query(
            dataset="events",
            natural_language_intent="cmd.exe processes",
            time_range="2025-12-01 21:33:06 UTC",
        )
        query = result["query"]
        assert "@timestamp >=" in query, "Timestamp filter should be present"
        # Should have T separator and Z suffix
        assert "2025-12-01T21:33:06Z" in query, \
            "ISO timestamp should be normalized to YYYY-MM-DDTHH:MM:SSZ format"
        
        print(f"\n✓ Time range query:\n{query}")

    def test_event_type_inference(self, query_builder):
        """Test that event types are correctly inferred from intent."""
        # Process query
        result = query_builder.build_query(
            dataset="events",
            natural_language_intent="powershell execution",
        )
        assert "#event_simpleName=ProcessRollup2" in result["query"], \
            "Process queries should get ProcessRollup2 event type"
        
        # Network query
        result = query_builder.build_query(
            dataset="events",
            natural_language_intent="network connections to external IP",
        )
        assert "#event_simpleName=NetworkConnectIP4" in result["query"], \
            "Network queries should get NetworkConnectIP4 event type"
        
        # File query
        result = query_builder.build_query(
            dataset="events",
            natural_language_intent="file written to disk",
        )
        assert "#event_simpleName=FileWritten" in result["query"], \
            "File queries should get FileWritten event type"

    def test_no_timestamp_in_wrong_fields(self, query_builder):
        """
        Regression test: ensure timestamp components never end up in wrong fields.
        
        This was the core bug: time components like "21:33:06" were being extracted
        and placed in fields like LocalAddressIP4.
        """
        result = query_builder.build_query(
            dataset="events",
            natural_language_intent=(
                "Find activity on device HOST-123 at 2025-12-01 21:33:06 UTC "
                "with process cmd.exe connecting to 10.0.0.1"
            ),
        )

        query = result["query"]
        
        # Verify the ACTUAL IP is in the query
        assert "10.0.0.1" in query, "Actual IP should be extracted"
        
        # Verify timestamp components are NOT in wrong places
        # These should NEVER appear as standalone filter values
        assert "= '21:33:06'" not in query.replace("@timestamp", ""), \
            "Time should not be a filter value outside @timestamp"
        assert "= '21'" not in query.replace("@timestamp", ""), \
            "Hour should not be extracted as separate value"
        assert "= '33'" not in query.replace("@timestamp", ""), \
            "Minute should not be extracted as separate value"
        assert "= '06'" not in query.replace("@timestamp", ""), \
            "Second should not be extracted as separate value"
        
        # Verify correct components ARE in query
        assert "HOST-123" in query, "Device name should be present"
        assert "cmd.exe" in query, "Process name should be present"
        
        print(f"\n✓ Complex query with no timestamp contamination:\n{query}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
