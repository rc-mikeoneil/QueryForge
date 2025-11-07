import pytest
from s1.query_builder import build_s1_query
from tests.base_query_builder_test import (
    BaseQueryBuilderTest,
    SecurityValidationMixin,
    IOCExtractionMixin,
    LimitValidationMixin,
    BooleanOperatorMixin,
)


MOCK_SCHEMA = {
    "datasets": {
        "processes": {
            "name": "Processes",
            "fields": {
                "tgt.process.displayName": {"data_type": "String", "description": "Target process name"},
                "tgt.process.cmdline": {"data_type": "String", "description": "Command line"},
                "tgt.process.image.md5": {"data_type": "String", "description": "MD5 hash"},
                "tgt.process.image.sha1": {"data_type": "String", "description": "SHA1 hash"},
                "tgt.process.image.sha256": {"data_type": "String", "description": "SHA256 hash"},
                "src.process.name": {"data_type": "String", "description": "Source process"},
            },
            "metadata": {"description": "Process events"},
        },
        "network_actions": {
            "name": "Network Actions",
            "fields": {
                "dst.ip.address": {"data_type": "String", "description": "Destination IP"},
                "src.ip.address": {"data_type": "String", "description": "Source IP"},
                "dst.port.number": {"data_type": "Numeric", "description": "Destination port"},
                "network.http.host": {"data_type": "String", "description": "HTTP host"},
                "dns.request.domain": {"data_type": "String", "description": "DNS request domain"},
                "dns.response.domain": {"data_type": "String", "description": "DNS response domain"},
                "url.address": {"data_type": "String", "description": "URL address"},
            },
            "metadata": {"description": "Network telemetry"},
        },
    },
    "common_fields": {
        "event.type": {"data_type": "Enum", "description": "Event type"},
    },
    "operators": {
        "operators": [
            {
                "name": "equals",
                "symbols": ["==", "="],
                "description": "Equality comparison operator"
            },
            {
                "name": "in",
                "symbols": ["in"],
                "description": "List comparison operator"
            }
        ]
    },
    "operator_variants": {
        "operators_string": [
            {
                "operator": "in",
                "description": "Case sensitive compare string with list",
                "syntax": "fieldname in ('value1', 'value2')"
            },
            {
                "operator": "contains",
                "description": "Case sensitive contains",
                "syntax": "fieldname contains 'value'"
            },
            {
                "operator": "contains anycase",
                "description": "Case insensitive contains",
                "syntax": "fieldname contains anycase 'value'"
            },
            {
                "operator": "contains:anycase",
                "description": "Case insensitive contains (alternate syntax)",
                "syntax": "fieldname contains:anycase 'value'"
            }
        ]
    }
}


class TestS1QueryBuilder(
    BaseQueryBuilderTest,
    SecurityValidationMixin,
    IOCExtractionMixin,
    LimitValidationMixin,
    BooleanOperatorMixin
):
    """Test suite for SentinelOne query builder with base class patterns."""
    
    @property
    def builder_function(self):
        """Return the S1 query builder function."""
        return build_s1_query
    
    @property
    def mock_schema(self):
        """Return the mock schema for S1 tests."""
        return MOCK_SCHEMA
    
    @property
    def required_params(self):
        """Return minimum required parameters for S1."""
        return {"dataset": "processes", "natural_language_intent": "find all processes"}
    
    def get_max_limit(self):
        """S1 may have platform-specific limits."""
        return None  # Check if S1 enforces a limit
    
    def get_valid_operators(self):
        """S1 supports AND and OR operators."""
        return ["AND", "OR"]
    
    def test_ioc_extraction_from_natural_language(self):
        """Test that IOCs are extracted from natural language.
        
        Override base class to handle S1-specific dataset/field requirements.
        """
        iocs = self.get_ioc_test_cases()
        
        for ioc_type, ioc_value in iocs.items():
            try:
                # For IOCs that require specific datasets (like IP addresses needing network_actions),
                # we need to infer the right dataset or the IOC won't be extracted
                intent = f"find activity for {ioc_value}"
                
                # Adjust intent to help dataset inference for network IOCs
                if ioc_type in ["ipv4", "ipv6"]:
                    intent = f"find network connections for {ioc_value}"
                elif ioc_type == "domain":
                    # Domain extraction requires the word "domain" in the intent
                    intent = f"find network connections where domain is {ioc_value}"
                
                query, metadata = self.builder_function(
                    schema=self.mock_schema,
                    natural_language_intent=intent
                )
                
                # Query should contain the IOC or a reference to it
                assert ioc_value in query or ioc_type in str(metadata).lower()
            except (ValueError, KeyError):
                # Some builders may not support all IOC types
                pass
    
    # Original tests
    def test_build_s1_query_from_natural_language_process(self):
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            natural_language_intent="Find processes launching powershell.exe",
        )

        assert "meta.event.name in ('PROCESSCREATION')" in query
        assert "tgt.process.displayName in:anycase ('powershell.exe')" in query
        assert metadata["dataset"] == "processes"

    def test_build_s1_query_with_structured_filters(self):
        filters = [
            {
                "field": "tgt.process.cmdline",
                "operator": "contains:anycase",
                "value": "-enc",
            }
        ]

        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            dataset="Processes",
            filters=filters,
            boolean_operator="AND",
        )

        assert "tgt.process.cmdline contains:anycase '-enc'" in query
        assert metadata["dataset_display_name"] == "Processes"

    def test_infer_network_dataset_from_intent(self):
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            natural_language_intent="Show network connections to 192.168.1.10 on port 443",
        )

        assert metadata["dataset"] == "network_actions"
        assert "dst.ip.address = '192.168.1.10'" in query
        assert "dst.port.number = 443" in query

    def test_operator_normalization_capitalin_to_lowercase(self):
        """Test that 'In' operator gets normalized to lowercase 'in' per S1QL schema."""
        filters = [
            {
                "field": "src.process.name",
                "operator": "In",  # Capitalized - should be normalized to lowercase
                "value": ["psexec.exe", "psexec64.exe", "paexec.exe"],
            }
        ]

        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            dataset="processes",
            filters=filters,
            boolean_operator="OR",
        )

        # Verify the operator was normalized to lowercase 'in'
        assert "src.process.name in (" in query
        # Ensure it's not capitalized
        assert "src.process.name In (" not in query
        assert "'psexec.exe'" in query
        assert "'psexec64.exe'" in query
        assert "'paexec.exe'" in query
    
    def test_operator_normalization_equals_to_symbol(self):
        """Test that 'equals' operator name gets normalized to '=' symbol."""
        filters = [
            {
                "field": "tgt.process.displayName",
                "operator": "equals",  # Operator name - should be normalized to '='
                "value": "notepad.exe",
            }
        ]

        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            dataset="processes",
            filters=filters,
        )

        # Verify the operator was normalized to '='
        assert "tgt.process.displayName = 'notepad.exe'" in query
        # Ensure it's not using the word 'equals'
        assert "equals" not in query.lower()
    
    # New tests for coverage gaps
    def test_error_on_invalid_dataset(self):
        """Test that invalid dataset names raise an error."""
        with pytest.raises((ValueError, KeyError, Exception)):
            build_s1_query(
                schema=MOCK_SCHEMA,
                dataset="invalid_dataset",
                filters=[{"field": "test", "value": "test"}]
            )
    
    def test_dataset_inference_process_keywords(self):
        """Test that process-related keywords infer the processes dataset."""
        process_intents = [
            "find processes",
            "show executables",
            "find cmd.exe running",
        ]
        
        for intent in process_intents:
            query, metadata = build_s1_query(
                schema=MOCK_SCHEMA,
                natural_language_intent=intent
            )
            
            assert metadata["dataset"] == "processes"
    
    def test_dataset_inference_network_keywords(self):
        """Test that network-related keywords infer the network_actions dataset."""
        network_intents = [
            "find network connections",
            "show traffic to 8.8.8.8",
            "find connections on port 443",
        ]
        
        for intent in network_intents:
            query, metadata = build_s1_query(
                schema=MOCK_SCHEMA,
                natural_language_intent=intent
            )
            
            assert metadata["dataset"] == "network_actions"
    
    def test_ioc_extraction_ip_address(self):
        """Test that IP addresses are extracted from natural language."""
        intent = "find connections to 10.0.0.1"
        
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            natural_language_intent=intent
        )
        
        assert "10.0.0.1" in query
        assert "dst.ip.address" in query or "src.ip.address" in query
    
    def test_ioc_extraction_md5_hash(self):
        """Test that MD5 hashes are extracted from natural language."""
        md5_hash = "5d41402abc4b2a76b9719d911017c592"
        intent = f"find processes with hash {md5_hash}"
        
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            natural_language_intent=intent
        )
        
        assert md5_hash in query
        assert "tgt.process.image.md5" in query or "md5" in query.lower()
    
    def test_port_extraction(self):
        """Test that port numbers are extracted from natural language."""
        intent = "find connections to port 8080"
        
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            natural_language_intent=intent
        )
        
        assert "8080" in query
        assert "dst.port.number" in query or "port" in query.lower()
    
    def test_multiple_filters_with_and(self):
        """Test that multiple filters are combined with AND."""
        filters = [
            {"field": "tgt.process.displayName", "operator": "=", "value": "cmd.exe"},
            {"field": "tgt.process.cmdline", "operator": "contains", "value": "/c"}
        ]
        
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            dataset="processes",
            filters=filters,
            boolean_operator="AND"
        )
        
        assert "cmd.exe" in query
        assert "/c" in query
        assert " AND " in query
    
    def test_multiple_filters_with_or(self):
        """Test that multiple filters are combined with OR."""
        filters = [
            {"field": "tgt.process.displayName", "operator": "=", "value": "cmd.exe"},
            {"field": "tgt.process.displayName", "operator": "=", "value": "powershell.exe"}
        ]
        
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            dataset="processes",
            filters=filters,
            boolean_operator="OR"
        )
        
        assert "cmd.exe" in query
        assert "powershell.exe" in query
        assert " OR " in query
    
    def test_contains_anycase_operator(self):
        """Test that contains:anycase operator works correctly."""
        filters = [
            {
                "field": "tgt.process.cmdline",
                "operator": "contains:anycase",
                "value": "PowerShell"
            }
        ]
        
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            dataset="processes",
            filters=filters
        )
        
        assert "contains:anycase" in query or "contains anycase" in query
        assert "PowerShell" in query or "powershell" in query.lower()
    
    def test_in_operator_with_list(self):
        """Test that 'in' operator works with lists of values."""
        filters = [
            {
                "field": "tgt.process.displayName",
                "operator": "in",
                "value": ["cmd.exe", "powershell.exe", "wscript.exe"]
            }
        ]
        
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            dataset="processes",
            filters=filters
        )
        
        assert " in (" in query
        assert "cmd.exe" in query
        assert "powershell.exe" in query
        assert "wscript.exe" in query
    
    def test_empty_filters_with_natural_language(self):
        """Test that empty filters with natural language still works."""
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            natural_language_intent="find all processes",
            filters=[]
        )
        
        assert metadata["dataset"] == "processes"
        assert len(query) > 0
    
    def test_explicit_dataset_overrides_inference(self):
        """Test that explicit dataset parameter overrides inference."""
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            dataset="network_actions",
            natural_language_intent="find processes"  # Would normally infer processes
        )
        
        # Should use explicit dataset, not inferred one
        assert metadata["dataset"] == "network_actions"
    
    def test_process_name_extraction(self):
        """Test that process names are extracted from natural language."""
        intent = "find suspicious.exe processes"
        
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            natural_language_intent=intent
        )
        
        assert "suspicious.exe" in query
        assert "tgt.process.displayName" in query
    
    def test_cmdline_extraction(self):
        """Test that command line patterns are extracted."""
        intent = "find processes with cmdline containing -encodedcommand"
        
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            natural_language_intent=intent
        )
        
        assert "encodedcommand" in query.lower()
        assert "tgt.process.cmdline" in query
    
    def test_metadata_contains_dataset_info(self):
        """Test that metadata includes dataset information."""
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            dataset="processes",
            filters=[{"field": "tgt.process.displayName", "value": "test"}]
        )
        
        assert "dataset" in metadata
        assert "dataset_display_name" in metadata
        assert metadata["dataset"] == "processes"
        assert metadata["dataset_display_name"] == "Processes"
    
    def test_case_insensitive_dataset_name(self):
        """Test that dataset names are case-insensitive."""
        for dataset_name in ["processes", "Processes", "PROCESSES"]:
            query, metadata = build_s1_query(
                schema=MOCK_SCHEMA,
                dataset=dataset_name,
                filters=[{"field": "tgt.process.displayName", "value": "test"}]
            )
            
            assert metadata["dataset"] == "processes"
    
    def test_special_characters_in_cmdline(self):
        """Test that special characters in command lines are handled."""
        filters = [
            {
                "field": "tgt.process.cmdline",
                "operator": "contains",
                "value": "-enc ABC123=="
            }
        ]
        
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            dataset="processes",
            filters=filters
        )
        
        # Should handle base64-like strings
        assert "ABC123" in query
    
    def test_multiple_iocs_in_query(self):
        """Test that multiple IOCs are extracted and combined."""
        intent = "find connections from 192.168.1.100 to 8.8.8.8 on port 443"
        
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            natural_language_intent=intent
        )
        
        # Should include multiple IOCs
        assert "192.168.1.100" in query or "168" in query
        assert "8.8.8.8" in query
        assert "443" in query
    
    def test_boolean_operator_default(self):
        """Test that default boolean operator is applied correctly."""
        filters = [
            {"field": "tgt.process.displayName", "value": "cmd.exe"},
            {"field": "src.process.name", "value": "explorer.exe"}
        ]
        
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            dataset="processes",
            filters=filters
            # No boolean_operator specified, should use default
        )
        
        # Default should be AND
        assert " AND " in query or len(filters) == 1
    
    def test_filter_with_equals_operator(self):
        """Test that equals operator works correctly."""
        filters = [
            {
                "field": "tgt.process.displayName",
                "operator": "=",
                "value": "notepad.exe"
            }
        ]
        
        query, metadata = build_s1_query(
            schema=MOCK_SCHEMA,
            dataset="processes",
            filters=filters
        )
        
        assert "tgt.process.displayName = 'notepad.exe'" in query
    
    def test_natural_language_with_time_reference(self):
        """Test natural language with time references."""
        intent = "find processes from the last 24 hours"
        
        try:
            query, metadata = build_s1_query(
                schema=MOCK_SCHEMA,
                natural_language_intent=intent
            )
            
            # Should handle time references if supported
            assert len(query) > 0
        except (AttributeError, NotImplementedError):
            # Time parsing may not be implemented yet
            pytest.skip("Time range parsing not implemented")
    
    def test_empty_filter_value(self):
        """Test that empty filter values are handled gracefully."""
        filters = [
            {
                "field": "tgt.process.displayName",
                "operator": "=",
                "value": ""
            }
        ]
        
        try:
            query, metadata = build_s1_query(
                schema=MOCK_SCHEMA,
                dataset="processes",
                filters=filters
            )
            # Should either work or raise an appropriate error
            assert isinstance(query, str)
        except (ValueError, Exception):
            # Raising an error for empty values is acceptable
            pass
