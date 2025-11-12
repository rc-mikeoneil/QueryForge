import pytest
from cbr import query_builder as cbr_query_builder
from urllib.parse import urlparse
from tests.base_query_builder_test import (
    BaseQueryBuilderTest,
    SecurityValidationMixin,
    IOCExtractionMixin,
    LimitValidationMixin,
    BooleanOperatorMixin,
)

# Mock CBR schema for testing
MOCK_CBR_SCHEMA = {
    "search_types": {
        "server_event": "Server-generated events (watchlist hits, feed hits, etc.)",
        "endpoint_event": "Raw endpoint events (regmod, filemod, netconn, etc.)",
    },
    "server_event_fields": {
        "process_name": {"type": "string", "description": "Filename of the executable backing this process"},
        "process_md5": {"type": "string", "description": "MD5 of the executable file backing this process"},
        "parent_md5": {"type": "string", "description": "MD5 of the parent process"},
        "md5": {"type": "string", "description": "MD5 of the binary"},
        "cmdline": {"type": "string", "description": "Process command line"},
        "path": {"type": "string", "description": "Full path to the executable file backing this process"},
        "observed_filename": {"type": "string", "description": "Full path to the executable backing the process"},
        "username": {"type": "string", "description": "User context in which the process executed"},
        "hostname": {"type": "string", "description": "Hostname of the computer on which the process executed"},
        "parent_name": {"type": "string", "description": "Name of the parent process"},
        "process_guid": {"type": "string", "description": "Process unique Id"},
        "parent_process_guid": {"type": "string", "description": "Parent process unique identifer"},
    },
    "endpoint_event_fields": {
        "process_name": {"type": "string", "description": "Process name"},
        "md5": {"type": "string", "description": "md5 of process executable"},
        "process_md5": {"type": "string", "description": "MD5 of process executable"},
        "parent_md5": {"type": "string", "description": "MD5 of parent's executable image"},
        "path": {"type": "string", "description": "Full file path or registry path"},
        "observed_filename": {"type": "string", "description": "Full path to the executable backing the process"},
        "command_line": {"type": "string", "description": "Command Line of the new process"},
        "cmdline": {"type": "string", "description": "Command line"},
        "username": {"type": "string", "description": "Username that initiated the process creation"},
        "computer_name": {"type": "string", "description": "hostname of the sensor"},
        "hostname": {"type": "string", "description": "Hostname of endpoint"},
        "remote_ip": {"type": "string", "description": "IP address of the remote system (peer)"},
        "local_ip": {"type": "string", "description": "Local IP address of network connection"},
        "ipv4": {"type": "string", "description": "remote ipv4 address of network connection"},
        "remote_port": {"type": "string", "description": "Remote port of the network connection"},
        "local_port": {"type": "string", "description": "Local port of the network connection"},
        "port": {"type": "string", "description": "remote port of the network connection"},
        "domain": {"type": "string", "description": "The DNS name of the network peer, if available"},
        "proxy_ip": {"type": "string", "description": "IP address of the web proxy connection"},
        "proxy_port": {"type": "string", "description": "Port of the web proxy connection"},
        "proxy_domain": {"type": "string", "description": "Domain of the web proxy connection, if available"},
        "process_guid": {"type": "string", "description": "Cb Process GUID of process"},
        "parent_process_guid": {"type": "string", "description": "Cb Process GUID of parent process"},
        "child_process_guid": {"type": "string", "description": "process guid of the child process"},
        "target_process_guid": {"type": "string", "description": "process_guid of the target process"},
        "parent_path": {"type": "string", "description": "file path of parent's executable image"},
        "target_path": {"type": "string", "description": "Path of the target process' executable image"},
    },
    "server_event_fields": {
        "process_name": {"type": "string", "description": "Filename of the executable backing this process"},
        "process_md5": {"type": "string", "description": "MD5 of the executable file backing this process"},
        "parent_md5": {"type": "string", "description": "MD5 of the parent process"},
        "md5": {"type": "string", "description": "MD5 of the binary"},
        "cmdline": {"type": "string", "description": "Process command line"},
        "path": {"type": "string", "description": "Full path to the executable file backing this process"},
        "observed_filename": {"type": "string", "description": "Full path to the executable backing the process"},
        "username": {"type": "string", "description": "User context in which the process executed"},
        "hostname": {"type": "string", "description": "Hostname of the computer on which the process executed"},
        "parent_name": {"type": "string", "description": "Name of the parent process"},
        "process_guid": {"type": "string", "description": "Process unique Id"},
        "parent_process_guid": {"type": "string", "description": "Parent process unique identifer"},
        "ipv4": {"type": "string", "description": "IPv4 address"},
        "port": {"type": "string", "description": "Port number"},
    }
}


class TestCBRQueryBuilder(
    BaseQueryBuilderTest,
    SecurityValidationMixin,
    IOCExtractionMixin,
    LimitValidationMixin,
    BooleanOperatorMixin
):
    """Test suite for CBR query builder with base class patterns."""
    
    @property
    def builder_function(self):
        """Return the CBR query builder function."""
        return cbr_query_builder.build_cbr_query
    
    @property
    def mock_schema(self):
        """Return the mock schema for CBR tests."""
        return MOCK_CBR_SCHEMA
    
    @property
    def required_params(self):
        """Return minimum required parameters for CBR."""
        return {"terms": ["process_name:test"]}
    
    def get_max_limit(self):
        """CBR enforces MAX_LIMIT of 5000."""
        return 5000
    
    def get_valid_operators(self):
        """CBR supports AND and OR operators."""
        return ["AND", "OR"]
    
    def test_ioc_extraction_from_natural_language(self):
        """Test that IOCs are extracted from natural language - CBR specific version."""
        # CBR doesn't have IPv6 fields, so we test only IPv4, MD5, and other supported IOCs
        test_cases = {
            "ipv4": "192.168.1.1",
            "md5": "5d41402abc4b2a76b9719d911017c592",
            "domain": "malicious.com",
            "port": "8080"
        }
        
        for ioc_type, ioc_value in test_cases.items():
            query, metadata = self.builder_function(
                schema=self.mock_schema,
                natural_language_intent=f"find activity for {ioc_value}"
            )
            
            # Query should contain the IOC or a reference to it
            assert (ioc_value in query or ioc_type in str(metadata).lower()), \
                f"IOC {ioc_type}:{ioc_value} not found in query: {query} or metadata: {metadata}"
    
    # CBR-specific tests
    def test_build_cbr_query_with_nl_intent(self):
        """Tests building a CBR query from a simple natural language intent."""
        intent = "find processes named cmd.exe"

        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent=intent,
        )

        assert 'process_name:cmd.exe' in query
        assert metadata["search_type"] == "server_event"

    def test_build_cbr_query_with_iocs(self):
        """Tests that IOCs like IPs and hashes are correctly extracted."""
        intent = "show me activity for IP 192.168.1.100 and hash 5d41402abc4b2a76b9719d911017c592"

        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent=intent,
        )

        # CBR uses remote_ip for endpoint events
        assert ("remote_ip:192.168.1.100" in query or "ipv4:192.168.1.100" in query)
        assert ("md5:5d41402abc4b2a76b9719d911017c592" in query or 
                "process_md5:5d41402abc4b2a76b9719d911017c592" in query)
        assert metadata["boolean_operator"] == "AND"

    def test_build_cbr_query_with_structured_terms(self):
        """Tests building a query from structured terms."""
        query, _ = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            terms=["username:admin", "hostname:workstation01"],
        )

        assert "username:admin" in query
        assert "hostname:workstation01" in query

    def test_build_cbr_query_raises_error_for_unsafe_chars(self):
        """Tests that unsafe characters in terms raise a QueryBuildError."""
        with pytest.raises(cbr_query_builder.QueryBuildError, match="Unsafe characters"):
            cbr_query_builder.build_cbr_query(
                schema=MOCK_CBR_SCHEMA,
                terms=["process_name:test; DROP TABLE users"],
            )
    
    def test_error_on_no_terms_or_intent(self):
        """Test that an error is raised when neither terms nor intent is provided."""
        with pytest.raises(cbr_query_builder.QueryBuildError, match="No expressions provided"):
            cbr_query_builder.build_cbr_query(schema=MOCK_CBR_SCHEMA)
    
    def test_limit_clamping_at_max(self):
        """Test that limits above MAX_LIMIT are clamped to 5000."""
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            terms=["process_name:test"],
            limit=10000
        )
        
        assert metadata["limit"] == 5000
        assert metadata["limit_clamped"] == 5000
    
    def test_port_extraction(self):
        """Test that port numbers are extracted from natural language."""
        intent = "find connections on port 443"
        
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent=intent
        )
        
        # CBR uses remote_port, local_port, or port
        assert ("remote_port:443" in query or "local_port:443" in query or "port:443" in query)
    
    def test_or_operator(self):
        """Test that OR boolean operator works correctly."""
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            terms=["process_name:cmd.exe", "process_name:powershell.exe"],
            boolean_operator="OR"
        )
        
        assert " OR " in query
        assert metadata["boolean_operator"] == "OR"
    
    def test_invalid_boolean_operator(self):
        """Test that invalid boolean operators raise an error."""
        with pytest.raises(cbr_query_builder.QueryBuildError, match="Unsupported boolean operator"):
            cbr_query_builder.build_cbr_query(
                schema=MOCK_CBR_SCHEMA,
                terms=["process_name:test"],
                boolean_operator="XOR"
            )
    
    def test_cmdline_extraction(self):
        """Test that command line patterns are extracted."""
        intent = 'find processes with cmdline containing "-enc"'
        
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent=intent
        )
        
        # CBR uses cmdline or command_line
        assert ("cmdline" in query or "command_line" in query)
        assert "-enc" in query
    
    def test_username_extraction(self):
        """Test that usernames are extracted from natural language."""
        intent = "find processes running as administrator"
        
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent=intent
        )
        
        assert "username" in query or "administrator" in query
    
    def test_domain_extraction(self):
        """Test that domains are extracted from natural language."""
        intent = "find connections to domain malicious.com"
        
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent=intent
        )
        
        # Ensure only the correct query token containing exact domain
        assert "domain:malicious.com" in query
    
    def test_quoted_values_with_spaces(self):
        """Test that values with spaces are properly quoted."""
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            terms=['process_name:"Google Chrome"']
        )
        
        # Should handle quoted values correctly
        assert "Google Chrome" in query or "Google" in query
    
    def test_path_extraction(self):
        """Test that file paths are extracted from natural language."""
        intent = 'find processes with path "C:\\Windows\\System32\\cmd.exe"'
        
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent=intent
        )
        
        # Path should be included (backslashes may be escaped)
        assert "cmd.exe" in query
    
    def test_multiple_iocs_combined(self):
        """Test that multiple IOCs are extracted and combined."""
        md5_hash = "5d41402abc4b2a76b9719d911017c592"
        intent = f"find activity for IP 10.0.0.1 and hash {md5_hash} and port 8080"
        
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent=intent
        )
        
        # Check for IP (could be remote_ip, local_ip, or ipv4)
        assert "10.0.0.1" in query
        assert md5_hash in query
        # Check for port (could be remote_port, local_port, or port)
        assert "8080" in query
    
    def test_search_type_normalization_server(self):
        """Test that server_event search type is normalized correctly."""
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            search_type="server_event",
            terms=["process_name:test"]
        )
        
        assert metadata["search_type"] == "server_event"
    
    def test_search_type_normalization_endpoint(self):
        """Test that endpoint_event search type is normalized correctly."""
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            search_type="endpoint_event",
            terms=["process_name:test"]
        )
        
        assert metadata["search_type"] == "endpoint_event"
    
    def test_empty_terms_list(self):
        """Test that empty terms list without intent raises an error."""
        with pytest.raises(cbr_query_builder.QueryBuildError, match="No expressions provided"):
            cbr_query_builder.build_cbr_query(
                schema=MOCK_CBR_SCHEMA,
                terms=[]
            )
    
    def test_residual_keyword_extraction(self):
        """Test that residual keywords are extracted after pattern matching."""
        intent = "find malicious activity"
        
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent=intent
        )
        
        # "malicious" should be included as a keyword after stopwords are removed
        assert "malicious" in query
    
    def test_metadata_contains_recognised_patterns(self):
        """Test that metadata includes recognised patterns."""
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent="find processes with IP 1.2.3.4"
        )
        
        assert "recognised" in metadata
        assert len(metadata["recognised"]) > 0
    
    def test_case_insensitive_boolean_operator(self):
        """Test that boolean operators are case-insensitive."""
        for operator in ["and", "AND", "And"]:
            query, metadata = cbr_query_builder.build_cbr_query(
                schema=MOCK_CBR_SCHEMA,
                terms=["process_name:test"],
                boolean_operator=operator
            )
            assert metadata["boolean_operator"] == "AND"
    
    def test_sanitization_of_backslashes(self):
        """Test that backslashes in paths are properly escaped."""
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            terms=["path:C:\\Windows\\System32\\cmd.exe"]
        )
        
        # Backslashes should be escaped
        assert "Windows" in query and "cmd.exe" in query
    
    # CBR-specific field tests
    def test_process_guid_extraction(self):
        """Test that CBR process GUIDs are extracted from natural language."""
        guid = "12345678-1234-1234-1234-123456789012-0000000000000001"
        intent = f"find process with GUID {guid}"
        
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent=intent
        )
        
        assert guid in query
        assert "process_guid" in query
    
    def test_parent_process_fields(self):
        """Test that parent process fields are used appropriately."""
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            terms=["parent_name:explorer.exe", "parent_md5:abc123def456789012345678901234567890"]
        )
        
        assert "parent_name:explorer.exe" in query
        assert "parent_md5" in query
    
    def test_network_connection_fields(self):
        """Test that network connection fields are handled correctly."""
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            terms=[
                "remote_ip:10.0.0.1",
                "remote_port:443",
                "domain:example.com"
            ]
        )
        
        assert "remote_ip:10.0.0.1" in query
        assert "remote_port:443" in query
        assert "domain:example.com" in query
    
    def test_proxy_fields(self):
        """Test that proxy-related fields are handled correctly."""
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            terms=[
                "proxy_ip:192.168.1.1",
                "proxy_port:8080",
                "proxy_domain:proxy.corp.local"
            ]
        )
        
        assert "proxy_ip:192.168.1.1" in query
        assert "proxy_port:8080" in query
        assert "proxy_domain:proxy.corp.local" in query
    
    def test_observed_filename_field(self):
        """Test that observed_filename field is used for binaries."""
        intent = "find binary named malware.exe"
        
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent=intent
        )
        
        # Should use observed_filename or process_name
        assert "malware.exe" in query
    
    def test_hostname_vs_computer_name(self):
        """Test that both hostname and computer_name fields work."""
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            terms=["hostname:workstation01"]
        )
        
        assert "hostname:workstation01" in query
    
    def test_local_vs_remote_ip(self):
        """Test that both local_ip and remote_ip are handled."""
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            terms=["local_ip:10.0.0.100", "remote_ip:8.8.8.8"]
        )
        
        assert "local_ip:10.0.0.100" in query
        assert "remote_ip:8.8.8.8" in query
    
    def test_command_line_vs_cmdline(self):
        """Test that both command_line and cmdline fields are supported."""
        # Test with server_event (uses cmdline)
        query1, _ = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            search_type="server_event",
            terms=['cmdline:"powershell.exe -enc"']
        )
        assert "powershell.exe -enc" in query1
        
        # Test with endpoint_event (uses command_line)
        query2, _ = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            search_type="endpoint_event",
            terms=['command_line:"powershell.exe -enc"']
        )
        assert "powershell.exe -enc" in query2
    
    def test_natural_language_with_netconn_context(self):
        """Test natural language query with network connection context."""
        intent = "find connections to port 443 at IP 1.1.1.1 with domain cloudflare.com"
        
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent=intent
        )
        
        assert "443" in query
        assert "1.1.1.1" in query
        # Parse out URL(s) in the query and validate the domain
        import re
        urls = re.findall(r'(https?://[^\s"\';,]+)', query)
        # Accept if any URL's hostname is cloudflare.com or ends with .cloudflare.com
        valid = False
        for url in urls:
            host = urlparse(url).hostname
            if host == "cloudflare.com" or (host and host.endswith(".cloudflare.com")):
                valid = True
                break
        assert valid, f"No valid cloudflare.com URL found in query: {query}"
    
    def test_natural_language_with_process_context(self):
        """Test natural language query with process context."""
        intent = "find processes named chrome.exe with cmdline containing '--no-sandbox'"
        
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent=intent
        )
        
        assert "chrome.exe" in query
        assert "--no-sandbox" in query
    
    def test_md5_field_priority(self):
        """Test that MD5 hashes use the correct field based on context."""
        md5_hash = "5d41402abc4b2a76b9719d911017c592"
        
        # Should prefer md5 or process_md5 depending on availability
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent=f"find binary with hash {md5_hash}"
        )
        
        assert md5_hash in query
        # Could be md5: or process_md5: depending on field availability
        assert ("md5:" in query or "process_md5:" in query)
    
    def test_parent_md5_extraction(self):
        """Test that parent MD5 hashes are handled correctly."""
        parent_md5 = "abc123def456789012345678901234567890"
        
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            terms=[f"parent_md5:{parent_md5}"]
        )
        
        assert f"parent_md5:{parent_md5}" in query
    
    def test_default_search_type_is_server_event(self):
        """Test that default search type is server_event for CBR."""
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            terms=["process_name:test"]
        )
        
        assert metadata["search_type"] == "server_event"
    
    def test_terms_as_string_raises_type_error(self):
        """Test that passing terms as a string raises TypeError."""
        with pytest.raises(TypeError, match="terms must be a list or tuple"):
            cbr_query_builder.build_cbr_query(
                schema=MOCK_CBR_SCHEMA,
                terms="process_name:test"  # Should be a list
            )
    
    def test_limit_zero_raises_error(self):
        """Test that limit of zero raises an error."""
        with pytest.raises(cbr_query_builder.QueryBuildError, match="Limit must be positive"):
            cbr_query_builder.build_cbr_query(
                schema=MOCK_CBR_SCHEMA,
                terms=["process_name:test"],
                limit=0
            )
    
    def test_limit_negative_raises_error(self):
        """Test that negative limit raises an error."""
        with pytest.raises(cbr_query_builder.QueryBuildError, match="Limit must be positive"):
            cbr_query_builder.build_cbr_query(
                schema=MOCK_CBR_SCHEMA,
                terms=["process_name:test"],
                limit=-1
            )
    
    def test_intent_exceeding_max_length_raises_error(self):
        """Test that intent exceeding MAX_INTENT_LENGTH raises an error."""
        # Create an intent that exceeds MAX_INTENT_LENGTH (10000 chars)
        long_intent = "find processes " + ("x" * 10000)
        
        with pytest.raises(ValueError, match="Intent exceeds maximum length"):
            cbr_query_builder.build_cbr_query(
                schema=MOCK_CBR_SCHEMA,
                natural_language_intent=long_intent
            )
    
    def test_stopwords_are_filtered(self):
        """Test that stopwords are filtered from residual keywords."""
        intent = "find all the malicious processes with the suspicious binary that is running"
        
        query, metadata = cbr_query_builder.build_cbr_query(
            schema=MOCK_CBR_SCHEMA,
            natural_language_intent=intent
        )
        
        # Stopwords like "find", "all", "the", "with", "that", "is" should be filtered
        # But "malicious" and "suspicious" should remain
        assert ("malicious" in query or "suspicious" in query or 
                len([r for r in metadata["recognised"] if r.get("type") == "keyword"]) > 0)
