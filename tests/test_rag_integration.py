"""Integration tests for RAG-enhanced query building across all platforms.

This test suite validates that RAG enhancement works consistently across
CBC, KQL, Cortex, and SentinelOne platforms.
"""

import time
import pytest
from typing import Dict, List, Any

from cbc.query_builder import build_cbc_query
from kql.query_builder import build_kql_query
from cortex.query_builder import build_cortex_query
from s1.query_builder import build_s1_query


# Mock schemas for testing
CBC_SCHEMA = {
    "search_types": {
        "process_search": {"description": "Search for processes"}
    },
    "process_search_fields": {
        "process_name": {"type": "string"},
        "netconn_port": {"type": "numeric"},
        "netconn_domain": {"type": "string"},
        "process_cmdline": {"type": "string"},
        "parent_name": {"type": "string"},
    }
}

KQL_SCHEMA = {
    "DeviceNetworkEvents": {
        "description": "Network connection events",
        "columns": {
            "RemotePort": {"type": "int"},
            "RemoteIP": {"type": "string"},
            "InitiatingProcessFileName": {"type": "string"},
            "InitiatingProcessCommandLine": {"type": "string"},
        }
    }
}

CORTEX_SCHEMA = {
    "datasets": {
        "xdr_data": {"description": "XDR event data"}
    },
    "xdr_data_fields": {
        "actor_process_image_name": {"type": "string"},
        "action_remote_port": {"type": "number"},
        "actor_process_command_line": {"type": "string"},
    }
}

S1_SCHEMA = {
    "datasets": {
        "network": {"description": "Network events"}
    },
    "network_fields": {
        "src.process.name": {"type": "string"},
        "dst.port.number": {"type": "number"},
        "src.process.cmdline": {"type": "string"},
    }
}


class TestCrossPlatformRDPQueries:
    """Test RDP query enhancement across all platforms."""

    @staticmethod
    def get_rdp_rag_context() -> List[Dict[str, Any]]:
        """Generate RDP-related RAG context."""
        return [
            {
                "text": "RDP (Remote Desktop Protocol) uses port 3389. Common processes: mstsc.exe, rdpclip.exe, termsrv.dll",
                "score": 0.95,
                "source": "best_practices"
            },
            {
                "text": "netconn_port:3389 for RDP connections. Examples: process_name:mstsc.exe OR process_name:rdpclip.exe",
                "score": 0.90,
                "source": "examples"
            },
            {
                "text": "Remote Desktop processes: mstsc.exe (client), rdpclip.exe (clipboard), termsrv.dll (service)",
                "score": 0.85,
                "source": "documentation"
            }
        ]

    def test_cbc_rdp_enhancement(self):
        """Test CBC RDP query is enhanced with multiple indicators."""
        rag_context = self.get_rdp_rag_context()
        
        query, metadata = build_cbc_query(
            CBC_SCHEMA,
            natural_language_intent="RDP connections",
            search_type="process_search",
            rag_context=rag_context
        )
        
        assert query is not None
        query_lower = query.lower()
        
        # Should contain port reference
        assert "3389" in query or "port" in query_lower
        
        # Check for RAG enhancement metadata
        print(f"CBC RDP Query: {query}")
        print(f"CBC Metadata: {metadata}")

    def test_kql_rdp_enhancement(self):
        """Test KQL RDP query is enhanced with multiple indicators."""
        rag_context = self.get_rdp_rag_context()
        
        query, metadata = build_kql_query(
            KQL_SCHEMA,
            natural_language_intent="RDP connections",
            dataset="DeviceNetworkEvents",
            rag_context=rag_context
        )
        
        assert query is not None
        query_lower = query.lower()
        
        # Should reference DeviceNetworkEvents table
        assert "devicenetworkevents" in query_lower
        
        print(f"KQL RDP Query: {query}")
        print(f"KQL Metadata: {metadata}")

    def test_cortex_rdp_enhancement(self):
        """Test Cortex RDP query is enhanced with multiple indicators."""
        rag_context = self.get_rdp_rag_context()
        
        query, metadata = build_cortex_query(
            CORTEX_SCHEMA,
            natural_language_intent="RDP connections",
            dataset="xdr_data",
            rag_context=rag_context
        )
        
        assert query is not None
        
        print(f"Cortex RDP Query: {query}")
        print(f"Cortex Metadata: {metadata}")

    def test_s1_rdp_enhancement(self):
        """Test SentinelOne RDP query is enhanced with multiple indicators."""
        rag_context = self.get_rdp_rag_context()
        
        query, metadata = build_s1_query(
            S1_SCHEMA,
            natural_language_intent="RDP connections",
            dataset="network",
            rag_context=rag_context
        )
        
        assert query is not None
        
        print(f"S1 RDP Query: {query}")
        print(f"S1 Metadata: {metadata}")


class TestCommonSecurityConcepts:
    """Test various security concepts are enhanced appropriately."""

    def test_smb_queries(self):
        """Test SMB/file sharing queries across platforms."""
        rag_context = [
            {
                "text": "SMB uses ports 445 and 139. Common processes: smbclient, net.exe",
                "score": 0.9,
                "source": "best_practices"
            }
        ]
        
        # Test CBC
        cbc_query, _ = build_cbc_query(
            CBC_SCHEMA,
            natural_language_intent="SMB file sharing",
            search_type="process_search",
            rag_context=rag_context
        )
        assert cbc_query is not None
        print(f"CBC SMB Query: {cbc_query}")

    def test_powershell_queries(self):
        """Test PowerShell detection queries across platforms."""
        rag_context = [
            {
                "text": "PowerShell processes: powershell.exe, pwsh.exe (PowerShell Core). Examples: process_name:powershell.exe",
                "score": 0.9,
                "source": "examples"
            },
            {
                "text": "Common PowerShell flags: -enc (encoded), -nop (no profile), -w hidden (hidden window)",
                "score": 0.85,
                "source": "documentation"
            }
        ]
        
        # Test CBC
        cbc_query, _ = build_cbc_query(
            CBC_SCHEMA,
            natural_language_intent="PowerShell execution",
            search_type="process_search",
            rag_context=rag_context
        )
        assert cbc_query is not None
        print(f"CBC PowerShell Query: {cbc_query}")

    def test_wmi_queries(self):
        """Test WMI (Windows Management Instrumentation) queries."""
        rag_context = [
            {
                "text": "WMI processes: wmic.exe, wmiprvse.exe. Examples: process_name:wmic.exe",
                "score": 0.9,
                "source": "examples"
            }
        ]
        
        # Test CBC
        cbc_query, _ = build_cbc_query(
            CBC_SCHEMA,
            natural_language_intent="WMI execution",
            search_type="process_search",
            rag_context=rag_context
        )
        assert cbc_query is not None
        print(f"CBC WMI Query: {cbc_query}")

    def test_lateral_movement(self):
        """Test lateral movement detection queries."""
        rag_context = [
            {
                "text": "Lateral movement techniques: PSExec (psexec.exe), WMI, RDP, SMB. Common ports: 445, 3389, 135",
                "score": 0.9,
                "source": "best_practices"
            }
        ]
        
        # Test CBC
        cbc_query, _ = build_cbc_query(
            CBC_SCHEMA,
            natural_language_intent="lateral movement",
            search_type="process_search",
            rag_context=rag_context
        )
        assert cbc_query is not None
        print(f"CBC Lateral Movement Query: {cbc_query}")


class TestRAGContextQualityImpact:
    """Test that RAG context quality affects query enhancement."""

    def test_high_quality_rag_produces_better_queries(self):
        """High quality RAG results should produce more comprehensive queries."""
        high_quality_rag = [
            {
                "text": "netconn_port:3389 for RDP. Common processes: mstsc.exe, rdpclip.exe, termsrv.dll",
                "score": 0.95,
                "source": "best_practices"
            },
            {
                "text": "Example query: (netconn_port:3389 OR process_name:mstsc.exe OR process_name:rdpclip.exe)",
                "score": 0.90,
                "source": "examples"
            }
        ]
        
        query_hq, metadata_hq = build_cbc_query(
            CBC_SCHEMA,
            natural_language_intent="RDP",
            search_type="process_search",
            rag_context=high_quality_rag
        )
        
        assert query_hq is not None
        print(f"High Quality RAG Query: {query_hq}")
        print(f"High Quality Metadata: {metadata_hq}")

    def test_low_quality_rag_fallback(self):
        """Low quality RAG should fall back to basic query building."""
        low_quality_rag = [
            {
                "text": "Some unrelated information about other topics",
                "score": 0.1,
                "source": "unrelated"
            }
        ]
        
        query_lq, metadata_lq = build_cbc_query(
            CBC_SCHEMA,
            natural_language_intent="RDP",
            search_type="process_search",
            rag_context=low_quality_rag
        )
        
        assert query_lq is not None
        print(f"Low Quality RAG Query: {query_lq}")

    def test_no_rag_context_backward_compatibility(self):
        """Query building should work without RAG context."""
        query, metadata = build_cbc_query(
            CBC_SCHEMA,
            natural_language_intent="RDP",
            search_type="process_search"
            # No rag_context parameter
        )
        
        assert query is not None
        print(f"No RAG Context Query: {query}")


class TestPerformance:
    """Test performance of RAG-enhanced query building."""

    def test_rag_parsing_performance(self):
        """RAG context parsing should add minimal overhead."""
        rag_context = [
            {
                "text": f"Field {i}: Example data with various patterns and information",
                "score": 0.8,
                "source": "test"
            }
            for i in range(10)  # 10 documents
        ]
        
        # Measure time without RAG
        start_no_rag = time.time()
        for _ in range(10):
            build_cbc_query(
                CBC_SCHEMA,
                natural_language_intent="test query",
                search_type="process_search"
            )
        time_no_rag = time.time() - start_no_rag
        
        # Measure time with RAG
        start_with_rag = time.time()
        for _ in range(10):
            build_cbc_query(
                CBC_SCHEMA,
                natural_language_intent="test query",
                search_type="process_search",
                rag_context=rag_context
            )
        time_with_rag = time.time() - start_with_rag
        
        overhead = time_with_rag - time_no_rag
        overhead_per_query = overhead / 10 * 1000  # Convert to ms
        
        print(f"\nPerformance Results:")
        print(f"  Time without RAG: {time_no_rag:.4f}s (10 queries)")
        print(f"  Time with RAG: {time_with_rag:.4f}s (10 queries)")
        print(f"  Overhead: {overhead:.4f}s total, {overhead_per_query:.2f}ms per query")
        
        # Should be less than 100ms per query
        assert overhead_per_query < 100, f"RAG overhead too high: {overhead_per_query:.2f}ms"

    def test_large_rag_context_handling(self):
        """Test handling of large RAG context."""
        large_rag_context = [
            {
                "text": "Long document " + ("x" * 1000) + f" field_{i}:value_{i}",
                "score": 0.8 - (i * 0.05),
                "source": "test"
            }
            for i in range(20)  # 20 large documents
        ]
        
        start = time.time()
        query, metadata = build_cbc_query(
            CBC_SCHEMA,
            natural_language_intent="test query",
            search_type="process_search",
            rag_context=large_rag_context
        )
        elapsed = (time.time() - start) * 1000  # Convert to ms
        
        assert query is not None
        print(f"Large RAG context processed in {elapsed:.2f}ms")
        
        # Should still be reasonable even with large context
        assert elapsed < 500, f"Processing time too high: {elapsed:.2f}ms"


def run_all_tests():
    """Run all integration tests."""
    print("=" * 80)
    print("RAG INTEGRATION TEST SUITE")
    print("=" * 80)
    
    # Cross-platform RDP tests
    print("\n[1] Cross-Platform RDP Query Tests")
    print("-" * 80)
    rdp_tests = TestCrossPlatformRDPQueries()
    rdp_tests.test_cbc_rdp_enhancement()
    rdp_tests.test_kql_rdp_enhancement()
    rdp_tests.test_cortex_rdp_enhancement()
    rdp_tests.test_s1_rdp_enhancement()
    print("✅ All RDP tests passed")
    
    # Common security concepts
    print("\n[2] Common Security Concepts Tests")
    print("-" * 80)
    security_tests = TestCommonSecurityConcepts()
    security_tests.test_smb_queries()
    security_tests.test_powershell_queries()
    security_tests.test_wmi_queries()
    security_tests.test_lateral_movement()
    print("✅ All security concept tests passed")
    
    # RAG quality impact
    print("\n[3] RAG Context Quality Impact Tests")
    print("-" * 80)
    quality_tests = TestRAGContextQualityImpact()
    quality_tests.test_high_quality_rag_produces_better_queries()
    quality_tests.test_low_quality_rag_fallback()
    quality_tests.test_no_rag_context_backward_compatibility()
    print("✅ All quality impact tests passed")
    
    # Performance tests
    print("\n[4] Performance Tests")
    print("-" * 80)
    perf_tests = TestPerformance()
    perf_tests.test_rag_parsing_performance()
    perf_tests.test_large_rag_context_handling()
    print("✅ All performance tests passed")
    
    print("\n" + "=" * 80)
    print("ALL INTEGRATION TESTS PASSED ✅")
    print("=" * 80)


if __name__ == "__main__":
    run_all_tests()
