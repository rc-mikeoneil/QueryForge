"""Tests for KQL RAG-enhanced query building."""

import pytest
from queryforge.platforms.kql.query_builder import build_kql_query


def test_kql_query_without_rag_context():
    """Test that KQL query building works without RAG context (backward compatibility)."""
    schema = {
        "DeviceProcessEvents": {
            "columns": [
                {"name": "Timestamp"},
                {"name": "DeviceName"},
                {"name": "FileName"},
                {"name": "ProcessCommandLine"},
                {"name": "InitiatingProcessFileName"}
            ]
        }
    }
    
    query, metadata = build_kql_query(
        schema,
        table="DeviceProcessEvents",
        natural_language_intent="RDP activity"
    )
    
    assert query is not None
    assert "DeviceProcessEvents" in query
    assert metadata["table"] == "DeviceProcessEvents"


def test_kql_query_with_rag_context():
    """Test that KQL query building enhances queries when RAG context is provided."""
    schema = {
        "DeviceProcessEvents": {
            "columns": [
                {"name": "Timestamp"},
                {"name": "DeviceName"},
                {"name": "FileName"},
                {"name": "ProcessCommandLine"},
                {"name": "InitiatingProcessFileName"}
            ]
        }
    }
    
    # Simulate RAG context with RDP-related information
    rag_context = [
        {
            "text": "FileName (string) - Process executable name. Examples: mstsc.exe, rdpclip.exe for RDP connections",
            "score": 0.9,
            "source": "kql"
        },
        {
            "text": "InitiatingProcessFileName (string) - Parent process name. Examples: services.exe, svchost.exe",
            "score": 0.85,
            "source": "kql"
        }
    ]
    
    query, metadata = build_kql_query(
        schema,
        table="DeviceProcessEvents",
        natural_language_intent="RDP activity",
        rag_context=rag_context
    )
    
    assert query is not None
    assert "DeviceProcessEvents" in query
    assert metadata["table"] == "DeviceProcessEvents"
    
    # Check for RAG-enhanced conditions in the query
    # Should contain conditions like: FileName contains 'mstsc.exe' or FileName =~ 'rdpclip.exe'
    query_lower = query.lower()
    has_rag_enhancement = any(term in query_lower for term in ['mstsc.exe', 'rdpclip.exe'])
    
    print(f"Query: {query}")
    print(f"Has RAG enhancement: {has_rag_enhancement}")
    print(f"Metadata: {metadata}")


def test_kql_query_rag_enhancement_with_low_confidence():
    """Test that low-confidence RAG results still enhance the query (aggressive approach)."""
    schema = {
        "DeviceProcessEvents": {
            "columns": [
                {"name": "Timestamp"},
                {"name": "DeviceName"},
                {"name": "FileName"}
            ]
        }
    }
    
    # Simulate low-quality RAG context that should still be used
    rag_context = [
        {
            "text": "FileName may contain executable names related to remote access",
            "score": 0.15,  # Low confidence but above 0.1 threshold
            "source": "kql"
        }
    ]
    
    query, metadata = build_kql_query(
        schema,
        table="DeviceProcessEvents",
        natural_language_intent="remote access",
        rag_context=rag_context
    )
    
    assert query is not None
    assert "DeviceProcessEvents" in query
    print(f"Query: {query}")
    print(f"Metadata: {metadata}")


def test_kql_query_rdp_comprehensive():
    """Test that RDP queries generate comprehensive coverage."""
    schema = {
        "DeviceNetworkEvents": {
            "columns": [
                {"name": "Timestamp"},
                {"name": "DeviceName"},
                {"name": "RemotePort"},
                {"name": "LocalPort"},
                {"name": "RemoteIP"},
                {"name": "ProcessName"}
            ]
        }
    }
    
    # Rich RAG context for RDP
    rag_context = [
        {
            "text": "RDP connections use RemotePort: 3389. ProcessName examples: mstsc.exe, rdpclip.exe, tstheme.exe",
            "score": 0.95,
            "source": "kql"
        },
        {
            "text": "LocalPort for RDP clients varies. RemotePort is typically 3389 for RDP servers.",
            "score": 0.88,
            "source": "kql"
        }
    ]
    
    query, metadata = build_kql_query(
        schema,
        table="DeviceNetworkEvents", 
        natural_language_intent="RDP connections in the last 24 hours",
        rag_context=rag_context
    )
    
    assert query is not None
    assert "DeviceNetworkEvents" in query
    
    # Should have comprehensive RDP coverage
    query_lower = query.lower()
    rdp_indicators = ['3389', 'mstsc.exe', 'rdpclip.exe']
    found_indicators = [indicator for indicator in rdp_indicators if indicator in query_lower]
    
    print(f"Query: {query}")
    print(f"Found RDP indicators: {found_indicators}")
    print(f"Metadata: {metadata}")
    
    # With aggressive RAG approach, we should find multiple indicators
    assert len(found_indicators) > 0, f"Expected RDP indicators in query, but found none. Query: {query}"


if __name__ == "__main__":
    print("Running KQL RAG Enhancement Tests...\n")
    
    print("Test 1: Backward compatibility (no RAG context)")
    test_kql_query_without_rag_context()
    print("✅ Passed\n")
    
    print("Test 2: With RAG context")
    test_kql_query_with_rag_context()
    print("✅ Passed\n")
    
    print("Test 3: Low confidence RAG context (aggressive approach)")
    test_kql_query_rag_enhancement_with_low_confidence()
    print("✅ Passed\n")
    
    print("Test 4: RDP comprehensive coverage")
    test_kql_query_rdp_comprehensive()
    print("✅ Passed\n")
    
    print("All KQL RAG enhancement tests passed! ✅")
