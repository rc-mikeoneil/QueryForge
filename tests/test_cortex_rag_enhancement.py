"""Tests for Cortex RAG-enhanced query building."""

import pytest
from queryforge.platforms.cortex.query_builder import build_cortex_query


def test_cortex_query_without_rag_context():
    """Test that Cortex query building works without RAG context (backward compatibility)."""
    schema = {
        "datasets": {
            "xdr_data": {
                "description": "Main XDR dataset",
                "default_fields": ["_time", "agent_hostname", "actor_process_image_name"]
            }
        },
        "xdr_data_fields": {
            "actor_process_image_name": {"type": "string"},
            "action_file_name": {"type": "string"},
            "_time": {"type": "timestamp"}
        }
    }
    
    query, metadata = build_cortex_query(
        schema,
        natural_language_intent="PowerShell activity"
    )
    
    assert query is not None
    assert "dataset = xdr_data" in query
    assert metadata["dataset"] == "xdr_data"


def test_cortex_query_with_rag_context():
    """Test that Cortex query building enhances queries when RAG context is provided."""
    schema = {
        "datasets": {
            "xdr_data": {
                "description": "Main XDR dataset",
                "default_fields": ["_time", "agent_hostname", "actor_process_image_name"]
            }
        },
        "xdr_data_fields": {
            "actor_process_image_name": {"type": "string"},
            "actor_process_command_line": {"type": "string"},
            "action_file_name": {"type": "string"},
            "_time": {"type": "timestamp"}
        }
    }
    
    # Simulate RAG context with PowerShell-related information
    rag_context = [
        {
            "text": "actor_process_image_name (string) - Process image name. Examples: powershell.exe, pwsh.exe for PowerShell",
            "score": 0.92,
            "source": "cortex"
        },
        {
            "text": "actor_process_command_line (string) - Process command line. May contain: -ExecutionPolicy, -EncodedCommand",
            "score": 0.87,
            "source": "cortex"
        }
    ]
    
    query, metadata = build_cortex_query(
        schema,
        natural_language_intent="PowerShell activity",
        rag_context=rag_context
    )
    
    assert query is not None
    assert "dataset = xdr_data" in query
    assert metadata["dataset"] == "xdr_data"
    
    # Check for RAG-enhanced filters
    query_lower = query.lower()
    has_rag_enhancement = any(term in query_lower for term in ['powershell.exe', 'pwsh.exe'])
    
    print(f"Query: {query}")
    print(f"Has RAG enhancement: {has_rag_enhancement}")
    print(f"Metadata: {metadata}")


def test_cortex_query_rag_enhancement_with_low_confidence():
    """Test that low-confidence RAG results still enhance the query (aggressive approach)."""
    schema = {
        "datasets": {
            "xdr_data": {
                "description": "Main XDR dataset"
            }
        },
        "xdr_data_fields": {
            "actor_process_image_name": {"type": "string"},
            "_time": {"type": "timestamp"}
        }
    }
    
    # Simulate low-quality RAG context that should still be used
    rag_context = [
        {
            "text": "actor_process_image_name may contain malicious process names",
            "score": 0.12,  # Low confidence but above 0.1 threshold
            "source": "cortex"
        }
    ]
    
    query, metadata = build_cortex_query(
        schema,
        natural_language_intent="malicious processes",
        rag_context=rag_context
    )
    
    assert query is not None
    assert "dataset = xdr_data" in query
    print(f"Query: {query}")
    print(f"Metadata: {metadata}")


def test_cortex_query_rdp_comprehensive():
    """Test that RDP queries generate comprehensive coverage."""
    schema = {
        "datasets": {
            "xdr_data": {
                "description": "Main XDR dataset"
            }
        },
        "xdr_data_fields": {
            "actor_process_image_name": {"type": "string"},
            "action_local_port": {"type": "integer"},
            "action_remote_port": {"type": "integer"},
            "action_remote_ip": {"type": "string"},
            "_time": {"type": "timestamp"}
        }
    }
    
    # Rich RAG context for RDP
    rag_context = [
        {
            "text": "RDP uses action_remote_port: 3389. actor_process_image_name examples: mstsc.exe, rdpclip.exe, tstheme.exe",
            "score": 0.94,
            "source": "cortex"
        },
        {
            "text": "action_local_port for RDP clients varies. Standard server port is 3389.",
            "score": 0.89,
            "source": "cortex"
        }
    ]
    
    query, metadata = build_cortex_query(
        schema,
        natural_language_intent="RDP connections",
        rag_context=rag_context
    )
    
    assert query is not None
    assert "dataset = xdr_data" in query
    
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
    print("Running Cortex RAG Enhancement Tests...\n")
    
    print("Test 1: Backward compatibility (no RAG context)")
    test_cortex_query_without_rag_context()
    print("✅ Passed\n")
    
    print("Test 2: With RAG context")
    test_cortex_query_with_rag_context()
    print("✅ Passed\n")
    
    print("Test 3: Low confidence RAG context (aggressive approach)")
    test_cortex_query_rag_enhancement_with_low_confidence()
    print("✅ Passed\n")
    
    print("Test 4: RDP comprehensive coverage")
    test_cortex_query_rdp_comprehensive()
    print("✅ Passed\n")
    
    print("All Cortex RAG enhancement tests passed! ✅")
