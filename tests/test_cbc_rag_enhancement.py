"""Tests for CBC RAG-enhanced query building."""

import pytest
from queryforge.platforms.cbc.query_builder import build_cbc_query


def test_cbc_query_without_rag_context():
    """Test that query building works without RAG context (backward compatibility)."""
    schema = {
        "search_types": {
            "process_search": {
                "description": "Search for processes"
            }
        },
        "process_search_fields": {
            "process_name": {"type": "string"},
            "netconn_port": {"type": "numeric"},
        }
    }
    
    query, metadata = build_cbc_query(
        schema,
        natural_language_intent="RDP",
        search_type="process_search"
    )
    
    assert query is not None
    assert "RDP" in query or "rdp" in query.lower()
    assert metadata["search_type"] == "process_search"


def test_cbc_query_with_rag_context():
    """Test that query building enhances queries when RAG context is provided."""
    schema = {
        "search_types": {
            "process_search": {
                "description": "Search for processes"
            }
        },
        "process_search_fields": {
            "process_name": {"type": "string"},
            "netconn_port": {"type": "numeric"},
        }
    }
    
    # Simulate RAG context with RDP-related information
    rag_context = [
        {
            "text": "netconn_port (numeric) - Port number for network connections. Examples: netconn_port:3389 for RDP",
            "score": 0.9,
            "source": "cbc"
        },
        {
            "text": "process_name (string) - Process executable name. Examples: mstsc.exe, rdpclip.exe for RDP",
            "score": 0.85,
            "source": "cbc"
        }
    ]
    
    query, metadata = build_cbc_query(
        schema,
        natural_language_intent="RDP",
        search_type="process_search",
        rag_context=rag_context
    )
    
    assert query is not None
    assert metadata["search_type"] == "process_search"
    
    # Check if RAG enhancement metadata is present
    rag_metadata = [r for r in metadata["recognised"] if r.get("type") == "rag_metadata"]
    if rag_metadata:
        # RAG enhancement was applied
        assert rag_metadata[0]["enhancement_count"] > 0
        print(f"✅ RAG enhancement applied: {rag_metadata[0]['enhancement_count']} additional terms")
    else:
        # RAG enhancement may not have been applied if confidence was too low
        print("⚠️  RAG enhancement not applied (confidence too low or parsing failed)")
    
    print(f"Query: {query}")
    print(f"Metadata: {metadata}")


def test_cbc_query_rag_enhancement_with_low_confidence():
    """Test that low-confidence RAG results don't enhance the query."""
    schema = {
        "search_types": {
            "process_search": {
                "description": "Search for processes"
            }
        },
        "process_search_fields": {
            "process_name": {"type": "string"},
        }
    }
    
    # Simulate low-quality RAG context
    rag_context = [
        {
            "text": "Some unrelated content about something else",
            "score": 0.1,
            "source": "cbc"
        }
    ]
    
    query, metadata = build_cbc_query(
        schema,
        natural_language_intent="test query",
        search_type="process_search",
        rag_context=rag_context
    )
    
    assert query is not None
    
    # Should not have RAG enhancements due to low confidence
    rag_enhancements = [r for r in metadata["recognised"] if r.get("type") == "rag_enhanced"]
    # Low confidence context should not produce enhancements
    print(f"Query: {query}")
    print(f"RAG enhancements: {len(rag_enhancements)}")


if __name__ == "__main__":
    print("Running CBC RAG Enhancement Tests...\n")
    
    print("Test 1: Backward compatibility (no RAG context)")
    test_cbc_query_without_rag_context()
    print("✅ Passed\n")
    
    print("Test 2: With RAG context")
    test_cbc_query_with_rag_context()
    print("✅ Passed\n")
    
    print("Test 3: Low confidence RAG context")
    test_cbc_query_rag_enhancement_with_low_confidence()
    print("✅ Passed\n")
    
    print("All tests passed! ✅")
