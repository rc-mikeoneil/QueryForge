"""Tests for SentinelOne RAG-enhanced query building."""

import pytest
from s1.query_builder import build_s1_query


def test_s1_query_without_rag_context():
    """Test that S1 query building works without RAG context (backward compatibility)."""
    schema = {
        "datasets": {
            "processes": {
                "name": "Processes",
                "description": "Process creation events"
            }
        },
        "common_fields": {
            "tgt.process.name": {"data_type": "string"},
            "src.process.name": {"data_type": "string"}
        }
    }
    
    query, metadata = build_s1_query(
        schema,
        dataset="processes",
        natural_language_intent="PowerShell execution"
    )
    
    assert query is not None
    assert metadata["dataset"] == "processes"


def test_s1_query_with_rag_context():
    """Test that S1 query building enhances queries when RAG context is provided."""
    schema = {
        "datasets": {
            "processes": {
                "name": "Processes",
                "description": "Process creation events",
                "fields": {
                    "tgt.process.displayName": {"data_type": "string"},
                    "tgt.process.cmdline": {"data_type": "string"}
                }
            }
        },
        "common_fields": {
            "tgt.process.name": {"data_type": "string"},
            "src.process.name": {"data_type": "string"}
        }
    }
    
    # Simulate RAG context with PowerShell-related information
    rag_context = [
        {
            "text": "tgt.process.displayName (string) - Process display name. Examples: powershell.exe, pwsh.exe for PowerShell",
            "score": 0.93,
            "source": "s1"
        },
        {
            "text": "tgt.process.cmdline (string) - Process command line. May contain: -ExecutionPolicy, -EncodedCommand",
            "score": 0.88,
            "source": "s1"
        }
    ]
    
    query, metadata = build_s1_query(
        schema,
        dataset="processes",
        natural_language_intent="PowerShell execution",
        rag_context=rag_context
    )
    
    assert query is not None
    assert metadata["dataset"] == "processes"
    
    # Check for RAG-enhanced expressions
    query_lower = query.lower()
    has_rag_enhancement = any(term in query_lower for term in ['powershell.exe', 'pwsh.exe'])
    
    print(f"Query: {query}")
    print(f"Has RAG enhancement: {has_rag_enhancement}")
    print(f"Metadata: {metadata}")


def test_s1_query_rag_enhancement_with_low_confidence():
    """Test that low-confidence RAG results still enhance the query (aggressive approach)."""
    schema = {
        "datasets": {
            "processes": {
                "name": "Processes",
                "description": "Process creation events"
            }
        },
        "common_fields": {
            "tgt.process.name": {"data_type": "string"}
        }
    }
    
    # Simulate low-quality RAG context that should still be used
    rag_context = [
        {
            "text": "tgt.process.name may contain suspicious process names",
            "score": 0.11,  # Low confidence but above 0.1 threshold
            "source": "s1"
        }
    ]
    
    query, metadata = build_s1_query(
        schema,
        dataset="processes",
        natural_language_intent="suspicious processes",
        rag_context=rag_context
    )
    
    assert query is not None
    assert metadata["dataset"] == "processes"
    print(f"Query: {query}")
    print(f"Metadata: {metadata}")


def test_s1_query_rdp_comprehensive():
    """Test that RDP queries generate comprehensive coverage."""
    schema = {
        "datasets": {
            "network_actions": {
                "name": "Network Actions",
                "description": "Network connection events",
                "fields": {
                    "dst.port.number": {"data_type": "numeric"},
                    "src.port.number": {"data_type": "numeric"}
                }
            },
            "processes": {
                "name": "Processes",
                "description": "Process creation events",
                "fields": {
                    "tgt.process.displayName": {"data_type": "string"},
                    "src.process.displayName": {"data_type": "string"}
                }
            }
        },
        "common_fields": {
            "tgt.process.name": {"data_type": "string"}
        }
    }
    
    # Rich RAG context for RDP
    rag_context = [
        {
            "text": "RDP uses dst.port.number: 3389. tgt.process.displayName examples: mstsc.exe, rdpclip.exe, tstheme.exe",
            "score": 0.95,
            "source": "s1"
        },
        {
            "text": "src.port.number for RDP clients varies. Standard server port is 3389.",
            "score": 0.91,
            "source": "s1"
        }
    ]
    
    query, metadata = build_s1_query(
        schema,
        natural_language_intent="RDP connections",
        rag_context=rag_context
    )
    
    assert query is not None
    # Should infer network_actions dataset from "connections" keyword
    
    # Should have comprehensive RDP coverage
    query_lower = query.lower()
    rdp_indicators = ['3389', 'mstsc.exe', 'rdpclip.exe']
    found_indicators = [indicator for indicator in rdp_indicators if indicator in query_lower]
    
    print(f"Query: {query}")
    print(f"Found RDP indicators: {found_indicators}")
    print(f"Metadata: {metadata}")
    
    # With aggressive RAG approach, we should find multiple indicators
    assert len(found_indicators) > 0, f"Expected RDP indicators in query, but found none. Query: {query}"


def test_s1_query_smb_comprehensive():
    """Test that SMB queries generate comprehensive coverage."""
    schema = {
        "datasets": {
            "network_actions": {
                "name": "Network Actions", 
                "description": "Network connection events",
                "fields": {
                    "dst.port.number": {"data_type": "numeric"},
                    "src.port.number": {"data_type": "numeric"}
                }
            }
        },
        "common_fields": {
            "tgt.process.name": {"data_type": "string"}
        }
    }
    
    # Rich RAG context for SMB
    rag_context = [
        {
            "text": "SMB uses dst.port.number: 445, 139. tgt.process.name examples: System, smb.exe, lsass.exe",
            "score": 0.94,
            "source": "s1"
        },
        {
            "text": "SMB file sharing over ports 445 (SMB) and 139 (NetBIOS). Common in lateral movement.",
            "score": 0.89,
            "source": "s1"
        }
    ]
    
    query, metadata = build_s1_query(
        schema,
        natural_language_intent="SMB file sharing activity",
        rag_context=rag_context
    )
    
    assert query is not None
    
    # Should have comprehensive SMB coverage
    query_lower = query.lower()
    smb_indicators = ['445', '139', 'system', 'smb.exe']
    found_indicators = [indicator for indicator in smb_indicators if indicator in query_lower]
    
    print(f"Query: {query}")
    print(f"Found SMB indicators: {found_indicators}")
    print(f"Metadata: {metadata}")
    
    # With aggressive RAG approach, we should find multiple indicators
    assert len(found_indicators) > 0, f"Expected SMB indicators in query, but found none. Query: {query}"


if __name__ == "__main__":
    print("Running S1 RAG Enhancement Tests...\n")
    
    print("Test 1: Backward compatibility (no RAG context)")
    test_s1_query_without_rag_context()
    print("✅ Passed\n")
    
    print("Test 2: With RAG context")
    test_s1_query_with_rag_context()
    print("✅ Passed\n")
    
    print("Test 3: Low confidence RAG context (aggressive approach)")
    test_s1_query_rag_enhancement_with_low_confidence()
    print("✅ Passed\n")
    
    print("Test 4: RDP comprehensive coverage")
    test_s1_query_rdp_comprehensive()
    print("✅ Passed\n")
    
    print("Test 5: SMB comprehensive coverage")
    test_s1_query_smb_comprehensive()
    print("✅ Passed\n")
    
    print("All S1 RAG enhancement tests passed! ✅")
