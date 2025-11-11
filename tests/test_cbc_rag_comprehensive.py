"""Comprehensive test for CBC RAG-enhanced query building."""

import logging
import sys
import os

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Add parent directory to module search path
current_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from queryforge.platforms.cbc.query_builder import build_cbc_query


def test_rdp_query_enhancement():
    """Test RDP query enhancement with realistic RAG context."""
    schema = {
        "search_types": {
            "process_search": {
                "description": "Search for processes"
            }
        },
        "process_search_fields": {
            "process_name": {
                "type": "string",
                "description": "Process executable name"
            },
            "netconn_port": {
                "type": "numeric", 
                "description": "Network connection port"
            },
            "parent_name": {
                "type": "string",
                "description": "Parent process name"
            }
        }
    }
    
    # Realistic RAG context that should provide good field/value extraction
    rag_context = [
        {
            "text": """Search Type: process_search - Network Fields
Fields:
netconn_port (numeric) - Port number for network connections
Examples: netconn_port:3389 for RDP connections, netconn_port:22 for SSH
Values: 3389, 22, 80, 443, 21""",
            "score": 0.95,
            "source": "cbc",
            "id": "cbc:process_netconn_fields"
        },
        {
            "text": """Search Type: process_search - Process Fields  
Fields:
process_name (string) - Process executable filename
Examples: process_name:mstsc.exe for RDP client, process_name:rdpclip.exe
Values: mstsc.exe, rdpclip.exe, termsrv.dll, rdpdd.dll""",
            "score": 0.92,
            "source": "cbc", 
            "id": "cbc:process_general_fields"
        },
        {
            "text": """Example Queries: Remote Access
Category: network_connections
- RDP Connections
  Description: Find Remote Desktop Protocol activity
  Query: (netconn_port:3389 OR process_name:mstsc.exe OR process_name:rdpclip.exe)""",
            "score": 0.88,
            "source": "cbc",
            "id": "cbc:examples"
        }
    ]
    
    # Test basic query without RAG
    query_basic, metadata_basic = build_cbc_query(
        schema,
        natural_language_intent="RDP",
        search_type="process_search"
    )
    
    print("=== Basic Query (no RAG) ===")
    print(f"Query: {query_basic}")
    print(f"Terms: {len(metadata_basic['recognised'])}")
    
    # Test enhanced query with RAG
    query_enhanced, metadata_enhanced = build_cbc_query(
        schema,
        natural_language_intent="RDP",
        search_type="process_search", 
        rag_context=rag_context
    )
    
    print("\n=== Enhanced Query (with RAG) ===")
    print(f"Query: {query_enhanced}")
    print(f"Terms: {len(metadata_enhanced['recognised'])}")
    
    # Check for RAG enhancements
    rag_enhanced_terms = [r for r in metadata_enhanced["recognised"] if r.get("type") == "rag_enhanced"]
    rag_metadata = [r for r in metadata_enhanced["recognised"] if r.get("type") == "rag_metadata"]
    
    if rag_enhanced_terms:
        print(f"\n✅ RAG Enhancement Success!")
        print(f"   Enhanced terms: {len(rag_enhanced_terms)}")
        for term in rag_enhanced_terms:
            print(f"   - {term['field']}:{term['value']} (confidence: {term['confidence']:.2f})")
    else:
        print(f"\n⚠️  RAG Enhancement not applied")
        if rag_metadata:
            print(f"   Confidence too low: {rag_metadata[0].get('confidence', 0):.2f}")
    
    # Verify the query is more comprehensive
    if len(metadata_enhanced['recognised']) > len(metadata_basic['recognised']):
        print(f"✅ Query enhanced: {len(metadata_basic['recognised'])} → {len(metadata_enhanced['recognised'])} terms")
    else:
        print(f"⚠️  Query not enhanced (same term count)")
    
    return query_enhanced, metadata_enhanced


def test_smb_query_enhancement():
    """Test SMB query enhancement.""" 
    schema = {
        "search_types": {
            "process_search": {"description": "Search for processes"}
        },
        "process_search_fields": {
            "process_name": {"type": "string"},
            "netconn_port": {"type": "numeric"},
        }
    }
    
    rag_context = [
        {
            "text": """netconn_port (numeric) - Network port numbers
Examples: netconn_port:445 for SMB, netconn_port:139 for NetBIOS
Values: 445, 139, 135""",
            "score": 0.9,
            "source": "cbc"
        }
    ]
    
    query, metadata = build_cbc_query(
        schema,
        natural_language_intent="SMB file sharing",
        search_type="process_search",
        rag_context=rag_context
    )
    
    print(f"\n=== SMB Query ===")
    print(f"Query: {query}")
    print(f"Terms: {len(metadata['recognised'])}")
    
    return query, metadata


if __name__ == "__main__":
    print("🚀 Comprehensive CBC RAG Enhancement Test\n")
    
    print("Test 1: RDP Query Enhancement")
    print("=" * 50)
    test_rdp_query_enhancement()
    
    print("\n" + "=" * 50)
    test_smb_query_enhancement()
    
    print(f"\n✅ All tests completed!")
