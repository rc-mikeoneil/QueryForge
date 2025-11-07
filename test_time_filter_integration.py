#!/usr/bin/env python3
"""
Test script to verify time filter integration with cortex_time_filters.json
"""

from pathlib import Path
from cortex.query_builder import build_cortex_query
from cortex.schema_loader import CortexSchemaCache

def test_time_filter_integration():
    """Test that time filters from schema are properly used"""
    
    # Initialize schema cache
    schema_dir = Path(__file__).parent / "cortex" / "new_schema"
    schema_path = schema_dir / "cortex_core.json"
    
    cache = CortexSchemaCache(schema_path)
    
    # Test 1: String time range "7 days" should map to schema preset
    print("Test 1: String time range '7 days'")
    query, metadata = build_cortex_query(
        schema=cache,
        dataset="xdr_data",
        filters=[{"field": "actor_process_image_name", "operator": "contains", "value": "test"}],
        time_range="7 days"
    )
    print(f"Query:\n{query}\n")
    print(f"Metadata: {metadata}\n")
    
    # Test 2: String time range "last_7_days" should map to schema preset
    print("Test 2: String time range 'last_7_days'")
    query, metadata = build_cortex_query(
        schema=cache,
        dataset="xdr_data",
        filters=[{"field": "actor_process_image_name", "operator": "contains", "value": "test"}],
        time_range="last_7_days"
    )
    print(f"Query:\n{query}\n")
    print(f"Metadata: {metadata}\n")
    
    # Test 3: Natural language with time range
    print("Test 3: Natural language with 'last 24 hours'")
    query, metadata = build_cortex_query(
        schema=cache,
        dataset="xdr_data",
        natural_language_intent="find metasploit activity in the last 24 hours"
    )
    print(f"Query:\n{query}\n")
    print(f"Metadata: {metadata}\n")
    
    # Test 4: Dict-based time range
    print("Test 4: Dict-based time range")
    query, metadata = build_cortex_query(
        schema=cache,
        dataset="xdr_data",
        filters=[{"field": "actor_process_image_name", "operator": "contains", "value": "test"}],
        time_range={"field": "_time", "operator": ">", "value": "current_time() - interval '30 days'"}
    )
    print(f"Query:\n{query}\n")
    print(f"Metadata: {metadata}\n")
    
    # Test 5: Check that time filter schema was loaded
    print("Test 5: Verify time filter schema is loaded")
    time_filters = cache.time_filters()
    print(f"Time filter schema loaded: {bool(time_filters)}")
    if time_filters:
        presets = time_filters.get("presets", {})
        print(f"Available presets: {list(presets.keys())}")
    print()
    
    print("✅ All tests completed!")

if __name__ == "__main__":
    test_time_filter_integration()
