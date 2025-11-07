#!/usr/bin/env python3
"""
Test script to verify Cortex query builder fix for default 7-day time filter
and has_time_filter metadata flag.
"""
import os
import sys
from pathlib import Path
sys.path.insert(0, 'queryforge')

from cortex.schema_loader import CortexSchemaCache
from cortex.query_builder import build_cortex_query
from cortex.validator import CortexValidator

# Helper to locate the schema path
def get_schema_path():
    """Get the path to the Cortex schema files."""
    # Try different possible locations
    possible_paths = [
        Path("queryforge/cortex/new_schema/cortex_core.json"),
        Path("cortex/new_schema/cortex_core.json"),
    ]
    
    for path in possible_paths:
        if path.exists():
            return path
    
    raise FileNotFoundError(f"Could not find Cortex schema files. Current directory: {os.getcwd()}")


def test_default_time_filter():
    """Test that queries without time filters get a default 7-day filter."""
    print("=" * 80)
    print("TEST 1: Default 7-day time filter")
    print("=" * 80)
    
    schema_path = get_schema_path()
    cache = CortexSchemaCache(schema_path)
    
    # Build a query without specifying a time filter
    query, metadata = build_cortex_query(
        cache,
        dataset="xdr_data",
        natural_language_intent="show powershell execution"
    )
    
    print("\nGenerated Query:")
    print("-" * 80)
    print(query)
    print("-" * 80)
    
    print("\nMetadata:")
    print(f"  has_time_filter: {metadata.get('has_time_filter')}")
    print(f"  dataset: {metadata.get('dataset')}")
    
    # Verify the default time filter was added
    assert "interval '7 days'" in query, "Default 7-day time filter should be in query"
    assert metadata.get('has_time_filter') == True, "has_time_filter should be True"
    
    # Check that the default filter is marked in metadata
    default_filter = None
    for item in metadata.get('recognised', []):
        if item.get('default') == True:
            default_filter = item
            break
    
    assert default_filter is not None, "Default time filter should be marked in metadata"
    print(f"  Default filter: {default_filter}")
    
    print("\n✅ TEST 1 PASSED: Default 7-day time filter added correctly\n")


def test_explicit_time_filter():
    """Test that explicit time filters override the default."""
    print("=" * 80)
    print("TEST 2: Explicit time filter (no default)")
    print("=" * 80)
    
    schema_path = get_schema_path()
    cache = CortexSchemaCache(schema_path)
    
    # Build a query with an explicit time filter
    query, metadata = build_cortex_query(
        cache,
        dataset="xdr_data",
        natural_language_intent="show powershell execution in the last 24 hours"
    )
    
    print("\nGenerated Query:")
    print("-" * 80)
    print(query)
    print("-" * 80)
    
    print("\nMetadata:")
    print(f"  has_time_filter: {metadata.get('has_time_filter')}")
    
    # Verify that we have a time filter but NOT the default 7-day one
    assert metadata.get('has_time_filter') == True, "has_time_filter should be True"
    assert "24 hour" in query.lower() or "1 day" in query.lower(), "Should use explicit time range"
    
    # Check that no default filter was added
    has_default = any(item.get('default') == True for item in metadata.get('recognised', []))
    assert not has_default, "Should not have default time filter when explicit one is provided"
    
    print("\n✅ TEST 2 PASSED: Explicit time filter used, no default added\n")


def test_validation_no_error():
    """Test that validation no longer throws 'has_time_filter' undefined error."""
    print("=" * 80)
    print("TEST 3: Validation with has_time_filter metadata")
    print("=" * 80)
    
    schema_path = get_schema_path()
    cache = CortexSchemaCache(schema_path)
    
    # Build a query
    query, metadata = build_cortex_query(
        cache,
        dataset="xdr_data",
        natural_language_intent="show cmd.exe processes"
    )
    
    print("\nGenerated Query:")
    print("-" * 80)
    print(query)
    print("-" * 80)
    
    # Now validate it - this should NOT throw NameError
    schema = cache.load()
    validator = CortexValidator(schema)
    
    try:
        result = validator.validate(query, metadata)
        print("\nValidation Result:")
        print(f"  valid: {result['valid']}")
        print(f"  complexity: {result.get('complexity', 'N/A')}")
        print(f"  estimated_result_size: {result.get('estimated_result_size', 'N/A')}")
        
        # Check for any errors
        validation_results = result.get('validation_results', {})
        total_errors = sum(len(cat.get('errors', [])) for cat in validation_results.values())
        print(f"  total_errors: {total_errors}")
        
        print("\n✅ TEST 3 PASSED: Validation completed without NameError\n")
        
    except NameError as e:
        print(f"\n❌ TEST 3 FAILED: NameError occurred: {e}\n")
        raise


def main():
    """Run all tests."""
    print("\n" + "=" * 80)
    print("CORTEX QUERY BUILDER FIX VERIFICATION")
    print("=" * 80 + "\n")
    
    try:
        test_default_time_filter()
        test_explicit_time_filter()
        test_validation_no_error()
        
        print("=" * 80)
        print("🎉 ALL TESTS PASSED!")
        print("=" * 80)
        return 0
        
    except Exception as e:
        print("\n" + "=" * 80)
        print(f"❌ TEST FAILED: {e}")
        print("=" * 80)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
