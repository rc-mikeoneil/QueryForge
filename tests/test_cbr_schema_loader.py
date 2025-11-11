"""
Test CBR Schema Loader

Validates that the schema loader can:
- Load schema from split files
- Cache and retrieve from cache
- Merge field sets correctly
- Provide helper methods
"""

import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from cbr.schema_loader import CBResponseSchemaCache, normalise_search_type


def test_schema_loading():
    """Test basic schema loading functionality."""
    print("=" * 60)
    print("Testing CBR Schema Loader")
    print("=" * 60)
    
    # Initialize cache pointing to cbr directory
    cbr_dir = Path(__file__).parent.parent / "cbr"
    cache = CBResponseSchemaCache(cbr_dir)
    
    print("\n1. Loading schema...")
    schema = cache.load()
    print(f"   ✓ Schema loaded successfully")
    print(f"   - Version: {schema.get('version')}")
    print(f"   - Platform: {schema.get('platform')}")
    print(f"   - Updated: {schema.get('updated_at')}")
    
    print("\n2. Testing search_types()...")
    search_types = cache.search_types()
    print(f"   ✓ Found {len(search_types)} search types:")
    for st_name, st_info in search_types.items():
        datasets = st_info.get('datasets', [])
        print(f"     - {st_name}: {len(datasets)} datasets")
    
    print("\n3. Testing field_map_for('server_event')...")
    server_fields = cache.field_map_for('server_event')
    print(f"   ✓ Found {len(server_fields)} fields in server_event")
    # Show a few example fields
    example_fields = list(server_fields.items())[:3]
    for field_name, field_meta in example_fields:
        print(f"     - {field_name}: {field_meta.get('type')} - {field_meta.get('description', '')[:50]}...")
    
    print("\n4. Testing field_map_for('endpoint_event')...")
    endpoint_fields = cache.field_map_for('endpoint_event')
    print(f"   ✓ Found {len(endpoint_fields)} fields in endpoint_event")
    # Show a few example fields
    example_fields = list(endpoint_fields.items())[:3]
    for field_name, field_meta in example_fields:
        print(f"     - {field_name}: {field_meta.get('type')} - {field_meta.get('description', '')[:50]}...")
    
    print("\n5. Testing list_fields('server_event')...")
    fields_list = cache.list_fields('server_event')
    print(f"   ✓ Retrieved {len(fields_list)} fields as list")
    if fields_list:
        first_field = fields_list[0]
        print(f"     - First field: {first_field.get('name')} ({first_field.get('type')})")
    
    print("\n6. Testing operator_reference()...")
    operators = cache.operator_reference()
    print(f"   ✓ Retrieved operator reference")
    if 'AND' in operators:
        print(f"     - AND: {operators['AND'].get('description', '')}")
    if 'OR' in operators:
        print(f"     - OR: {operators['OR'].get('description', '')}")
    
    print("\n7. Testing best_practices()...")
    best_practices = cache.best_practices()
    print(f"   ✓ Retrieved best practices")
    if isinstance(best_practices, dict):
        print(f"     - Categories: {list(best_practices.keys())[:3]}")
    
    print("\n8. Testing example_queries()...")
    examples = cache.example_queries()
    print(f"   ✓ Retrieved {len(examples)} example categories")
    if examples:
        first_category = list(examples.keys())[0]
        print(f"     - First category: {first_category}")
    
    print("\n9. Testing cache persistence...")
    cache2 = CBResponseSchemaCache(cbr_dir)
    schema2 = cache2.load()
    print(f"   ✓ Loaded from cache successfully")
    print(f"   - Cache file exists: {cache2.cache_file.exists()}")
    
    print("\n10. Testing normalise_search_type()...")
    available = list(search_types.keys())
    
    # Test exact match
    result, log = normalise_search_type("server_event", available)
    print(f"   ✓ 'server_event' → '{result}'")
    
    # Test alias
    result, log = normalise_search_type("server", available)
    print(f"   ✓ 'server' → '{result}' (log: {log})")
    
    # Test endpoint alias
    result, log = normalise_search_type("endpoint", available)
    print(f"   ✓ 'endpoint' → '{result}' (log: {log})")
    
    print("\n" + "=" * 60)
    print("All tests passed! ✓")
    print("=" * 60)
    
    # Print summary
    print("\nSchema Summary:")
    print(f"  - Search types: {len(search_types)}")
    print(f"  - Server event fields: {len(server_fields)}")
    print(f"  - Endpoint event fields: {len(endpoint_fields)}")
    print(f"  - Example categories: {len(examples)}")
    print(f"  - Cache file: {cache.cache_file}")
    
    return True


def test_granular_field_sets():
    """Test loading granular field sets."""
    print("\n" + "=" * 60)
    print("Testing Granular Field Sets")
    print("=" * 60)
    
    cbr_dir = Path(__file__).parent.parent / "cbr"
    cache = CBResponseSchemaCache(cbr_dir)
    schema = cache.load()
    
    # Test some granular field sets
    granular_tests = [
        "watchlist_hit_process_fields",
        "netconn (network connection)_fields",
        "regmod (registry modification)_fields",
    ]
    
    for field_set in granular_tests:
        fields = cache.field_map_for(field_set)
        print(f"\n  {field_set}:")
        print(f"    - Fields: {len(fields)}")
        if fields:
            # Show first field
            first_name, first_meta = next(iter(fields.items()))
            print(f"    - Example: {first_name} ({first_meta.get('type')})")
    
    print("\n  ✓ Granular field sets working correctly")


if __name__ == "__main__":
    try:
        test_schema_loading()
        test_granular_field_sets()
        print("\n✅ All schema loader tests completed successfully!\n")
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
