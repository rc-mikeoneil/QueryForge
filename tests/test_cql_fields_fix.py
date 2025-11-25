#!/usr/bin/env python3
"""Test script to verify CQL fields are properly loaded including InstalledBrowserExtension."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from queryforge.platforms.cql.schema_loader import CQLSchemaLoader

def test_fields_loading():
    """Test that all fields from all event types are loaded."""
    loader = CQLSchemaLoader()
    
    # Get fields for events dataset
    fields_data = loader.get_fields("events")
    
    field_names = [f["name"] for f in fields_data.get("fields", [])]
    
    print(f"Total fields loaded: {len(field_names)}")
    print(f"\nChecking for browser extension fields...")
    
    # Check for InstalledBrowserExtension-specific fields
    extension_fields = [
        "BrowserExtensionId",
        "BrowserExtensionName",
        "BrowserName",
        "BrowserProfileId"
    ]
    
    found = []
    missing = []
    
    for field in extension_fields:
        if field in field_names:
            found.append(field)
            print(f"✓ Found: {field}")
        else:
            missing.append(field)
            print(f"✗ Missing: {field}")
    
    print(f"\n{'SUCCESS' if not missing else 'FAILURE'}: {len(found)}/{len(extension_fields)} browser extension fields found")
    
    if missing:
        print(f"Missing fields: {', '.join(missing)}")
        return False
    
    return True

if __name__ == "__main__":
    success = test_fields_loading()
    sys.exit(0 if success else 1)
