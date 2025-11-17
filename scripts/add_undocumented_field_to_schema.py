#!/usr/bin/env python3
"""
Add IsOnRemovableDisk field to FileWritten schema.
"""

import json
from pathlib import Path

def main():
    base_dir = Path(__file__).parent.parent
    schema_file = base_dir / "src/queryforge/platforms/cql/cql_schemas/tables/FileWritten.json"
    
    print("Adding IsOnRemovableDisk field to FileWritten schema...")
    
    # Load the schema
    with open(schema_file, 'r', encoding='utf-8') as f:
        schema = json.load(f)
    
    # Check if field already exists
    existing_fields = {col["name"] for col in schema.get("columns", [])}
    
    if "IsOnRemovableDisk" in existing_fields:
        print("  Field already exists!")
        return
    
    # Add the new field
    new_field = {
        "name": "IsOnRemovableDisk",
        "type": "boolean",
        "description": "Indicates if the file was written to removable media (USB drive, external HDD, etc.)",
        "searchable": True,
        "common_usage": ["filtering", "removable media detection", "data exfiltration monitoring"],
        "undocumented": True,
        "note": "Found in production queries but not in official CrowdStrike documentation"
    }
    
    schema["columns"].append(new_field)
    schema["col_count"] = len(schema["columns"])
    
    # Update common operations
    if "common_operations" in schema:
        schema["common_operations"].append("Monitor writes to removable media for data exfiltration")
    
    # Save the updated schema
    with open(schema_file, 'w', encoding='utf-8') as f:
        json.dump(schema, f, indent=2, ensure_ascii=False)
        f.write('\n')  # Add trailing newline
    
    print(f"  ✓ Added IsOnRemovableDisk field to FileWritten schema")
    print(f"  ✓ Updated col_count to {schema['col_count']}")
    print(f"  ✓ Saved to {schema_file}")

if __name__ == "__main__":
    main()
