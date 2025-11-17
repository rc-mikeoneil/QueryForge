#!/usr/bin/env python3
"""
Find undocumented CQL fields by comparing example queries against schema definitions.
"""

import json
import os
from pathlib import Path
from collections import defaultdict
from typing import Dict, Set, List

def load_json_file(filepath: Path) -> dict:
    """Load a JSON file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return {}

def extract_fields_from_examples(examples_dir: Path) -> Dict[str, Set[str]]:
    """Extract all fields referenced in example queries."""
    fields_by_event = defaultdict(set)
    
    for example_file in examples_dir.rglob("*.json"):
        data = load_json_file(example_file)
        if not data:
            continue
            
        # Get event types and fields
        event_types = data.get("event_types", [])
        fields = data.get("fields_referenced", [])
        
        # Map fields to event types
        if event_types and fields:
            for event_type in event_types:
                for field in fields:
                    # Skip special keywords that aren't actual fields
                    if field.lower() in {"as", "function", "to", "from", "by", "field", "column", "data_source_name"}:
                        continue
                    fields_by_event[event_type].add(field)
        elif fields:
            # If no event type specified, add to "general"
            for field in fields:
                if field.lower() not in {"as", "function", "to", "from", "by", "field", "column", "data_source_name"}:
                    fields_by_event["general"].add(field)
    
    return fields_by_event

def load_schema_fields(tables_dir: Path) -> Dict[str, Set[str]]:
    """Load all fields from schema table definitions."""
    schema_fields = {}
    
    for schema_file in tables_dir.glob("*.json"):
        data = load_json_file(schema_file)
        if not data:
            continue
            
        table_name = data.get("table", schema_file.stem)
        columns = data.get("columns", [])
        
        field_names = {col["name"] for col in columns if "name" in col}
        schema_fields[table_name] = field_names
    
    return schema_fields

def find_missing_fields(
    fields_by_event: Dict[str, Set[str]], 
    schema_fields: Dict[str, Set[str]]
) -> Dict[str, List[str]]:
    """Find fields that are in examples but not in schemas."""
    missing = defaultdict(list)
    
    for event_type, example_fields in fields_by_event.items():
        # Try to find matching schema
        schema_key = event_type
        if schema_key not in schema_fields:
            # Try variations
            for key in schema_fields.keys():
                if key.lower() == event_type.lower():
                    schema_key = key
                    break
        
        if schema_key in schema_fields:
            schema_field_set = schema_fields[schema_key]
            for field in example_fields:
                if field not in schema_field_set:
                    missing[event_type].append(field)
        else:
            # No matching schema found
            missing[event_type] = list(example_fields)
    
    return missing

def generate_field_definitions(missing_fields: Dict[str, List[str]]) -> Dict[str, List[Dict]]:
    """Generate field definition JSON for missing fields."""
    definitions = {}
    
    for event_type, fields in missing_fields.items():
        field_defs = []
        for field in sorted(fields):
            # Infer field type from name
            field_type = "string"
            if any(x in field.lower() for x in ["count", "total", "number", "size", "id"]):
                if "id" in field.lower() or "hash" in field.lower():
                    field_type = "string"
                else:
                    field_type = "long"
            elif any(x in field.lower() for x in ["time", "timestamp", "date"]):
                field_type = "long"  # Usually epoch time
            elif any(x in field.lower() for x in ["is", "has", "enabled", "disabled"]):
                field_type = "boolean"
            elif any(x in field.lower() for x in ["percent", "ratio", "rate"]):
                field_type = "float"
            
            field_def = {
                "name": field,
                "type": field_type,
                "description": f"Field found in example queries (undocumented)",
                "searchable": True,
                "undocumented": True
            }
            field_defs.append(field_def)
        
        definitions[event_type] = field_defs
    
    return definitions

def main():
    """Main execution."""
    # Paths
    base_dir = Path(__file__).parent.parent
    examples_dir = base_dir / "src/queryforge/platforms/cql/cql_schemas/examples"
    tables_dir = base_dir / "src/queryforge/platforms/cql/cql_schemas/tables"
    output_file = base_dir / "src/queryforge/platforms/cql/cql_schemas/undocumented_fields.json"
    
    print("=" * 80)
    print("CQL Undocumented Field Finder")
    print("=" * 80)
    print()
    
    # Extract fields from examples
    print("Extracting fields from example queries...")
    fields_by_event = extract_fields_from_examples(examples_dir)
    print(f"Found {len(fields_by_event)} event types with {sum(len(f) for f in fields_by_event.values())} total field references")
    print()
    
    # Load schema fields
    print("Loading schema definitions...")
    schema_fields = load_schema_fields(tables_dir)
    print(f"Loaded {len(schema_fields)} schema tables")
    print()
    
    # Find missing fields
    print("Finding undocumented fields...")
    missing_fields = find_missing_fields(fields_by_event, schema_fields)
    
    # Generate report
    print()
    print("=" * 80)
    print("UNDOCUMENTED FIELDS REPORT")
    print("=" * 80)
    print()
    
    total_missing = sum(len(fields) for fields in missing_fields.values())
    print(f"Found {total_missing} undocumented fields across {len(missing_fields)} event types")
    print()
    
    for event_type in sorted(missing_fields.keys()):
        fields = sorted(missing_fields[event_type])
        if fields:
            print(f"\n{event_type} ({len(fields)} fields):")
            for field in fields:
                print(f"  - {field}")
    
    # Generate field definitions
    print()
    print("=" * 80)
    print("Generating field definitions...")
    field_definitions = generate_field_definitions(missing_fields)
    
    # Save to file
    output_data = {
        "generated_at": "2025-11-17T18:47:00Z",
        "description": "Undocumented CQL fields found in example queries",
        "total_fields": total_missing,
        "fields_by_event_type": field_definitions
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    print(f"Saved field definitions to: {output_file}")
    print()
    print("=" * 80)
    print("DONE")
    print("=" * 80)

if __name__ == "__main__":
    main()
