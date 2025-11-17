#!/usr/bin/env python3
"""
CQL Schema Validation Script
Validates all JSON schema files for proper structure, required fields, and cross-references.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Set, Any
from collections import defaultdict


class SchemaValidator:
    def __init__(self, base_path: str = "cql_schemas"):
        self.base_path = Path(base_path)
        self.errors = []
        self.warnings = []
        self.info = []

        # Track all entities for cross-reference validation
        self.functions = set()
        self.tables = set()
        self.operators = set()
        self.examples = set()

    def validate_json_file(self, file_path: Path) -> bool:
        """Validate that file contains valid JSON"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                json.load(f)
            return True
        except json.JSONDecodeError as e:
            self.errors.append(f"{file_path}: Invalid JSON - {e}")
            return False
        except Exception as e:
            self.errors.append(f"{file_path}: Error reading file - {e}")
            return False

    def load_json(self, file_path: Path) -> Dict:
        """Load JSON file and return data"""
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def validate_function_schema(self, file_path: Path, data: Dict):
        """Validate function schema structure"""
        required_fields = ['name', 'category', 'description', 'syntax']

        for field in required_fields:
            if field not in data:
                self.errors.append(f"{file_path}: Missing required field '{field}'")

        # Track function name
        if 'name' in data:
            self.functions.add(data['name'])

        # Validate parameters structure if present
        if 'parameters' in data:
            if not isinstance(data['parameters'], list):
                self.errors.append(f"{file_path}: 'parameters' must be an array")
            else:
                for i, param in enumerate(data['parameters']):
                    if not isinstance(param, dict):
                        self.errors.append(f"{file_path}: Parameter {i} must be an object")
                        continue

                    param_required = ['name', 'type', 'required', 'description']
                    for field in param_required:
                        if field not in param:
                            self.errors.append(
                                f"{file_path}: Parameter '{param.get('name', i)}' missing field '{field}'"
                            )

        # Validate examples if present
        if 'examples' in data:
            if not isinstance(data['examples'], list):
                self.errors.append(f"{file_path}: 'examples' must be an array")
            elif len(data['examples']) == 0:
                self.warnings.append(f"{file_path}: No examples provided")
        else:
            self.warnings.append(f"{file_path}: No examples field")

        # Check for documentation URL
        if 'documentation_url' not in data:
            self.warnings.append(f"{file_path}: Missing 'documentation_url'")

    def validate_table_schema(self, file_path: Path, data: Dict):
        """Validate table (event type) schema structure"""
        required_fields = ['table', 'category', 'description', 'columns']

        for field in required_fields:
            if field not in data:
                self.errors.append(f"{file_path}: Missing required field '{field}'")

        # Track table name
        if 'table' in data:
            self.tables.add(data['table'])

        # Validate columns structure
        if 'columns' in data:
            if not isinstance(data['columns'], list):
                self.errors.append(f"{file_path}: 'columns' must be an array")
            else:
                if len(data['columns']) == 0:
                    self.errors.append(f"{file_path}: No columns defined")

                # Validate col_count matches
                if 'col_count' in data:
                    if data['col_count'] != len(data['columns']):
                        self.errors.append(
                            f"{file_path}: col_count ({data['col_count']}) doesn't match "
                            f"actual column count ({len(data['columns'])})"
                        )

                for i, col in enumerate(data['columns']):
                    if not isinstance(col, dict):
                        self.errors.append(f"{file_path}: Column {i} must be an object")
                        continue

                    col_required = ['name', 'type', 'description']
                    for field in col_required:
                        if field not in col:
                            self.errors.append(
                                f"{file_path}: Column '{col.get('name', i)}' missing field '{field}'"
                            )

        # Check for generated_at timestamp
        if 'generated_at' not in data:
            self.warnings.append(f"{file_path}: Missing 'generated_at' timestamp")

        # Check for source_url
        if 'source_url' not in data:
            self.warnings.append(f"{file_path}: Missing 'source_url'")

    def validate_operators_schema(self, file_path: Path, data: Dict):
        """Validate operators schema structure"""
        required_fields = ['schema_version', 'operators']

        for field in required_fields:
            if field not in data:
                self.errors.append(f"{file_path}: Missing required field '{field}'")

        # Validate operators array
        if 'operators' in data:
            if not isinstance(data['operators'], list):
                self.errors.append(f"{file_path}: 'operators' must be an array")
            else:
                for i, op in enumerate(data['operators']):
                    if not isinstance(op, dict):
                        self.errors.append(f"{file_path}: Operator {i} must be an object")
                        continue

                    op_required = ['operator', 'name', 'category', 'description', 'syntax']
                    for field in op_required:
                        if field not in op:
                            self.errors.append(
                                f"{file_path}: Operator '{op.get('operator', i)}' missing field '{field}'"
                            )

                    # Track operator
                    if 'operator' in op:
                        self.operators.add(op['operator'])

    def validate_example_schema(self, file_path: Path, data: Dict):
        """Validate example query schema structure"""
        required_fields = ['id', 'title', 'source_file', 'category', 'query']

        for field in required_fields:
            if field not in data:
                self.errors.append(f"{file_path}: Missing required field '{field}'")

        # Track example ID
        if 'id' in data:
            if data['id'] in self.examples:
                self.errors.append(f"{file_path}: Duplicate example ID '{data['id']}'")
            self.examples.add(data['id'])

        # Validate arrays
        for array_field in ['event_types', 'functions_used', 'operators_used', 'fields_referenced']:
            if array_field in data and not isinstance(data[array_field], list):
                self.errors.append(f"{file_path}: '{array_field}' must be an array")

        # Check for empty query
        if 'query' in data and not data['query'].strip():
            self.errors.append(f"{file_path}: Query is empty")

    def validate_metadata_schema(self, file_path: Path, data: Dict):
        """Validate metadata files"""
        filename = file_path.name

        # Different validation based on metadata file type
        if filename == 'master_schema_index.json':
            required = ['schema_version', 'generated_at']
            for field in required:
                if field not in data:
                    self.errors.append(f"{file_path}: Missing required field '{field}'")

        elif filename == 'functions_index.json':
            if 'functions' not in data:
                self.errors.append(f"{file_path}: Missing 'functions' field")

        elif filename == 'event_types_catalog.json':
            if 'event_types' not in data:
                self.errors.append(f"{file_path}: Missing 'event_types' field")

        elif filename == 'examples_index.json':
            # This file has metadata and summary structure instead of examples list
            if 'metadata' not in data:
                self.warnings.append(f"{file_path}: Missing 'metadata' field")
            if 'summary' not in data:
                self.warnings.append(f"{file_path}: Missing 'summary' field")

    def validate_cross_references(self):
        """Validate that cross-references between files are valid"""
        # Load all examples and check if referenced functions/tables exist
        example_files = list(self.base_path.glob('examples/**/*.json'))

        for ex_file in example_files:
            if not self.validate_json_file(ex_file):
                continue

            data = self.load_json(ex_file)

            # Check functions_used references
            if 'functions_used' in data:
                for func in data['functions_used']:
                    if func not in self.functions:
                        self.warnings.append(
                            f"{ex_file}: References unknown function '{func}'"
                        )

            # Check event_types references
            if 'event_types' in data:
                for table in data['event_types']:
                    if table not in self.tables:
                        self.warnings.append(
                            f"{ex_file}: References unknown event type '{table}'"
                        )

    def validate_all(self):
        """Run all validations"""
        print("=" * 80)
        print("CQL SCHEMA VALIDATION")
        print("=" * 80)
        print()

        # Validate functions
        print("Validating function schemas...")
        func_files = list(self.base_path.glob('functions/*.json'))
        for file_path in func_files:
            if self.validate_json_file(file_path):
                data = self.load_json(file_path)
                self.validate_function_schema(file_path, data)
        print(f"  ✓ Validated {len(func_files)} function files")

        # Validate tables
        print("Validating table schemas...")
        table_files = list(self.base_path.glob('tables/*.json'))
        for file_path in table_files:
            if self.validate_json_file(file_path):
                data = self.load_json(file_path)
                self.validate_table_schema(file_path, data)
        print(f"  ✓ Validated {len(table_files)} table files")

        # Validate operators
        print("Validating operator schemas...")
        op_files = list(self.base_path.glob('operators/*.json'))
        for file_path in op_files:
            if self.validate_json_file(file_path):
                data = self.load_json(file_path)
                self.validate_operators_schema(file_path, data)
        print(f"  ✓ Validated {len(op_files)} operator files")

        # Validate examples
        print("Validating example schemas...")
        example_files = list(self.base_path.glob('examples/**/*.json'))
        for file_path in example_files:
            if self.validate_json_file(file_path):
                data = self.load_json(file_path)
                self.validate_example_schema(file_path, data)
        print(f"  ✓ Validated {len(example_files)} example files")

        # Validate metadata
        print("Validating metadata files...")
        meta_files = list(self.base_path.glob('metadata/*.json'))
        for file_path in meta_files:
            if self.validate_json_file(file_path):
                data = self.load_json(file_path)
                self.validate_metadata_schema(file_path, data)
        print(f"  ✓ Validated {len(meta_files)} metadata files")

        # Cross-reference validation
        print("\nValidating cross-references...")
        self.validate_cross_references()
        print(f"  ✓ Cross-reference validation complete")

        # Print summary
        print("\n" + "=" * 80)
        print("VALIDATION SUMMARY")
        print("=" * 80)

        total_files = len(func_files) + len(table_files) + len(op_files) + len(example_files) + len(meta_files)

        print(f"\nTotal files validated: {total_files}")
        print(f"  - Functions: {len(self.functions)}")
        print(f"  - Tables: {len(self.tables)}")
        print(f"  - Operators: {len(self.operators)}")
        print(f"  - Examples: {len(self.examples)}")

        print(f"\n{'✗' if self.errors else '✓'} Errors: {len(self.errors)}")
        print(f"⚠ Warnings: {len(self.warnings)}")
        print(f"ℹ Info: {len(self.info)}")

        # Print errors
        if self.errors:
            print("\n" + "=" * 80)
            print("ERRORS")
            print("=" * 80)
            for error in self.errors:
                print(f"✗ {error}")

        # Print warnings
        if self.warnings:
            print("\n" + "=" * 80)
            print("WARNINGS")
            print("=" * 80)
            for warning in self.warnings[:20]:  # Limit to first 20
                print(f"⚠ {warning}")
            if len(self.warnings) > 20:
                print(f"... and {len(self.warnings) - 20} more warnings")

        # Print info
        if self.info:
            print("\n" + "=" * 80)
            print("INFO")
            print("=" * 80)
            for info in self.info[:10]:
                print(f"ℹ {info}")

        print("\n" + "=" * 80)

        # Return exit code
        return 0 if len(self.errors) == 0 else 1


def main():
    validator = SchemaValidator()
    exit_code = validator.validate_all()

    # Generate validation report
    report_path = Path("VALIDATION_REPORT.md")
    with open(report_path, 'w') as f:
        f.write("# CQL Schema Validation Report\n\n")
        f.write(f"**Generated:** {Path('cql_schemas/metadata/master_schema_index.json').stat().st_mtime}\n\n")

        f.write("## Summary\n\n")
        f.write(f"- **Total Errors:** {len(validator.errors)}\n")
        f.write(f"- **Total Warnings:** {len(validator.warnings)}\n")
        f.write(f"- **Functions:** {len(validator.functions)}\n")
        f.write(f"- **Tables:** {len(validator.tables)}\n")
        f.write(f"- **Operators:** {len(validator.operators)}\n")
        f.write(f"- **Examples:** {len(validator.examples)}\n\n")

        if validator.errors:
            f.write("## Errors\n\n")
            for error in validator.errors:
                f.write(f"- ❌ {error}\n")
            f.write("\n")

        if validator.warnings:
            f.write("## Warnings\n\n")
            for warning in validator.warnings:
                f.write(f"- ⚠️ {warning}\n")
            f.write("\n")

        if len(validator.errors) == 0:
            f.write("## ✅ Validation Passed\n\n")
            f.write("All schemas are valid and conform to the expected structure.\n")

    print(f"\n✓ Validation report written to {report_path}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
