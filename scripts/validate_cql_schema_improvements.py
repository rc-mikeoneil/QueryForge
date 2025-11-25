#!/usr/bin/env python3
"""
Script to validate CQL schema improvements and report coverage statistics.
"""

import json
from pathlib import Path

# Base directories
FUNCTIONS_DIR = Path("src/queryforge/platforms/cql/cql_schemas/functions")
OPERATORS_FILE = Path("src/queryforge/platforms/cql/cql_schemas/operators/operators.json")
VALIDATION_DATA = Path("src/queryforge/platforms/cql/CQL_VALIDATION_DATA.json")

def count_existing_functions():
    """Count existing function definitions."""
    if not FUNCTIONS_DIR.exists():
        return 0, []
    
    function_files = list(FUNCTIONS_DIR.glob("*.json"))
    function_names = [f.stem for f in function_files]
    return len(function_files), function_names

def count_existing_operators():
    """Count existing operator definitions."""
    if not OPERATORS_FILE.exists():
        return 0, []
    
    with open(OPERATORS_FILE, 'r') as f:
        operators_data = json.load(f)
    
    operators = [op["operator"] for op in operators_data.get("operators", [])]
    return len(operators), operators

def analyze_coverage():
    """Analyze current coverage against validation data."""
    print("🔍 Analyzing CQL Schema Coverage...")
    print("=" * 50)
    
    # Load validation data
    with open(VALIDATION_DATA, 'r') as f:
        validation = json.load(f)
    
    # Function analysis
    func_count, existing_functions = count_existing_functions()
    missing_functions = list(validation.get("missing_functions", {}).keys())
    all_functions_used = validation.get("all_functions_used", [])
    
    covered_functions = set(existing_functions) & set(all_functions_used)
    still_missing = set(missing_functions) - set(existing_functions)
    
    print(f"📊 FUNCTION COVERAGE:")
    print(f"   Total functions in schemas: {func_count}")
    print(f"   Functions used in examples: {len(all_functions_used)}")
    print(f"   Functions covered: {len(covered_functions)}")
    print(f"   Coverage rate: {len(covered_functions)/len(all_functions_used)*100:.1f}%")
    print(f"   Originally missing: {len(missing_functions)}")
    print(f"   Still missing: {len(still_missing)}")
    if still_missing:
        print(f"   Remaining gaps: {', '.join(sorted(still_missing)[:10])}")
        if len(still_missing) > 10:
            print(f"                   ... and {len(still_missing)-10} more")
    print()
    
    # Operator analysis
    op_count, existing_operators = count_existing_operators()
    missing_operators = list(validation.get("missing_operators", {}).keys())
    all_operators_used = validation.get("all_operators_used", [])
    
    covered_operators = set(existing_operators) & set(all_operators_used)
    still_missing_ops = set(missing_operators) - set(existing_operators)
    
    print(f"📊 OPERATOR COVERAGE:")
    print(f"   Total operators in schema: {op_count}")
    print(f"   Operators used in examples: {len(all_operators_used)}")
    print(f"   Operators covered: {len(covered_operators)}")
    print(f"   Coverage rate: {len(covered_operators)/len(all_operators_used)*100:.1f}%")
    print(f"   Originally missing: {len(missing_operators)}")
    print(f"   Still missing: {len(still_missing_ops)}")
    if still_missing_ops:
        print(f"   Remaining gaps: {', '.join(sorted(still_missing_ops))}")
    print()
    
    # Summary
    print(f"📈 IMPROVEMENT SUMMARY:")
    original_func_coverage = 48/99*100  # From validation report
    current_func_coverage = len(covered_functions)/len(all_functions_used)*100
    func_improvement = current_func_coverage - original_func_coverage
    
    original_op_coverage = 13/20*100  # From validation report
    current_op_coverage = len(covered_operators)/len(all_operators_used)*100
    op_improvement = current_op_coverage - original_op_coverage
    
    print(f"   Functions: {original_func_coverage:.1f}% → {current_func_coverage:.1f}% (+{func_improvement:.1f}%)")
    print(f"   Operators: {original_op_coverage:.1f}% → {current_op_coverage:.1f}% (+{op_improvement:.1f}%)")
    
    # Recommendations
    print(f"\n🎯 NEXT STEPS:")
    if still_missing:
        print(f"   • Add {len(still_missing)} remaining missing functions")
        high_priority = [f for f in still_missing if validation.get("missing_functions", {}).get(f, [0])[0] > 5]
        if high_priority:
            print(f"   • High priority functions (>5 uses): {', '.join(high_priority[:5])}")
    
    if still_missing_ops:
        print(f"   • Add {len(still_missing_ops)} remaining missing operators")
    
    # Field analysis
    missing_fields = validation.get("missing_fields", {})
    total_missing_field_instances = sum(len(fields) for fields in missing_fields.values())
    print(f"   • Review {len(missing_fields)} tables with missing fields ({total_missing_field_instances} field instances)")
    
    return {
        "function_coverage": current_func_coverage,
        "operator_coverage": current_op_coverage,
        "functions_remaining": len(still_missing),
        "operators_remaining": len(still_missing_ops)
    }

if __name__ == "__main__":
    analyze_coverage()
