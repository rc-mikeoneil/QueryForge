#!/usr/bin/env python3
"""
Quick test of concept expansion functionality.

This tests the Phase 2 implementation to verify that security concepts
are correctly detected and expanded into comprehensive multi-indicator queries.
"""

from shared.security_concepts import (
    detect_security_concepts,
    generate_concept_hints,
    get_concept_description,
)


def test_rdp_concept_detection():
    """Test RDP concept detection from natural language."""
    print("=" * 80)
    print("TEST 1: RDP Concept Detection")
    print("=" * 80)

    test_intents = [
        "Build a query for detecting RDP",
        "Show me remote desktop activity",
        "Find RDP connections",
        "Detect mstsc usage",
    ]

    for intent in test_intents:
        print(f"\nIntent: '{intent}'")
        detected = detect_security_concepts(intent)
        print(f"Detected concepts: {detected}")

        if detected:
            for concept in detected:
                description = get_concept_description(concept)
                print(f"  - {concept}: {description}")
        print()


def test_concept_expansion_cbc():
    """Test concept expansion for CBC platform."""
    print("=" * 80)
    print("TEST 2: CBC Concept Expansion (RDP)")
    print("=" * 80)

    intent = "Build a query for detecting RDP"
    detected = detect_security_concepts(intent)
    print(f"Intent: '{intent}'")
    print(f"Detected: {detected}\n")

    if detected:
        for concept in detected:
            hints = generate_concept_hints({concept}, "cbc")
            print(f"CBC hints for '{concept}':")
            for category, values in hints.items():
                print(f"  {category}: {values}")
    print()


def test_concept_expansion_all_platforms():
    """Test concept expansion across all platforms."""
    print("=" * 80)
    print("TEST 3: Multi-Platform Concept Expansion (RDP)")
    print("=" * 80)

    platforms = ["cbc", "cortex", "kql", "s1"]
    intent = "Build a query for detecting RDP"
    detected = detect_security_concepts(intent)

    print(f"Intent: '{intent}'")
    print(f"Detected concepts: {detected}\n")

    for platform in platforms:
        print(f"\n{platform.upper()} Platform:")
        print("-" * 40)
        for concept in detected:
            hints = generate_concept_hints({concept}, platform)
            for category, values in hints.items():
                if values:
                    print(f"  {category}: {len(values)} values")
                    print(f"    {values[:3]}{'...' if len(values) > 3 else ''}")
    print()


def test_multiple_concepts():
    """Test detection of multiple concepts in one query."""
    print("=" * 80)
    print("TEST 4: Multiple Concept Detection")
    print("=" * 80)

    intent = "Find PowerShell downloads using RDP and SMB lateral movement"
    detected = detect_security_concepts(intent)

    print(f"Intent: '{intent}'")
    print(f"Detected concepts: {detected}\n")

    for concept in detected:
        description = get_concept_description(concept)
        print(f"  - {concept}: {description}")

    print(f"\nTotal concepts detected: {len(detected)}")
    print()


def test_concept_coverage():
    """Test that all major security concepts are defined."""
    print("=" * 80)
    print("TEST 5: Security Concept Coverage")
    print("=" * 80)

    from shared.security_concepts import SECURITY_CONCEPTS

    print(f"Total security concepts defined: {len(SECURITY_CONCEPTS)}\n")

    for concept_id, concept_data in SECURITY_CONCEPTS.items():
        description = concept_data.get("description", "")
        keywords = concept_data.get("keywords", [])
        indicators = concept_data.get("indicators", {})

        print(f"{concept_id}:")
        print(f"  Description: {description}")
        print(f"  Keywords: {keywords[:3]}{'...' if len(keywords) > 3 else ''}")
        print(f"  Indicator categories: {list(indicators.keys())}")
        print()


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("CONCEPT EXPANSION TEST SUITE - Phase 2 Implementation")
    print("=" * 80 + "\n")

    test_rdp_concept_detection()
    test_concept_expansion_cbc()
    test_concept_expansion_all_platforms()
    test_multiple_concepts()
    test_concept_coverage()

    print("=" * 80)
    print("ALL TESTS COMPLETED")
    print("=" * 80)
    print("\nNext Steps:")
    print("1. Run MCP server to test end-to-end query building with concepts")
    print("2. Test queries like 'Build a query for detecting RDP'")
    print("3. Verify comprehensive multi-indicator queries are generated")
    print("=" * 80 + "\n")
