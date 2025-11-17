#!/usr/bin/env python3
"""
Migrate and normalize how-tos and best practices to unified schema.
Creates indexes and updates master schema.
"""

import json
import os
import shutil
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict

# Directories
HOWTOS_SRC = "logscale_howtos_json"
BEST_PRACTICES_SRC = "logscale_best_practices_individual_json"
SCHEMAS_DIR = "cql_schemas"
HOWTOS_DEST = f"{SCHEMAS_DIR}/how_tos"
BEST_PRACTICES_DEST = f"{SCHEMAS_DIR}/best_practices"
METADATA_DIR = f"{SCHEMAS_DIR}/metadata"

# Statistics
stats = {
    "howtos_processed": 0,
    "best_practices_processed": 0,
    "howtos_migrated": 0,
    "best_practices_migrated": 0,
    "errors": []
}

def ensure_directories():
    """Create necessary directories."""
    Path(HOWTOS_DEST).mkdir(parents=True, exist_ok=True)
    Path(BEST_PRACTICES_DEST).mkdir(parents=True, exist_ok=True)
    Path(METADATA_DIR).mkdir(parents=True, exist_ok=True)
    print(f"✅ Created directories: {HOWTOS_DEST}, {BEST_PRACTICES_DEST}")

def categorize_by_tags(tags: List[str]) -> str:
    """Infer category from tags."""
    tag_lower = [t.lower() for t in tags]

    if any(t in tag_lower for t in ['integration', 'cribl', 'crowdstream', 'ingest', 'shipper']):
        return "integration"
    elif any(t in tag_lower for t in ['admin', 'user', 'graphql', 'api']):
        return "admin"
    elif any(t in tag_lower for t in ['performance', 'optimization', 'speed']):
        return "performance"
    elif any(t in tag_lower for t in ['security', 'detection', 'alert']):
        return "security"
    elif any(t in tag_lower for t in ['query', 'search', 'cql', 'logscale']):
        return "query"
    else:
        return "general"

def estimate_difficulty(description: str, examples: List[Dict]) -> str:
    """Estimate difficulty based on content."""
    text = (description + " " + " ".join([ex.get("query", "") for ex in examples])).lower()

    # Advanced indicators
    advanced_indicators = ['correlate', 'selfjoinfilter', 'sequence', 'join', 'regex', 'advanced']
    if any(ind in text for ind in advanced_indicators):
        return "advanced"

    # Intermediate indicators
    intermediate_indicators = ['groupby', 'aggregate', 'stats', 'multiple', 'complex']
    if any(ind in text for ind in intermediate_indicators):
        return "intermediate"

    return "beginner"

def normalize_how_to(data: Dict[str, Any], filename: str) -> Dict[str, Any]:
    """Normalize how-to to unified schema."""
    # Already mostly in correct format
    normalized = {
        "title": data.get("title", ""),
        "slug": data.get("slug", filename.replace(".json", "")),
        "type": "how-to",
        "product": data.get("product", "Falcon LogScale"),
        "category": data.get("category", categorize_by_tags(data.get("tags", []))),
        "description": data.get("description", ""),
        "examples": data.get("examples", []),
        "tags": data.get("tags", [])
    }

    # Add difficulty
    normalized["difficulty"] = estimate_difficulty(normalized["description"], normalized["examples"])

    # Extract related functions from queries
    related_funcs = set()
    for ex in normalized["examples"]:
        query = ex.get("query", "")
        # Simple function extraction (look for common patterns)
        import re
        funcs = re.findall(r'\b([a-zA-Z]+)\s*\(', query)
        related_funcs.update(funcs)

    if related_funcs:
        normalized["related_functions"] = sorted(list(related_funcs))

    return normalized

def normalize_best_practice(data: Dict[str, Any], filename: str) -> Dict[str, Any]:
    """Normalize best practice to unified schema."""
    # Convert single example to array format
    example = data.get("example", {})
    examples = [{
        "name": "Example",
        "description": example.get("explanation", data.get("description", "")),
        "language": "logscale",
        "query": example.get("query", "")
    }]

    tags = data.get("tags", [])

    normalized = {
        "title": data.get("title", ""),
        "slug": filename.replace(".json", ""),
        "type": "best-practice",
        "product": "Falcon LogScale",
        "category": categorize_by_tags(tags),
        "description": data.get("description", ""),
        "examples": examples,
        "tags": tags
    }

    # Add URL if present
    if "url" in data:
        normalized["url"] = data["url"]

    # Add difficulty
    normalized["difficulty"] = estimate_difficulty(normalized["description"], normalized["examples"])

    # Extract related functions
    related_funcs = set()
    for ex in normalized["examples"]:
        query = ex.get("query", "")
        import re
        funcs = re.findall(r'\b([a-zA-Z]+)\s*\(', query)
        related_funcs.update(funcs)

    if related_funcs:
        normalized["related_functions"] = sorted(list(related_funcs))

    return normalized

def migrate_files():
    """Migrate and normalize all files."""
    print("\n📦 Migrating How-Tos...")

    # Migrate how-tos
    for filename in os.listdir(HOWTOS_SRC):
        if not filename.endswith(".json"):
            continue

        stats["howtos_processed"] += 1
        src_path = os.path.join(HOWTOS_SRC, filename)
        dest_path = os.path.join(HOWTOS_DEST, filename)

        try:
            with open(src_path, 'r') as f:
                data = json.load(f)

            normalized = normalize_how_to(data, filename)

            with open(dest_path, 'w') as f:
                json.dump(normalized, f, indent=2)

            stats["howtos_migrated"] += 1

        except Exception as e:
            stats["errors"].append(f"How-to {filename}: {str(e)}")
            print(f"  ❌ Error in {filename}: {e}")

    print(f"  ✅ Migrated {stats['howtos_migrated']}/{stats['howtos_processed']} how-tos")

    print("\n📦 Migrating Best Practices...")

    # Migrate best practices
    for filename in os.listdir(BEST_PRACTICES_SRC):
        if not filename.endswith(".json"):
            continue

        stats["best_practices_processed"] += 1
        src_path = os.path.join(BEST_PRACTICES_SRC, filename)
        dest_path = os.path.join(BEST_PRACTICES_DEST, filename)

        try:
            with open(src_path, 'r') as f:
                data = json.load(f)

            normalized = normalize_best_practice(data, filename)

            with open(dest_path, 'w') as f:
                json.dump(normalized, f, indent=2)

            stats["best_practices_migrated"] += 1

        except Exception as e:
            stats["errors"].append(f"Best practice {filename}: {str(e)}")
            print(f"  ❌ Error in {filename}: {e}")

    print(f"  ✅ Migrated {stats['best_practices_migrated']}/{stats['best_practices_processed']} best practices")

def create_index(source_dir: str, index_type: str) -> Dict[str, Any]:
    """Create index file for how-tos or best practices."""
    items = []
    by_category = defaultdict(int)
    by_difficulty = defaultdict(int)
    all_tags = defaultdict(int)
    all_functions = defaultdict(int)

    for filename in sorted(os.listdir(source_dir)):
        if not filename.endswith(".json"):
            continue

        with open(os.path.join(source_dir, filename), 'r') as f:
            data = json.load(f)

        # Collect statistics
        category = data.get("category", "general")
        difficulty = data.get("difficulty", "beginner")
        by_category[category] += 1
        by_difficulty[difficulty] += 1

        for tag in data.get("tags", []):
            all_tags[tag] += 1

        for func in data.get("related_functions", []):
            all_functions[func] += 1

        # Add to items list
        items.append({
            "slug": data.get("slug"),
            "title": data.get("title"),
            "category": category,
            "difficulty": difficulty,
            "tags": data.get("tags", []),
            "file": f"{index_type}/{filename}"
        })

    # Create index structure
    index = {
        "schema_version": "2.0.0",
        "type": index_type,
        "generated_at": "2025-11-15T00:00:00Z",
        "total_count": len(items),
        "summary": {
            "by_category": dict(by_category),
            "by_difficulty": dict(by_difficulty)
        },
        "top_tags": [
            {"tag": tag, "count": count}
            for tag, count in sorted(all_tags.items(), key=lambda x: x[1], reverse=True)[:20]
        ],
        "top_functions": [
            {"function": func, "count": count}
            for func, count in sorted(all_functions.items(), key=lambda x: x[1], reverse=True)[:20]
        ],
        "items": items
    }

    return index

def create_indexes():
    """Create index files for both types."""
    print("\n📑 Creating Indexes...")

    # How-tos index
    howtos_index = create_index(HOWTOS_DEST, "how_tos")
    with open(f"{METADATA_DIR}/how_tos_index.json", 'w') as f:
        json.dump(howtos_index, f, indent=2)
    print(f"  ✅ Created how_tos_index.json ({howtos_index['total_count']} items)")

    # Best practices index
    bp_index = create_index(BEST_PRACTICES_DEST, "best_practices")
    with open(f"{METADATA_DIR}/best_practices_index.json", 'w') as f:
        json.dump(bp_index, f, indent=2)
    print(f"  ✅ Created best_practices_index.json ({bp_index['total_count']} items)")

    return howtos_index, bp_index

def update_master_index(howtos_index: Dict, bp_index: Dict):
    """Update master schema index with new sections."""
    print("\n📝 Updating Master Schema Index...")

    master_path = f"{METADATA_DIR}/master_schema_index.json"

    with open(master_path, 'r') as f:
        master = json.load(f)

    # Update version
    master["schema_version"] = "2.0.0"
    master["generated_at"] = "2025-11-15T00:00:00Z"

    # Add how_tos section
    master["how_tos"] = {
        "index_file": "metadata/how_tos_index.json",
        "directory": "how_tos/",
        "total_count": howtos_index["total_count"],
        "status": "complete",
        "by_category": howtos_index["summary"]["by_category"],
        "by_difficulty": howtos_index["summary"]["by_difficulty"]
    }

    # Add best_practices section
    master["best_practices"] = {
        "index_file": "metadata/best_practices_index.json",
        "directory": "best_practices/",
        "total_count": bp_index["total_count"],
        "status": "complete",
        "by_category": bp_index["summary"]["by_category"],
        "by_difficulty": bp_index["summary"]["by_difficulty"]
    }

    # Update statistics
    if "statistics" in master:
        master["statistics"]["total_schemas"] = (
            master["statistics"].get("total_schemas", 0) +
            howtos_index["total_count"] +
            bp_index["total_count"]
        )
        master["statistics"]["breakdown"]["how_tos"] = howtos_index["total_count"]
        master["statistics"]["breakdown"]["best_practices"] = bp_index["total_count"]

    with open(master_path, 'w') as f:
        json.dump(master, f, indent=2)

    print(f"  ✅ Updated master_schema_index.json")

def print_summary():
    """Print migration summary."""
    print("\n" + "="*60)
    print("📊 MIGRATION SUMMARY")
    print("="*60)
    print(f"How-Tos:         {stats['howtos_migrated']}/{stats['howtos_processed']} migrated")
    print(f"Best Practices:  {stats['best_practices_migrated']}/{stats['best_practices_processed']} migrated")
    print(f"Total:           {stats['howtos_migrated'] + stats['best_practices_migrated']} files migrated")

    if stats["errors"]:
        print(f"\n⚠️  Errors: {len(stats['errors'])}")
        for error in stats["errors"][:5]:
            print(f"  - {error}")
        if len(stats["errors"]) > 5:
            print(f"  ... and {len(stats['errors']) - 5} more")
    else:
        print("\n✅ No errors!")

    print("="*60)

def main():
    """Main migration function."""
    print("🚀 Starting Migration: How-Tos and Best Practices")
    print("="*60)

    # Step 1: Create directories
    ensure_directories()

    # Step 2: Migrate files
    migrate_files()

    # Step 3: Create indexes
    howtos_index, bp_index = create_indexes()

    # Step 4: Update master index
    update_master_index(howtos_index, bp_index)

    # Step 5: Print summary
    print_summary()

    print("\n✅ Migration Complete!")
    print(f"\nNew locations:")
    print(f"  - How-Tos: {HOWTOS_DEST}/")
    print(f"  - Best Practices: {BEST_PRACTICES_DEST}/")
    print(f"  - Indexes: {METADATA_DIR}/{{how_tos,best_practices}}_index.json")
    print(f"\n⚠️  Original directories preserved for validation")

if __name__ == "__main__":
    main()
