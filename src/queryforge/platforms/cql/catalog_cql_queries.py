#!/usr/bin/env python3
"""
CQL Query Cataloging Script
Extracts and catalogs all CQL example queries with comprehensive metadata
"""

import os
import re
import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Optional, Tuple

class CQLQueryCatalog:
    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
        self.queries = []
        self.stats = {
            'total': 0,
            'by_category': defaultdict(int),
            'by_difficulty': defaultdict(int),
            'by_query_type': defaultdict(int),
            'event_types': defaultdict(int),
            'functions': defaultdict(int),
            'mitre_tactics': defaultdict(int),
            'mitre_techniques': defaultdict(int),
            'platforms': defaultdict(int),
            'tags': defaultdict(int)
        }

        # CQL function patterns
        self.cql_functions = [
            'groupBy', 'count', 'table', 'sort', 'join', 'selfJoinFilter', 'correlate',
            'rename', 'default', 'format', 'concat', 'in', 'match', 'regex', 'test',
            'ipLocation', 'worldMap', 'sankey', 'timechart', 'bucket', 'stats',
            'top', 'tail', 'head', 'limit', 'select', 'drop', 'case', 'eval',
            'split', 'replace', 'toInt', 'toString', 'lower', 'upper', 'trim',
            'substring', 'length', 'array', 'kvParse', 'readFile', 'parseJson',
            'parseXml', 'parseCsv', 'sequence', 'transpose', 'union', 'diff',
            'avg', 'sum', 'min', 'max', 'stddev', 'percentile', 'selectFromMax',
            'selectFromMin', 'asn', 'cidr', 'domain', 'tail', 'timeChart',
            'streamQuery', 'filterAsync', 'aggregate'
        ]

    def extract_code_blocks(self, content: str) -> List[str]:
        """Extract CQL code from markdown code blocks"""
        # Match code blocks with or without language specifier
        pattern = r'```(?:cql|logscale|crowdstrike|falcon)?\s*\n(.*?)\n```'
        blocks = re.findall(pattern, content, re.DOTALL)

        # Also try without language specifier
        if not blocks:
            pattern = r'```\s*\n(.*?)\n```'
            blocks = re.findall(pattern, content, re.DOTALL)

        return [block.strip() for block in blocks if block.strip()]

    def extract_event_types(self, query: str) -> List[str]:
        """Extract event_simpleName values from query"""
        # Match #event_simpleName=Value or #event_simpleName=*Value*
        pattern = r'#event_simpleName\s*=\s*(["\']?)(\w+)\1'
        matches = re.findall(pattern, query)
        return list(set([m[1] for m in matches]))

    def extract_functions(self, query: str) -> List[str]:
        """Extract CQL functions used in query"""
        found_functions = []
        for func in self.cql_functions:
            # Match function name followed by (
            if re.search(rf'\b{func}\s*\(', query):
                found_functions.append(func)
        return sorted(list(set(found_functions)))

    def extract_operators(self, query: str) -> List[str]:
        """Extract operators used in query"""
        operators = set()
        operator_patterns = [
            r'!=', r'<=', r'>=', r'=', r'<', r'>',
            r'\bregex\b', r'\bin\b', r'\bmatch\b', r'\blike\b',
            r'\band\b', r'\bor\b', r'\bnot\b',
            r'\|'
        ]

        for pattern in operator_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                operator = pattern.replace(r'\b', '').replace('\\', '')
                operators.add(operator)

        return sorted(list(operators))

    def extract_fields(self, query: str) -> List[str]:
        """Extract field names referenced in query"""
        fields = set()

        # Match field assignments: field=value or field = value
        field_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_\.]*)\s*='
        matches = re.findall(field_pattern, query)

        # Filter out common keywords and event_simpleName
        keywords = {'event_simpleName', 'true', 'false', 'null'}
        for field in matches:
            if field not in keywords and not field.startswith('event_'):
                fields.add(field)

        # Match field references in functions: function(field)
        func_field_pattern = r'\(([a-zA-Z_][a-zA-Z0-9_\.]*)\)'
        matches = re.findall(func_field_pattern, query)
        for field in matches:
            if field not in keywords:
                fields.add(field)

        return sorted(list(fields))[:20]  # Limit to 20 most relevant fields

    def detect_correlation_patterns(self, query: str) -> List[str]:
        """Detect correlation and join patterns"""
        patterns = []

        if re.search(r'\bjoin\b', query, re.IGNORECASE):
            patterns.append('join')
        if re.search(r'\bselfJoinFilter\b', query):
            patterns.append('selfJoinFilter')
        if re.search(r'\bcorrelate\b', query):
            patterns.append('correlate')
        if re.search(r'\bsequence\b', query):
            patterns.append('sequence')
        if re.search(r'\bunion\b', query):
            patterns.append('union')

        return patterns

    def assess_difficulty(self, query: str, functions: List[str],
                         event_types: List[str], correlations: List[str]) -> str:
        """Assess query difficulty level"""

        expert_functions = {'correlate', 'selfJoinFilter', 'sequence'}
        advanced_functions = {'join', 'union', 'streamQuery', 'aggregate'}

        # Expert level
        if any(f in expert_functions for f in functions):
            return 'expert'
        if len(correlations) >= 2:
            return 'expert'

        # Advanced level
        if any(f in advanced_functions for f in functions):
            return 'advanced'
        if len(event_types) >= 3:
            return 'advanced'
        if 'join' in correlations:
            return 'advanced'

        # Intermediate level
        if len(functions) >= 3:
            return 'intermediate'
        if len(event_types) == 2:
            return 'intermediate'
        if any(f in ['groupBy', 'stats', 'timechart'] for f in functions):
            return 'intermediate'

        # Basic level
        return 'basic'

    def detect_query_type(self, query: str, title: str, description: str,
                          functions: List[str]) -> str:
        """Detect query type based on content and metadata"""

        combined_text = f"{title} {description} {query}".lower()

        # Visualization
        if any(f in functions for f in ['worldMap', 'sankey', 'timechart']):
            return 'visualization'

        # Detection
        if any(word in combined_text for word in ['detect', 'alert', 'suspicious', 'malicious', 'threat']):
            return 'detection'

        # Hunting
        if any(word in combined_text for word in ['hunt', 'search', 'find', 'investigate']):
            return 'hunting'

        # Inventory
        if any(word in combined_text for word in ['inventory', 'list', 'enumerate', 'asset']):
            return 'inventory'

        # Monitoring
        if any(word in combined_text for word in ['monitor', 'track', 'watch', 'observe']):
            return 'monitoring'

        # Analysis
        if any(f in functions for f in ['stats', 'aggregate', 'groupBy', 'count']):
            return 'analysis'

        return 'utility'

    def detect_platform(self, query: str, title: str) -> List[str]:
        """Detect target platforms"""
        platforms = set()
        combined_text = f"{title} {query}".lower()

        if any(word in combined_text for word in ['windows', 'win', 'registry', 'powershell', 'cmd.exe']):
            platforms.add('Win')
        if any(word in combined_text for word in ['mac', 'macos', 'darwin', 'osx']):
            platforms.add('Mac')
        if any(word in combined_text for word in ['linux', 'lin', 'unix', 'bash']):
            platforms.add('Lin')

        return sorted(list(platforms)) if platforms else ['Cross-platform']

    def generate_tags(self, query_data: Dict) -> List[str]:
        """Generate tags from query metadata"""
        tags = set()

        # Add event types as tags
        for event in query_data['event_types']:
            tags.add(event.lower())

        # Add platform tags
        for platform in query_data['platforms']:
            tags.add(platform.lower())

        # Add key functions as tags
        important_funcs = {'join', 'correlate', 'worldMap', 'sankey', 'timechart'}
        for func in query_data['functions_used']:
            if func in important_funcs:
                tags.add(func.lower())

        # Extract keywords from title
        title_words = re.findall(r'\b\w+\b', query_data['title'].lower())
        keywords = ['rdp', 'ssh', 'dns', 'network', 'process', 'file', 'registry',
                   'user', 'login', 'authentication', 'powershell', 'script']
        for word in title_words:
            if word in keywords:
                tags.add(word)

        return sorted(list(tags))[:10]  # Limit to 10 tags

    def parse_mitre_path(self, file_path: str) -> Optional[Dict]:
        """Parse MITRE ATT&CK metadata from file path"""
        # Expected format: (TA007) Discovery/(T1057) Process Discovery.md
        match = re.search(r'\(TA(\d+)\)\s+([^/]+)/\(T(\d+)(?:\.(\d+))?\)\s+([^.]+)', file_path)

        if match:
            tactic_code = f"TA{match.group(1)}"
            tactic_name = match.group(2).strip()
            technique_id = f"T{match.group(3)}"
            sub_technique = match.group(4)
            technique_name = match.group(5).strip()

            if sub_technique:
                technique_id = f"{technique_id}.{sub_technique}"

            return {
                'tactic_code': tactic_code,
                'tactic_name': tactic_name,
                'technique_id': technique_id,
                'technique_name': technique_name,
                'sub_technique_id': sub_technique if sub_technique else None
            }

        return None

    def sanitize_filename(self, name: str) -> str:
        """Convert filename to lowercase with hyphens"""
        # Remove file extension
        name = re.sub(r'\.md$', '', name)
        # Remove MITRE codes
        name = re.sub(r'\([TA]\d+\)\s*', '', name)
        name = re.sub(r'\(T\d+(?:\.\d+)?\)\s*', '', name)
        # Replace spaces and special chars with hyphens
        name = re.sub(r'[^\w\s-]', '', name)
        name = re.sub(r'[-\s]+', '-', name)
        return name.lower().strip('-')

    def extract_description(self, content: str) -> str:
        """Extract description from markdown content"""
        # Remove code blocks first
        content = re.sub(r'```.*?```', '', content, flags=re.DOTALL)

        # Look for description patterns
        patterns = [
            r'(?:Description|Summary|Overview):\s*(.+?)(?:\n\n|\n#)',
            r'^(.+?)(?:\n\n|\n```)',  # First paragraph
        ]

        for pattern in patterns:
            match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
            if match:
                desc = match.group(1).strip()
                # Clean up
                desc = re.sub(r'\n+', ' ', desc)
                desc = re.sub(r'\s+', ' ', desc)
                return desc[:300]  # Limit length

        return ""

    def process_query_file(self, file_path: Path, category: str) -> Dict:
        """Process a single query file"""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Extract code blocks
        code_blocks = self.extract_code_blocks(content)
        query = code_blocks[0] if code_blocks else ""

        # Get title from filename
        title = file_path.stem

        # Extract metadata
        event_types = self.extract_event_types(query)
        functions = self.extract_functions(query)
        operators = self.extract_operators(query)
        fields = self.extract_fields(query)
        correlations = self.detect_correlation_patterns(query)

        # Assess characteristics
        difficulty = self.assess_difficulty(query, functions, event_types, correlations)
        description = self.extract_description(content)
        query_type = self.detect_query_type(query, title, description, functions)
        platforms = self.detect_platform(query, title)

        # Generate ID
        query_id = self.sanitize_filename(file_path.name)

        # Get relative source path
        source_file = str(file_path.relative_to(self.base_path))

        # Build query data
        query_data = {
            'id': query_id,
            'title': title,
            'source_file': source_file,
            'category': category,
            'subcategory': None,
            'description': description,
            'mitre_attack': None,
            'event_types': event_types,
            'functions_used': functions,
            'operators_used': operators,
            'fields_referenced': fields,
            'correlation_patterns': correlations,
            'difficulty': difficulty,
            'query_type': query_type,
            'platforms': platforms,
            'use_case': description[:200] if description else f"{query_type.title()} query for {title}",
            'query': query,
            'key_features': [],
            'related_examples': [],
            'tags': []
        }

        # Parse MITRE metadata if applicable
        if category == 'mitre_attack':
            mitre_data = self.parse_mitre_path(source_file)
            if mitre_data:
                query_data['mitre_attack'] = mitre_data

        # Determine subcategory based on query characteristics
        if 'worldMap' in functions or 'sankey' in functions:
            query_data['subcategory'] = 'visualization'
        elif 'network' in title.lower() or any(e in ['NetworkConnect', 'DnsRequest'] for e in event_types):
            query_data['subcategory'] = 'network'
        elif any(e in ['ProcessRollup2', 'SyntheticProcessRollup2'] for e in event_types):
            query_data['subcategory'] = 'process'

        # Generate key features
        key_features = []
        if correlations:
            key_features.append(f"Uses {', '.join(correlations)} for correlation")
        if 'worldMap' in functions:
            key_features.append("Geographic visualization")
        if 'ipLocation' in functions:
            key_features.append("IP geolocation enrichment")
        if len(event_types) > 2:
            key_features.append(f"Multi-event correlation ({len(event_types)} event types)")
        if difficulty == 'expert':
            key_features.append("Advanced correlation techniques")

        query_data['key_features'] = key_features[:5]

        # Generate tags
        query_data['tags'] = self.generate_tags(query_data)

        return query_data

    def process_directory(self, directory: Path, category: str):
        """Process all queries in a directory"""
        md_files = list(directory.rglob('*.md'))

        for file_path in md_files:
            try:
                query_data = self.process_query_file(file_path, category)
                self.queries.append(query_data)

                # Update stats
                self.stats['total'] += 1
                self.stats['by_category'][category] += 1
                self.stats['by_difficulty'][query_data['difficulty']] += 1
                self.stats['by_query_type'][query_data['query_type']] += 1

                for event in query_data['event_types']:
                    self.stats['event_types'][event] += 1

                for func in query_data['functions_used']:
                    self.stats['functions'][func] += 1

                for platform in query_data['platforms']:
                    self.stats['platforms'][platform] += 1

                for tag in query_data['tags']:
                    self.stats['tags'][tag] += 1

                if query_data['mitre_attack']:
                    mitre = query_data['mitre_attack']
                    self.stats['mitre_tactics'][f"{mitre['tactic_code']} - {mitre['tactic_name']}"] += 1
                    self.stats['mitre_techniques'][f"{mitre['technique_id']} - {mitre['technique_name']}"] += 1

                print(f"✓ Processed: {query_data['title']}")

            except Exception as e:
                print(f"✗ Error processing {file_path}: {e}")

    def save_queries(self, output_dir: Path):
        """Save individual query JSON files"""
        category_dirs = {
            'cool_query_friday': output_dir / 'cool_query_friday',
            'mitre_attack': output_dir / 'mitre_attack',
            'helpful_query': output_dir / 'helpful_queries'
        }

        for query in self.queries:
            category = query['category']
            output_file = category_dirs[category] / f"{query['id']}.json"

            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(query, f, indent=2, ensure_ascii=False)

    def create_master_index(self, output_dir: Path):
        """Create master index with all queries and statistics"""

        # Sort queries by category and title
        sorted_queries = sorted(self.queries, key=lambda x: (x['category'], x['title']))

        # Create summary metadata
        index = {
            'metadata': {
                'total_queries': self.stats['total'],
                'last_updated': '2025-11-14',
                'version': '1.0.0'
            },
            'summary': {
                'by_category': dict(self.stats['by_category']),
                'by_difficulty': dict(self.stats['by_difficulty']),
                'by_query_type': dict(self.stats['by_query_type']),
                'by_platform': dict(self.stats['platforms'])
            },
            'top_statistics': {
                'top_event_types': sorted(
                    self.stats['event_types'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10],
                'top_functions': sorted(
                    self.stats['functions'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10],
                'top_tags': sorted(
                    self.stats['tags'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:20]
            },
            'mitre_attack': {
                'tactics': dict(self.stats['mitre_tactics']),
                'techniques': dict(self.stats['mitre_techniques']),
                'total_coverage': len(self.stats['mitre_techniques'])
            },
            'queries': [
                {
                    'id': q['id'],
                    'title': q['title'],
                    'category': q['category'],
                    'difficulty': q['difficulty'],
                    'query_type': q['query_type'],
                    'event_types': q['event_types'],
                    'platforms': q['platforms'],
                    'file': f"{q['category']}/{q['id']}.json",
                    'mitre_technique': q['mitre_attack']['technique_id'] if q['mitre_attack'] else None
                }
                for q in sorted_queries
            ]
        }

        output_file = output_dir / 'metadata' / 'examples_index.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(index, f, indent=2, ensure_ascii=False)

        return index

    def print_summary(self):
        """Print summary statistics"""
        print("\n" + "="*80)
        print("CQL QUERY CATALOG SUMMARY")
        print("="*80)

        print(f"\nTotal Queries Cataloged: {self.stats['total']}")

        print("\n--- By Category ---")
        for category, count in sorted(self.stats['by_category'].items()):
            print(f"  {category}: {count}")

        print("\n--- By Difficulty Level ---")
        for difficulty, count in sorted(self.stats['by_difficulty'].items()):
            print(f"  {difficulty}: {count}")

        print("\n--- By Query Type ---")
        for qtype, count in sorted(self.stats['by_query_type'].items()):
            print(f"  {qtype}: {count}")

        print("\n--- By Platform ---")
        for platform, count in sorted(self.stats['platforms'].items()):
            print(f"  {platform}: {count}")

        print("\n--- MITRE ATT&CK Coverage ---")
        print(f"  Unique Tactics: {len(self.stats['mitre_tactics'])}")
        print(f"  Unique Techniques: {len(self.stats['mitre_techniques'])}")

        print("\n--- Top 10 Event Types ---")
        for event, count in sorted(self.stats['event_types'].items(),
                                   key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {event}: {count}")

        print("\n--- Top 10 Functions ---")
        for func, count in sorted(self.stats['functions'].items(),
                                  key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {func}: {count}")

        print("\n" + "="*80)


def main():
    base_path = "/Users/michaeloneil/Github/cql_claude/logscale-community-content-main-2"
    output_dir = Path("/Users/michaeloneil/Github/cql_claude/cql_schemas/examples")

    catalog = CQLQueryCatalog(base_path)

    print("Processing Cool Query Friday queries...")
    catalog.process_directory(
        Path(base_path) / "Queries-Only" / "Cool-Query-Friday",
        "cool_query_friday"
    )

    print("\nProcessing MITRE ATT&CK queries...")
    catalog.process_directory(
        Path(base_path) / "Queries-Only" / "MITRE-ATT&CK-Enterprise",
        "mitre_attack"
    )

    print("\nProcessing Helpful CQL Queries...")
    catalog.process_directory(
        Path(base_path) / "Queries-Only" / "Helpful-CQL-Queries",
        "helpful_query"
    )

    print("\nSaving individual query files...")
    catalog.save_queries(output_dir)

    print("\nCreating master index...")
    index = catalog.create_master_index(Path("/Users/michaeloneil/Github/cql_claude/cql_schemas"))

    catalog.print_summary()

    print(f"\n✓ Catalog complete! Files saved to {output_dir}")
    print(f"✓ Master index saved to cql_schemas/metadata/examples_index.json")


if __name__ == "__main__":
    main()
