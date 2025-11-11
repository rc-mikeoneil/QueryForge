#!/usr/bin/env python3
"""
Carbon Black Response (CBR) Schema Scraper

Fetches and parses the CBR Event Forwarder schema documentation from:
https://developer.carbonblack.com/reference/enterprise-response/connectors/event-forwarder/event-schema/

Generates split schema JSON files for QueryForge CBR query builder integration.
"""

import json
import re
import requests
from bs4 import BeautifulSoup
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional


class CBRSchemaScraper:
    """Scrapes CBR Event Forwarder schema documentation and generates QueryForge schema files."""
    
    def __init__(self, url: str, output_dir: str = "cbr"):
        self.url = url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Storage for extracted data
        self.server_generated_events = {}
        self.raw_endpoint_events = {}
        self.examples = {}
        self.version = "1.0.0"
        self.updated_at = datetime.utcnow().isoformat() + "Z"
        
    def fetch_page(self) -> BeautifulSoup:
        """Fetch and parse the documentation page."""
        print(f"Fetching schema documentation from: {self.url}")
        response = requests.get(self.url, timeout=30)
        response.raise_for_status()
        return BeautifulSoup(response.content, 'html.parser')
    
    def normalize_type(self, type_str: str) -> str:
        """Normalize type strings to JSON schema types."""
        type_map = {
            'int32': 'integer',
            'in32': 'integer',  # Handle typo
            'float': 'float',
            'string': 'string',
            'bool': 'boolean',
            'boolean': 'boolean',
            'int': 'integer',
            'integer': 'integer'
        }
        normalized = type_str.lower().strip()
        return type_map.get(normalized, 'string')
    
    def extract_field_from_row(self, row) -> Optional[tuple]:
        """Extract field name, type, and description from a table row."""
        cells = row.find_all(['td', 'th'])
        if len(cells) < 2:
            return None
            
        # Try to extract field name and type
        field_name = cells[0].get_text(strip=True)
        
        # Skip header rows
        if field_name.lower() in ['key', 'name', 'field', 'property']:
            return None
            
        # Get type (might be in second or third column)
        field_type = cells[1].get_text(strip=True) if len(cells) > 1 else 'string'
        
        # Get description (might be in third column or combined with type)
        description = ''
        if len(cells) > 2:
            description = cells[2].get_text(strip=True)
        elif len(cells) > 1:
            # Check if second column contains description instead of type
            cell_text = cells[1].get_text(strip=True)
            if not cell_text.lower() in ['int32', 'float', 'string', 'bool', 'boolean', 'int', 'integer']:
                description = cell_text
                field_type = 'string'
        
        if not field_name or field_name.startswith('—'):
            return None
            
        return (field_name, self.normalize_type(field_type), description)
    
    def extract_fields_from_table(self, table) -> Dict[str, Dict[str, str]]:
        """Extract all fields from a documentation table."""
        fields = {}
        rows = table.find_all('tr')
        
        for row in rows:
            field_data = self.extract_field_from_row(row)
            if field_data:
                name, ftype, desc = field_data
                fields[name] = {
                    'type': ftype,
                    'description': desc
                }
        
        return fields
    
    def extract_fields_from_list(self, ul_element) -> Dict[str, Dict[str, str]]:
        """Extract fields from a bulleted list with key-value descriptions."""
        fields = {}
        items = ul_element.find_all('li', recursive=False)
        
        for item in items:
            text = item.get_text(strip=True)
            # Pattern: "field_name (type) - description" or "field_name: description"
            
            # Try pattern with type
            match = re.match(r'(\w+)\s*\((\w+)\)\s*[-–—:]\s*(.*)', text)
            if match:
                name, ftype, desc = match.groups()
                fields[name] = {
                    'type': self.normalize_type(ftype),
                    'description': desc.strip()
                }
                continue
            
            # Try pattern without type
            match = re.match(r'(\w+)\s*[-–—:]\s*(.*)', text)
            if match:
                name, desc = match.groups()
                fields[name] = {
                    'type': 'string',
                    'description': desc.strip()
                }
                continue
            
            # Try just field name
            match = re.match(r'^(\w+)$', text)
            if match:
                name = match.group(1)
                fields[name] = {
                    'type': 'string',
                    'description': ''
                }
        
        return fields
    
    def extract_json_example(self, code_block) -> Optional[Dict]:
        """Extract JSON example from a code block."""
        try:
            code_text = code_block.get_text(strip=True)
            # Try to parse as JSON
            return json.loads(code_text)
        except (json.JSONDecodeError, AttributeError):
            return None
    
    def parse_server_generated_events(self, soup: BeautifulSoup):
        """Parse server-generated event sections."""
        print("Parsing server-generated events...")
        
        # Find main heading
        server_heading = soup.find('h1', string=re.compile(r'Server.*[Gg]enerated.*[Ee]vents?', re.I))
        if not server_heading:
            print("Warning: Could not find 'Server generated events' heading")
            return
        
        # Process all siblings until we hit another h1 or end
        current = server_heading.find_next_sibling()
        section_name = None
        
        while current:
            # Stop at next h1
            if current.name == 'h1':
                break
            
            # h3 or h4 define sections
            if current.name in ['h3', 'h4']:
                section_text = current.get_text(strip=True)
                print(f"  Processing subsection: {section_text}")
                
                # Map section names to field set names
                text_lower = section_text.lower()
                if 'process watchlist hit' in text_lower:
                    section_name = 'watchlist_hit_process_fields'
                elif 'binary watchlist hit' in text_lower:
                    section_name = 'watchlist_hit_binary_fields'
                elif 'process ingress' in text_lower and 'feed' in text_lower:
                    section_name = 'feed_ingress_hit_process_fields'
                elif 'binary ingress' in text_lower and 'feed' in text_lower:
                    section_name = 'feed_ingress_hit_binary_fields'
                elif 'process storage' in text_lower and 'feed' in text_lower:
                    section_name = 'feed_storage_hit_process_fields'
                elif 'binary storage' in text_lower and 'feed' in text_lower:
                    section_name = 'feed_storage_hit_binary_fields'
                elif 'process query' in text_lower and 'feed' in text_lower:
                    section_name = 'feed_query_hit_process_fields'
                elif 'binary query' in text_lower and 'feed' in text_lower:
                    section_name = 'feed_query_hit_binary_fields'
                elif 'scenario 1' in text_lower or 'observed for the first time on any endpoint' in text_lower:
                    section_name = 'binaryinfo_observed_fields'
                elif 'scenario 2' in text_lower or 'observed on an individual endpoint' in text_lower:
                    section_name = 'binaryinfo_host_observed_fields'
                elif 'scenario 3' in text_lower or 'observed within a sensor group' in text_lower:
                    section_name = 'binaryinfo_group_observed_fields'
                elif 'binary file arrival' in text_lower or 'binarystore' in text_lower:
                    section_name = 'binarystore_file_added_fields'
                # Keep section_name if it's just a parent heading
            
            # Extract fields from tables
            elif current.name == 'table' and section_name:
                fields = self.extract_fields_from_table(current)
                if fields:
                    if section_name not in self.server_generated_events:
                        self.server_generated_events[section_name] = {}
                    self.server_generated_events[section_name].update(fields)
                    print(f"    Added {len(fields)} fields to {section_name}")
            
            # Extract fields from lists
            elif current.name == 'ul' and section_name:
                fields = self.extract_fields_from_list(current)
                if fields:
                    if section_name not in self.server_generated_events:
                        self.server_generated_events[section_name] = {}
                    self.server_generated_events[section_name].update(fields)
            
            # Extract examples from code blocks
            elif current.name in ['pre', 'code'] and section_name:
                example = self.extract_json_example(current)
                if example:
                    example_key = section_name.replace('_fields', '')
                    if example_key not in self.examples:
                        self.examples[example_key] = []
                    self.examples[example_key].append({
                        'example': example,
                        'description': f'Example from {section_name}'
                    })
            
            current = current.find_next_sibling()
    
    def parse_raw_endpoint_events(self, soup: BeautifulSoup):
        """Parse raw endpoint event sections."""
        print("Parsing raw endpoint events...")
        
        # Find main heading
        endpoint_heading = soup.find('h1', string=re.compile(r'Raw.*[Ee]ndpoint.*[Ee]vents?', re.I))
        if not endpoint_heading:
            print("Warning: Could not find 'Raw endpoint events' heading")
            return
        
        # Process all siblings until we hit another h1 or end
        current = endpoint_heading.find_next_sibling()
        section_name = None
        
        while current:
            # Stop at next h1
            if current.name == 'h1':
                break
            
            # h2 or h3 define event types
            if current.name in ['h2', 'h3']:
                section_text = current.get_text(strip=True)
                print(f"  Processing subsection: {section_text}")
                
                # Extract event type name from heading
                # Format: "ingress.event.TYPE" or just "TYPE"
                text_lower = section_text.lower()
                if 'ingress.event.' in text_lower:
                    event_type = text_lower.split('ingress.event.')[-1].strip()
                else:
                    # Clean up the heading text to get event type
                    event_type = text_lower.replace('ingress.event.', '').replace(' ', '_').strip()
                
                section_name = f'{event_type}_fields'
            
            # Extract fields from tables
            elif current.name == 'table' and section_name:
                fields = self.extract_fields_from_table(current)
                if fields:
                    if section_name not in self.raw_endpoint_events:
                        self.raw_endpoint_events[section_name] = {}
                    self.raw_endpoint_events[section_name].update(fields)
                    print(f"    Added {len(fields)} fields to {section_name}")
            
            # Extract fields from lists
            elif current.name == 'ul' and section_name:
                fields = self.extract_fields_from_list(current)
                if fields:
                    if section_name not in self.raw_endpoint_events:
                        self.raw_endpoint_events[section_name] = {}
                    self.raw_endpoint_events[section_name].update(fields)
            
            # Extract examples from code blocks
            elif current.name in ['pre', 'code'] and section_name:
                example = self.extract_json_example(current)
                if example:
                    example_key = section_name.replace('_fields', '')
                    if example_key not in self.examples:
                        self.examples[example_key] = []
                    self.examples[example_key].append({
                        'example': example,
                        'description': f'Example from {section_name}'
                    })
            
            current = current.find_next_sibling()
    
    def generate_core_schema(self):
        """Generate cbr_core.json with platform metadata and search types."""
        print("Generating core schema...")
        
        core = {
            'carbonblack_response_query_schema': {
                'version': self.version,
                'updated_at': self.updated_at,
                'platform': 'Carbon Black Response',
                'search_types': {
                    'server_event': {
                        'description': 'Server generated events (watchlist hits, feed hits, binary observations)',
                        'datasets': list(self.server_generated_events.keys())
                    },
                    'endpoint_event': {
                        'description': 'Raw endpoint events (regmod, filemod, netconn, etc.)',
                        'datasets': list(self.raw_endpoint_events.keys())
                    }
                }
            }
        }
        
        output_path = self.output_dir / 'cbr_core.json'
        with open(output_path, 'w') as f:
            json.dump(core, f, indent=2)
        print(f"  Written: {output_path}")
    
    def generate_server_events_schema(self):
        """Generate cbr_server_generated_events.json."""
        print("Generating server events schema...")
        
        schema = {
            'carbonblack_response_query_schema': self.server_generated_events
        }
        
        output_path = self.output_dir / 'cbr_server_generated_events.json'
        with open(output_path, 'w') as f:
            json.dump(schema, f, indent=2)
        print(f"  Written: {output_path}")
        print(f"  Field sets: {list(self.server_generated_events.keys())}")
    
    def generate_endpoint_events_schema(self):
        """Generate cbr_raw_endpoint_events.json."""
        print("Generating endpoint events schema...")
        
        schema = {
            'carbonblack_response_query_schema': self.raw_endpoint_events
        }
        
        output_path = self.output_dir / 'cbr_raw_endpoint_events.json'
        with open(output_path, 'w') as f:
            json.dump(schema, f, indent=2)
        print(f"  Written: {output_path}")
        print(f"  Field sets: {list(self.raw_endpoint_events.keys())}")
    
    def generate_operators_schema(self):
        """Generate cbr_operators.json."""
        print("Generating operators schema...")
        
        operators = {
            'carbonblack_response_query_schema': {
                'logical_operators': {
                    'AND': {
                        'description': 'Logical AND - all conditions must match',
                        'usage': 'field1:value1 AND field2:value2'
                    },
                    'OR': {
                        'description': 'Logical OR - any condition must match',
                        'usage': 'field1:value1 OR field2:value2'
                    }
                },
                'field_operators': {
                    'field:value': {
                        'description': 'Exact field match',
                        'example': 'md5:5d41402abc4b2a76b9719d911017c592'
                    },
                    'field:"quoted value"': {
                        'description': 'Field match with quoted value (for values containing spaces)',
                        'example': 'process_name:"google chrome"'
                    },
                    'field:*wildcard*': {
                        'description': 'Wildcard matching',
                        'example': 'domain:*.malicious.com'
                    },
                    'keyword': {
                        'description': 'Unqualified keyword search across all fields',
                        'example': 'malware.exe'
                    }
                },
                'notes': [
                    'CBR does not support inequality operators (!=, <, >, <=, >=)',
                    'Avoid leading wildcards (*value) for performance reasons',
                    'Use exact field matches when possible for better performance',
                    'Quote values containing spaces'
                ]
            }
        }
        
        output_path = self.output_dir / 'cbr_operators.json'
        with open(output_path, 'w') as f:
            json.dump(operators, f, indent=2)
        print(f"  Written: {output_path}")
    
    def generate_best_practices_schema(self):
        """Generate cbr_best_practices.json."""
        print("Generating best practices schema...")
        
        best_practices = {
            'carbonblack_response_query_schema': {
                'field_usage': {
                    'hash_searches': {
                        'recommendation': 'Prefer field-specific hash searches',
                        'good': 'md5:5d41402abc4b2a76b9719d911017c592',
                        'avoid': '5d41402abc4b2a76b9719d911017c592',
                        'rationale': 'Field-specific searches are more efficient and precise'
                    },
                    'network_searches': {
                        'recommendation': 'Use specific network fields for netconn events',
                        'fields': ['remote_ip', 'local_ip', 'remote_port', 'local_port', 'domain'],
                        'example': 'remote_ip:192.168.1.100 AND remote_port:443'
                    },
                    'process_searches': {
                        'recommendation': 'Use process-specific fields',
                        'fields': ['process_name', 'cmdline', 'path', 'process_guid'],
                        'example': 'process_name:cmd.exe'
                    }
                },
                'value_formatting': {
                    'spaces': {
                        'rule': 'Quote values containing spaces',
                        'example': 'process_name:"google chrome"'
                    },
                    'backslashes': {
                        'rule': 'Escape backslashes in Windows paths',
                        'example': 'path:c:\\\\windows\\\\system32\\\\cmd.exe'
                    }
                },
                'performance': {
                    'wildcards': {
                        'rule': 'Avoid leading wildcards',
                        'good': 'domain:*.malicious.com',
                        'avoid': 'domain:*malicious*',
                        'rationale': 'Leading wildcards prevent index usage and slow queries'
                    },
                    'field_specificity': {
                        'rule': 'Prefer field-specific searches over keywords',
                        'good': 'md5:abc123 AND process_name:malware.exe',
                        'avoid': 'abc123 malware.exe',
                        'rationale': 'Field-specific searches use indexes efficiently'
                    }
                },
                'dataset_selection': {
                    'server_events': {
                        'use_cases': ['Watchlist hits', 'Feed hits', 'Binary observations'],
                        'fields': ['watchlist_name', 'feed_name', 'md5', 'observed_filename']
                    },
                    'endpoint_events': {
                        'use_cases': ['Registry modifications', 'File modifications', 'Network connections', 'Process starts'],
                        'fields': ['regmod', 'filemod', 'netconn', 'procstart', 'childproc']
                    }
                }
            }
        }
        
        output_path = self.output_dir / 'cbr_best_practices.json'
        with open(output_path, 'w') as f:
            json.dump(best_practices, f, indent=2)
        print(f"  Written: {output_path}")
    
    def generate_examples_schema(self):
        """Generate cbr_examples.json."""
        print("Generating examples schema...")
        
        examples = {
            'carbonblack_response_query_schema': self.examples
        }
        
        output_path = self.output_dir / 'cbr_examples.json'
        with open(output_path, 'w') as f:
            json.dump(examples, f, indent=2)
        print(f"  Written: {output_path}")
        print(f"  Example categories: {list(self.examples.keys())}")
    
    def run(self):
        """Execute the full scraping workflow."""
        print("=" * 60)
        print("CBR Schema Scraper - Starting")
        print("=" * 60)
        
        # Fetch and parse page
        soup = self.fetch_page()
        
        # Parse sections
        self.parse_server_generated_events(soup)
        self.parse_raw_endpoint_events(soup)
        
        # Generate schema files
        self.generate_core_schema()
        self.generate_server_events_schema()
        self.generate_endpoint_events_schema()
        self.generate_operators_schema()
        self.generate_best_practices_schema()
        self.generate_examples_schema()
        
        print("=" * 60)
        print("CBR Schema Scraper - Complete")
        print("=" * 60)
        print(f"Server event field sets: {len(self.server_generated_events)}")
        print(f"Endpoint event field sets: {len(self.raw_endpoint_events)}")
        print(f"Example categories: {len(self.examples)}")


def main():
    """Main entry point."""
    url = "https://developer.carbonblack.com/reference/enterprise-response/connectors/event-forwarder/event-schema/"
    scraper = CBRSchemaScraper(url)
    scraper.run()


if __name__ == '__main__':
    main()
