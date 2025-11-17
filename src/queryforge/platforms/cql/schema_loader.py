"""
Schema loader for CrowdStrike Query Language (CQL).

This module provides schema loading and caching functionality for CQL,
including dataset definitions, field schemas, operators, and best practices.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class CQLSchemaLoader:
    """Load and provide access to CQL schema definitions."""

    def __init__(self, schema_dir: Optional[Path] = None, cache_dir: Optional[Path] = None) -> None:
        """
        Initialize CQL schema loader.

        Parameters
        ----------
        schema_dir : Optional[Path]
            Directory containing CQL schema JSON files.
            Defaults to the cql_schemas subdirectory.
        cache_dir : Optional[Path]
            Directory for cache files (not currently used, for API compatibility).
        """
        if schema_dir is None:
            schema_dir = Path(__file__).parent / "cql_schemas"
        self.schema_dir = Path(schema_dir)
        self._cache: Dict[str, Any] = {}
        self._full_schema_cache: Optional[Dict[str, Any]] = None

    def load(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Load complete CQL schema for RAG indexing.

        This method aggregates all schema components into a unified dictionary
        that can be consumed by the RAG document builder.

        Parameters
        ----------
        force_refresh : bool
            If True, clear caches and reload from disk.

        Returns
        -------
        Dict[str, Any]
            Complete schema dictionary with all components.
        """
        if force_refresh:
            self._cache.clear()
            self._full_schema_cache = None

        if self._full_schema_cache is not None:
            return self._full_schema_cache

        logger.info("Loading CQL schema from %s", self.schema_dir)

        # Aggregate all schema components
        schema = {
            "core": self.get_core_info(),
            "datasets": self.get_datasets().get("datasets", []),
            "operators": self.get_operators(),
            "best_practices": self.get_best_practices(),
            "patterns": self.get_patterns(),
            "examples": self.get_examples().get("examples", []),
            "documentation": self.get_documentation(),
        }

        # Add placeholder fields for common datasets
        # This creates a structure compatible with build_cql_documents()
        placeholder_fields = {}
        for dataset_info in schema["datasets"]:
            dataset_name = dataset_info.get("name", "")
            if dataset_name:
                fields_data = self.get_fields(dataset_name)
                fields_dict = {
                    field["name"]: {
                        "type": field.get("type", "string"),
                        "description": field.get("description", ""),
                        "indexed": field.get("indexed", True),
                    }
                    for field in fields_data.get("fields", [])
                }
                placeholder_fields[dataset_name] = fields_dict

        schema["placeholder_fields"] = placeholder_fields

        # Cache the result
        self._full_schema_cache = schema
        
        logger.info(
            "Loaded CQL schema: %d datasets, %d operators, %d best practices, %d examples",
            len(schema["datasets"]),
            len(schema["operators"].get("operators", [])),
            len(schema["best_practices"]),
            len(schema["examples"]),
        )

        return schema

    def _load_json(self, filename: str) -> Dict[str, Any]:
        """Load and cache a JSON schema file."""
        if filename in self._cache:
            return self._cache[filename]

        file_path = self.schema_dir / filename
        if not file_path.exists():
            logger.warning("Schema file not found: %s", file_path)
            return {}

        try:
            with file_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            self._cache[filename] = data
            logger.debug("Loaded CQL schema: %s", filename)
            return data
        except (json.JSONDecodeError, IOError) as exc:
            logger.error("Failed to load %s: %s", filename, exc)
            return {}

    def get_core_info(self) -> Dict[str, Any]:
        """Get core platform information."""
        # Load from cql_core.json
        core_data = self._load_json("cql_core.json")
        if core_data:
            return core_data
        
        # Fallback to hardcoded values if file not found
        logger.warning("cql_core.json not found, using fallback values")
        return {
            "schema_version": "1.0.0",
            "platform": {
                "name": "CrowdStrike Query Language (CQL)",
                "short_name": "cql",
                "version": "2024.1",
                "description": "CrowdStrike's query language for threat hunting and security analytics across Falcon event data"
            },
            "datasets": [
                {
                    "name": "events",
                    "display_name": "Falcon Events",
                    "description": "Primary dataset for endpoint events including process execution, network activity, file operations, and authentication events",
                    "event_types": ["ProcessRollup2", "NetworkConnectIP4", "DnsRequest", "UserLogon", "UserLogonFailed2", "DriverLoad", "InstalledBrowserExtension", "AgentOnline", "EndOfProcess", "OsVersionInfo"],
                    "primary_use_cases": ["Threat hunting", "Process analysis", "Network monitoring", "Behavioral detection"],
                    "search_type": "#event_simpleName=<event_type>"
                },
                {
                    "name": "detections",
                    "display_name": "Detections",
                    "description": "Security detections and alerts generated by Falcon",
                    "event_types": ["DetectionSummaryEvent"],
                    "primary_use_cases": ["Alert analysis", "Detection hunting", "Incident response"],
                    "search_type": "event_simpleName=DetectionSummaryEvent"
                }
            ]
        }

    def get_datasets(self, query_intent: Optional[str] = None) -> Dict[str, Any]:
        """
        Get available datasets with optional semantic filtering.

        Parameters
        ----------
        query_intent : Optional[str]
            Natural language description to filter datasets.
            If provided, uses RAG to find semantically relevant datasets.

        Returns
        -------
        Dict[str, Any]
            Dictionary with datasets list and metadata.
        """
        core = self.get_core_info()
        datasets = core.get("datasets", [])

        if query_intent:
            # RAG-enhanced filtering will be implemented when RAG is integrated
            # For now, return all datasets with a note about the intent
            return {
                "datasets": datasets,
                "query_intent": query_intent,
                "note": "Semantic filtering will be enabled when RAG integration is complete"
            }

        return {"datasets": datasets}

    def get_fields(self, dataset: str, query_intent: Optional[str] = None) -> Dict[str, Any]:
        """
        Get available fields for a dataset.

        Parameters
        ----------
        dataset : str
            Dataset name (e.g., 'events', 'detections', 'indicators')
        query_intent : Optional[str]
            Natural language description to filter fields semantically.

        Returns
        -------
        Dict[str, Any]
            Dictionary with fields and metadata.
        """
        # Load fields from the table schemas
        fields_list = []
        
        # Get table schemas from the tables directory
        tables_dir = self.schema_dir / "tables"
        if tables_dir.exists():
            # Load ALL event types from the tables directory, not just a hardcoded subset
            try:
                for table_file in tables_dir.glob("*.json"):
                    try:
                        with table_file.open("r", encoding="utf-8") as f:
                            table_data = json.load(f)
                        
                        # Extract fields from the table schema
                        for field in table_data.get("columns", []):
                            field_entry = {
                                "name": field.get("name", ""),
                                "type": field.get("type", "string"),
                                "description": field.get("description", ""),
                                "indexed": field.get("searchable", True)
                            }
                            # Avoid duplicates
                            if not any(f["name"] == field_entry["name"] for f in fields_list):
                                fields_list.append(field_entry)
                                
                    except (json.JSONDecodeError, IOError) as exc:
                        logger.warning("Failed to load table schema %s: %s", table_file, exc)
            except Exception as exc:
                logger.warning("Failed to list table schemas: %s", exc)

        # If no fields found, add some common CQL fields
        if not fields_list:
            common_fields = [
                {"name": "aid", "type": "string", "description": "Agent ID", "indexed": True},
                {"name": "ComputerName", "type": "string", "description": "Hostname", "indexed": True},
                {"name": "UserName", "type": "string", "description": "Username", "indexed": True},
                {"name": "FileName", "type": "string", "description": "Process filename", "indexed": True},
                {"name": "ImageFileName", "type": "string", "description": "Full process path", "indexed": True},
                {"name": "CommandLine", "type": "string", "description": "Command line arguments", "indexed": True},
                {"name": "TargetProcessId", "type": "long", "description": "Process ID", "indexed": True},
                {"name": "@timestamp", "type": "datetime", "description": "Event timestamp", "indexed": True},
                {"name": "event_simpleName", "type": "string", "description": "Event type", "indexed": True},
            ]
            fields_list = common_fields

        result = {
            "dataset": dataset,
            "fields": fields_list,
            "count": len(fields_list)
        }

        if query_intent:
            result["query_intent"] = query_intent
            result["note"] = "Semantic filtering will be enabled when RAG integration is complete"

        return result

    def get_field_types(self) -> Dict[str, Any]:
        """Get field type definitions and compatible operators."""
        # Load from builder/validation_rules.json
        validation_rules = self._load_json("builder/validation_rules.json")
        return validation_rules.get("field_type_definitions", {})

    def get_operators(self) -> Dict[str, Any]:
        """Get operator definitions and normalization rules."""
        # Load from operators/operators.json
        return self._load_json("operators/operators.json")

    def get_best_practices(self) -> List[Dict[str, Any]]:
        """Get query best practices."""
        # Load from metadata/best_practices_index.json
        best_practices_index = self._load_json("metadata/best_practices_index.json")
        
        # Convert to list format expected by other components
        practices_list = []
        
        # The schema uses "items" at the top level, not "by_category"
        items = best_practices_index.get("items", [])
        for item in items:
            practices_list.append({
                "category": item.get("category", "general"),
                "title": item.get("title", ""),
                "description": "",  # Description is in separate files
                "importance": item.get("difficulty", "medium"),
                "tags": item.get("tags", [])
            })
        
        return practices_list

    def get_patterns(self) -> Dict[str, Any]:
        """Get comprehensive query patterns."""
        # Load from builder/context_examples.json
        return self._load_json("builder/context_examples.json")

    def get_examples(self, category: Optional[str] = None, query_intent: Optional[str] = None) -> Dict[str, Any]:
        """
        Get example queries, optionally filtered by category or semantic search.

        Parameters
        ----------
        category : Optional[str]
            Filter examples by category (e.g., 'process_execution', 'network_activity')
        query_intent : Optional[str]
            Natural language description to find semantically relevant examples.

        Returns
        -------
        Dict[str, Any]
            Dictionary with examples and metadata.
        """
        # Load from metadata/examples_index.json
        examples_index = self._load_json("metadata/examples_index.json")
        all_examples = examples_index.get("queries", [])

        if category:
            # Filter by category
            filtered = [ex for ex in all_examples if ex.get("category") == category]
            return {
                "examples": filtered,
                "category": category,
                "count": len(filtered)
            }

        if query_intent:
            # RAG-enhanced filtering will be implemented when RAG is integrated
            return {
                "examples": all_examples,
                "query_intent": query_intent,
                "count": len(all_examples),
                "note": "Semantic filtering will be enabled when RAG integration is complete"
            }

        return {
            "examples": all_examples,
            "count": len(all_examples)
        }

    def get_documentation(self) -> Dict[str, Any]:
        """Get documentation sections for RAG integration."""
        # Build documentation from schema structure
        docs = {
            "schema_version": "1.0.0",
            "sections": []
        }
        
        # Load functions index for documentation
        functions_index = self._load_json("metadata/functions_index.json")
        if functions_index:
            docs["sections"].append({
                "title": "CQL Functions",
                "content": f"CQL provides {len(functions_index.get('functions', []))} built-in functions across {len(functions_index.get('by_category', {}))} categories for data analysis, transformation, and visualization.",
                "keywords": ["functions", "operations", "analysis"]
            })
        
        # Load operators for documentation
        operators_data = self.get_operators()
        if operators_data:
            docs["sections"].append({
                "title": "CQL Operators",
                "content": f"CQL supports {len(operators_data.get('operators', []))} operators including comparison, pattern matching, logical, and special operators.",
                "keywords": ["operators", "syntax", "filtering"]
            })
        
        return docs

    def normalize_operator(self, operator: str) -> str:
        """
        Normalize an operator to its canonical form.

        Parameters
        ----------
        operator : str
            Operator to normalize (e.g., '==', 'equals', 'contains')

        Returns
        -------
        str
            Normalized operator (e.g., '=', '=', 'contains')
        """
        operators_data = self.get_operators()
        operators_list = operators_data.get("operators", [])

        operator_lower = operator.lower().strip()

        # Common normalization mappings
        normalize_map = {
            "==": "=",
            "equals": "=",
            "not equals": "!=",
            "contains": "=*",
            "matches": "=/regex/",
            "greater than": ">",
            "less than": "<",
            "greater than or equal": ">=",
            "less than or equal": "<=",
        }

        if operator_lower in normalize_map:
            return normalize_map[operator_lower]

        # Search through operator definitions for matches
        # operators_list is an array of operator objects
        for op_def in operators_list:
            if isinstance(op_def, dict):
                op_symbol = op_def.get("operator", "")
                op_name = op_def.get("name", "")
                
                # Check if input matches the operator symbol or name
                if operator_lower == op_symbol.lower() or operator_lower == op_name.lower():
                    return op_symbol

        # If not found, return as-is
        logger.debug("Operator '%s' not found in normalization rules, returning as-is", operator)
        return operator

    def get_compatible_operators(self, field_type: str) -> List[str]:
        """
        Get operators compatible with a specific field type.

        Parameters
        ----------
        field_type : str
            Field type (e.g., 'string', 'number', 'datetime', 'ip')

        Returns
        -------
        List[str]
            List of compatible operator symbols.
        """
        # Get operators data which has type_compatibility_matrix
        operators_data = self.get_operators()
        type_matrix = operators_data.get("type_compatibility_matrix", {})
        
        # Return operators compatible with this type
        compatible = type_matrix.get(field_type, [])
        if compatible:
            return compatible
        
        # Fallback: try to get from field_types if available
        field_types = self.get_field_types()
        type_info = field_types.get("field_types", {}).get(field_type, {})
        return type_info.get("compatible_operators", [])

    def validate_field_exists(self, dataset: str, field_name: str) -> bool:
        """
        Check if a field exists in the specified dataset.

        Parameters
        ----------
        dataset : str
            Dataset name
        field_name : str
            Field name to check

        Returns
        -------
        bool
            True if field exists, False otherwise.
        """
        fields_data = self.get_fields(dataset)
        field_names = [f["name"] for f in fields_data.get("fields", [])]
        return field_name in field_names

    def get_field_type(self, dataset: str, field_name: str) -> Optional[str]:
        """
        Get the type of a specific field.

        Parameters
        ----------
        dataset : str
            Dataset name
        field_name : str
            Field name

        Returns
        -------
        Optional[str]
            Field type (e.g., 'string', 'number') or None if not found.
        """
        fields_data = self.get_fields(dataset)
        for field in fields_data.get("fields", []):
            if field["name"] == field_name:
                return field.get("type")
        return None

    def get_fields_by_type(self, dataset: str, field_type: str) -> List[str]:
        """
        Get all fields of a specific type from a dataset.

        Parameters
        ----------
        dataset : str
            Dataset name
        field_type : str
            Field type to filter by (e.g., 'ip_address', 'string', 'long')

        Returns
        -------
        List[str]
            List of field names matching the specified type.
        """
        fields_data = self.get_fields(dataset)
        matching_fields = []
        
        for field in fields_data.get("fields", []):
            if field.get("type") == field_type:
                matching_fields.append(field["name"])
        
        return matching_fields

    def get_field_categories(self) -> Dict[str, List[str]]:
        """
        Get semantic field categories from the schema.

        Returns field groupings by purpose (e.g., 'ip_fields', 'process_fields').
        This method loads field categories from validation_rules.json and 
        field_descriptions_enhanced.json to provide semantic field groupings.

        Returns
        -------
        Dict[str, List[str]]
            Dictionary mapping category names to lists of field names.
        """
        categories = {
            "ip_fields": [],
            "domain_fields": [],
            "process_name_fields": [],
            "cmdline_fields": [],
            "file_name_fields": [],
            "username_fields": [],
            "port_fields": [],
            "hash_fields": {
                "md5": [],
                "sha1": [],
                "sha256": [],
            }
        }
        
        # Load from validation_rules.json
        validation_rules = self._load_json("builder/validation_rules.json")
        
        # Extract IP fields from function validations
        for func_name, func_rules in validation_rules.get("function_field_validations", {}).items():
            if func_name in ["ipLocation", "asn", "cidr", "rdns"]:
                valid_fields = func_rules.get("valid_fields", [])
                for field in valid_fields:
                    if field not in categories["ip_fields"]:
                        categories["ip_fields"].append(field)
        
        # Load from field_descriptions_enhanced.json
        field_descriptions = self._load_json("metadata/field_descriptions_enhanced.json")
        
        # Extract field suffixes/prefixes that indicate field purpose
        suffixes = field_descriptions.get("suffixes", {})
        for field_name, description in suffixes.items():
            if "filename" in description.lower() or field_name == "FileName":
                if field_name not in categories["process_name_fields"]:
                    categories["process_name_fields"].append(field_name)
        
        # Load from cql_field_types.json for type-based categorization
        field_types = self._load_json("cql_field_types.json")
        
        # Get all fields from the events dataset (most comprehensive)
        events_fields = self.get_fields("events")
        for field in events_fields.get("fields", []):
            field_name = field.get("name", "")
            field_type = field.get("type", "")
            
            # Categorize by field type
            if field_type == "ip_address":
                if field_name not in categories["ip_fields"]:
                    categories["ip_fields"].append(field_name)
            
            # Categorize by field name patterns
            if "Domain" in field_name and field_name not in categories["domain_fields"]:
                categories["domain_fields"].append(field_name)
            
            if "FileName" in field_name or field_name in ["ImageFileName", "ParentBaseFileName", "ContextBaseFileName"]:
                if field_name not in categories["process_name_fields"]:
                    categories["process_name_fields"].append(field_name)
            
            if "CommandLine" in field_name:
                if field_name not in categories["cmdline_fields"]:
                    categories["cmdline_fields"].append(field_name)
            
            if "FilePath" in field_name or "TargetFileName" in field_name:
                if field_name not in categories["file_name_fields"]:
                    categories["file_name_fields"].append(field_name)
            
            if "UserName" in field_name or "UID" in field_name:
                if field_name not in categories["username_fields"]:
                    categories["username_fields"].append(field_name)
            
            if "Port" in field_name and field_type in ["long", "integer"]:
                if field_name not in categories["port_fields"]:
                    categories["port_fields"].append(field_name)
            
            # Hash fields
            if "MD5" in field_name or field_name == "file_md5":
                if field_name not in categories["hash_fields"]["md5"]:
                    categories["hash_fields"]["md5"].append(field_name)
            
            if "SHA1" in field_name or field_name == "file_sha1":
                if field_name not in categories["hash_fields"]["sha1"]:
                    categories["hash_fields"]["sha1"].append(field_name)
            
            if "SHA256" in field_name or field_name == "file_sha256":
                if field_name not in categories["hash_fields"]["sha256"]:
                    categories["hash_fields"]["sha256"].append(field_name)
        
        # Ensure fallback values if schema loading fails
        if not categories["ip_fields"]:
            categories["ip_fields"] = ["RemoteAddressIP4", "LocalAddressIP4", "RemoteAddressIP6", "LocalAddressIP6", "aip"]
        
        if not categories["domain_fields"]:
            categories["domain_fields"] = ["DomainName", "DNSRequestDomain", "HttpHost"]
        
        if not categories["process_name_fields"]:
            categories["process_name_fields"] = ["FileName", "ImageFileName", "ParentBaseFileName", "ContextBaseFileName"]
        
        if not categories["cmdline_fields"]:
            categories["cmdline_fields"] = ["CommandLine", "ParentCommandLine"]
        
        if not categories["file_name_fields"]:
            categories["file_name_fields"] = ["TargetFileName", "FilePath", "FileName"]
        
        if not categories["username_fields"]:
            categories["username_fields"] = ["UserName", "EffectiveUserName", "SubjectUserName"]
        
        if not categories["port_fields"]:
            categories["port_fields"] = ["RemotePort", "LocalPort"]
        
        if not categories["hash_fields"]["md5"]:
            categories["hash_fields"]["md5"] = ["file_hash", "file_md5", "hash_md5", "MD5HashData"]
        
        if not categories["hash_fields"]["sha1"]:
            categories["hash_fields"]["sha1"] = ["file_hash", "file_sha1", "hash_sha1", "SHA1HashData"]
        
        if not categories["hash_fields"]["sha256"]:
            categories["hash_fields"]["sha256"] = ["file_hash", "file_sha256", "hash_sha256", "SHA256HashData"]
        
        logger.debug("Loaded field categories: %d IP fields, %d domain fields, %d process fields", 
                    len(categories["ip_fields"]), len(categories["domain_fields"]), len(categories["process_name_fields"]))
        
        return categories
