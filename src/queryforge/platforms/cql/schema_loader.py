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

    def __init__(self, schema_dir: Optional[Path] = None) -> None:
        """
        Initialize CQL schema loader.

        Parameters
        ----------
        schema_dir : Optional[Path]
            Directory containing CQL schema JSON files.
            Defaults to the cql platform directory.
        """
        if schema_dir is None:
            schema_dir = Path(__file__).parent
        self.schema_dir = Path(schema_dir)
        self._cache: Dict[str, Any] = {}

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
        return self._load_json("cql_core.json")

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
        field_types = self._load_json("cql_field_types.json")
        placeholder_fields = field_types.get("placeholder_fields", {})

        # Get fields for the specified dataset
        dataset_fields = placeholder_fields.get(dataset, {})

        if not dataset_fields:
            # If dataset not found, try using events as default
            dataset_fields = placeholder_fields.get("events", {})
            logger.info("Dataset '%s' not found, using 'events' fields as fallback", dataset)

        # Convert to list format with field metadata
        fields_list = []
        for field_name, field_meta in dataset_fields.items():
            field_entry = {
                "name": field_name,
                "type": field_meta.get("type", "string"),
                "description": field_meta.get("description", ""),
                "indexed": field_meta.get("indexed", False)
            }
            fields_list.append(field_entry)

        result = {
            "dataset": dataset,
            "fields": fields_list,
            "count": len(fields_list)
        }

        if query_intent:
            # RAG-enhanced filtering will be implemented when RAG is integrated
            result["query_intent"] = query_intent
            result["note"] = "Semantic filtering will be enabled when RAG integration is complete"

        return result

    def get_field_types(self) -> Dict[str, Any]:
        """Get field type definitions and compatible operators."""
        return self._load_json("cql_field_types.json")

    def get_operators(self) -> Dict[str, Any]:
        """Get operator definitions and normalization rules."""
        return self._load_json("cql_operators.json")

    def get_best_practices(self) -> List[Dict[str, Any]]:
        """Get query best practices."""
        data = self._load_json("cql_best_practices.json")
        return data.get("best_practices", [])

    def get_patterns(self) -> Dict[str, Any]:
        """Get comprehensive query patterns."""
        return self._load_json("cql_comprehensive_patterns.json")

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
        data = self._load_json("cql_examples.json")
        all_examples = data.get("examples", [])

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
        return self._load_json("cql_documentation.json")

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
        operators = operators_data.get("operators", {})

        operator_lower = operator.lower().strip()

        # Search through all operator definitions
        for op_name, op_def in operators.items():
            if isinstance(op_def, dict):
                variants = op_def.get("operators", [])
                if operator_lower in [v.lower() for v in variants]:
                    return op_def.get("normalized", operator)

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
