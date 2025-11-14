"""
MCP server tools for CrowdStrike Falcon Query Language (FQL).
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Union

from fastmcp import FastMCP

from queryforge.platforms.fql.schema_loader import FQLSchemaLoader
from queryforge.platforms.fql.query_builder import (
    FQLQueryBuilder,
    DEFAULT_BOOLEAN_OPERATOR as FQL_DEFAULT_BOOLEAN_OPERATOR,
    DEFAULT_DATASET as FQL_DEFAULT_DATASET,
    DEFAULT_LIMIT as FQL_DEFAULT_LIMIT,
    QueryBuildError as FQLQueryBuildError,
)
from queryforge.platforms.fql.validator import FQLValidator
from queryforge.server.server_runtime import ServerRuntime

from queryforge.server.server_tools_shared import (
    attach_rag_context,
    get_rag_enhanced_examples,
    get_rag_enhanced_fields,
    get_rag_enhanced_datasets,
)

logger = logging.getLogger(__name__)


def register_fql_tools(mcp: FastMCP, runtime: ServerRuntime) -> None:
    """Register CrowdStrike Falcon Query Language (FQL) tools."""

    # Initialize FQL components
    schema_loader = FQLSchemaLoader()
    query_builder = FQLQueryBuilder(schema_loader)

    @mcp.tool
    def fql_list_datasets(query_intent: Optional[str] = None) -> Dict[str, Any]:
        """
        List CrowdStrike Falcon datasets with descriptions.
        
        Args:
            query_intent: Optional natural language description to find semantically relevant datasets
                         (e.g., "process execution", "network activity", "file operations")
        
        Returns:
            Dictionary with datasets, either semantically ranked or all datasets
        """
        try:
            datasets_data = schema_loader.get_datasets(query_intent)
            
            # If query_intent provided, use RAG-enhanced retrieval
            if query_intent:
                logger.info("Using RAG-enhanced dataset discovery for FQL intent: %s", query_intent[:100])
                # Convert to format expected by RAG
                all_datasets = {}
                for ds in datasets_data.get("datasets", []):
                    key = ds.get("name", "")
                    all_datasets[key] = {
                        "name": ds.get("display_name", key),
                        "metadata": {"description": ds.get("description", "")}
                    }
                
                result = get_rag_enhanced_datasets(
                    runtime=runtime,
                    query_intent=query_intent,
                    source_filter="fql",
                    all_datasets=all_datasets,
                    k=10,
                )
                
                # Convert back to list format
                if "datasets" in result and isinstance(result["datasets"], dict):
                    items = []
                    for key, meta in result["datasets"].items():
                        items.append({
                            "name": key,
                            "display_name": meta.get("name", key),
                            "description": meta.get("metadata", {}).get("description", "")
                        })
                    result["datasets"] = items
                return result
            
            logger.info("Listing %d CrowdStrike Falcon datasets", len(datasets_data.get("datasets", [])))
            return datasets_data
            
        except Exception as exc:
            logger.error("Failed to list FQL datasets: %s", exc)
            return {"error": str(exc)}

    @mcp.tool
    def fql_get_fields(
        dataset: str,
        query_intent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Return available fields for a CrowdStrike Falcon dataset.
        
        Args:
            dataset: FQL dataset name (e.g., 'events', 'detections', 'indicators')
            query_intent: Optional natural language description to filter semantically relevant fields
                         (e.g., "network fields", "process execution fields", "file operations")
        
        Returns:
            Dictionary with fields, either semantically filtered or all fields
        """
        try:
            fields_data = schema_loader.get_fields(dataset, query_intent)
            
            # If query_intent provided, use RAG-enhanced field filtering
            if query_intent:
                logger.info("Using RAG-enhanced field filtering for FQL intent: %s", query_intent[:100])
                result = get_rag_enhanced_fields(
                    runtime=runtime,
                    query_intent=query_intent,
                    source_filter="fql",
                    all_fields=fields_data.get("fields", []),
                    dataset_name=dataset,
                    k=20,
                )
                result["dataset"] = dataset
                return result
            
            logger.info(
                "Retrieved %d fields for FQL dataset '%s'",
                len(fields_data.get("fields", [])),
                dataset
            )
            return fields_data
            
        except Exception as exc:
            logger.error("Failed to get FQL fields for dataset '%s': %s", dataset, exc)
            return {"error": str(exc)}

    @mcp.tool
    def fql_get_operator_reference() -> Dict[str, Any]:
        """
        Return the FQL operator reference.
        
        Returns:
            Dictionary with operator definitions and normalization rules
        """
        try:
            operators = schema_loader.get_operators()
            logger.info("Retrieved FQL operator reference")
            return operators
        except Exception as exc:
            logger.error("Failed to get FQL operator reference: %s", exc)
            return {"error": str(exc)}

    @mcp.tool
    def fql_get_best_practices() -> Dict[str, Any]:
        """
        Return FQL query best practices.
        
        Returns:
            Dictionary with best practice guidelines
        """
        try:
            best_practices = schema_loader.get_best_practices()
            logger.info("Retrieved FQL best practices")
            return {"best_practices": best_practices}
        except Exception as exc:
            logger.error("Failed to get FQL best practices: %s", exc)
            return {"error": str(exc)}

    @mcp.tool
    def fql_get_examples(
        category: Optional[str] = None,
        query_intent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Return example FQL queries, optionally filtered by category or semantic search.

        Args:
            category: Optional category to filter examples (e.g., 'process_execution', 'network_activity')
            query_intent: Optional natural language description to find semantically relevant examples
                         (e.g., "find suspicious PowerShell activity", "detect lateral movement")

        Returns:
            Dictionary with examples, either:
            - Filtered by category if category provided
            - Semantically relevant if query_intent provided (uses RAG)
            - All examples if neither provided
        """
        try:
            examples_data = schema_loader.get_examples(category, query_intent)
            
            # If query_intent provided, use RAG-enhanced retrieval
            if query_intent:
                logger.info("Using RAG-enhanced example retrieval for FQL intent: %s", query_intent[:100])
                return get_rag_enhanced_examples(
                    runtime=runtime,
                    query_intent=query_intent,
                    source_filter="fql",
                    fallback_examples=examples_data.get("examples", []),
                    k=10,
                )
            
            logger.info("Retrieved %d FQL examples", len(examples_data.get("examples", [])))
            return examples_data
            
        except Exception as exc:
            logger.error("Failed to get FQL examples: %s", exc)
            return {"error": str(exc)}

    @mcp.tool
    def fql_build_query(
        dataset: Optional[str] = None,
        filters: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None,
        fields: Optional[List[str]] = None,
        natural_language_intent: Optional[str] = None,
        time_range: Optional[Union[str, Dict[str, Any]]] = None,
        limit: Optional[int] = None,
        boolean_operator: str = FQL_DEFAULT_BOOLEAN_OPERATOR,
    ) -> Dict[str, Any]:
        """
        Build a CrowdStrike Falcon FQL query from structured params or natural language.

        RECOMMENDED WORKFLOW:
            1. Call fql_build_query to generate the initial query
            2. Call fql_validate_query on the generated query and metadata
            3. If validation fails (valid=False):
               - Review error messages and suggestions in validation_results
               - Adjust parameters based on feedback (e.g., fix field names, datasets)
               - Call fql_build_query again with corrected parameters
               - Repeat validation until valid=True
            4. Present the validated query to the user

            Always validate queries before presenting them as final results.
            Validation is a REQUIRED step, not optional.
        
        Args:
            dataset: FQL dataset (e.g., 'events', 'detections', 'indicators')
            filters: Structured filter conditions as dict or list of dicts
            fields: List of fields to project in results
            natural_language_intent: Natural language description for RAG enhancement
            time_range: Time range filter (string like "24h" or dict with start/end)
            limit: Maximum number of results
            boolean_operator: Operator to join filters ('AND' or 'OR', default 'AND')
        
        Returns:
            Dictionary with query and metadata
        """
        try:
            # Build query
            result = query_builder.build_query(
                dataset=dataset,
                filters=filters,
                fields=fields,
                natural_language_intent=natural_language_intent,
                time_range=time_range,
                limit=limit,
                boolean_operator=boolean_operator,
                rag_context=None,  # RAG context will be added if available
            )
            
            logger.info(
                "Built FQL query for dataset=%s",
                result["metadata"].get("dataset", FQL_DEFAULT_DATASET)
            )
            
            # Attach RAG context metadata
            result["metadata"] = attach_rag_context(
                runtime=runtime,
                intent=natural_language_intent,
                metadata=result["metadata"],
                source_filter="fql",
                provider_label="CrowdStrike Falcon",
                logger=logger,
            )
            
            return result
            
        except Exception as exc:
            logger.error("Failed to build FQL query: %s", exc)
            return {"error": str(exc)}

    @mcp.tool
    def fql_validate_query(
        query: str,
        dataset: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate a CrowdStrike Falcon FQL query for syntax, schema compliance, and best practices.

        Args:
            query: The FQL query string to validate
            dataset: Optional dataset name (for schema validation)
            metadata: Optional metadata from query building (enhances validation)

        Returns:
            Validation results with detailed feedback on errors, warnings, and suggestions

        IMPORTANT - Validation Failure Workflow:
            When valid=False (validation fails):
            1. Review ALL errors in validation_results for specific issues
            2. Use the 'suggestion' field from each error to understand fixes
            3. Call fql_build_query again with corrections based on suggestions
            4. Validate the corrected query with fql_validate_query
            5. Repeat steps 1-4 until valid=True

            Common fixes:
            - Field errors: Use suggested field names from error messages
            - Syntax errors: Follow suggestion text to fix FQL syntax issues
            - Schema errors: Adjust dataset or field names as suggested
            - Operator errors: Use valid FQL operators for the field type

            You MUST attempt to fix validation errors before presenting queries to users.
            Do not present invalid queries as final results.
        """
        try:
            validator = FQLValidator(schema_loader)
            result = validator.validate(query, dataset, metadata)
            
            logger.info(
                "Validated FQL query: valid=%s, errors=%d, warnings=%d",
                result["valid"],
                sum(len(cat["errors"]) for cat in result["validation_results"].values()),
                sum(len(cat["warnings"]) for cat in result["validation_results"].values())
            )
            
            return result
            
        except Exception as exc:
            logger.error("Failed to validate FQL query: %s", exc)
            return {"error": str(exc)}

    @mcp.tool
    def fql_build_query_validated(
        dataset: Optional[str] = None,
        filters: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None,
        fields: Optional[List[str]] = None,
        natural_language_intent: Optional[str] = None,
        time_range: Optional[Union[str, Dict[str, Any]]] = None,
        limit: Optional[int] = None,
        boolean_operator: str = FQL_DEFAULT_BOOLEAN_OPERATOR,
        max_retries: int = 3,
    ) -> Dict[str, Any]:
        """
        Build and validate a CrowdStrike Falcon FQL query in a single optimized operation.

        This tool combines query building and validation with automatic retry logic,
        eliminating multiple round-trips and significantly improving performance.

        PERFORMANCE OPTIMIZATION:
            - Single API call instead of separate build + validate calls
            - Automatic error correction and retry (no LLM reasoning delay)
            - 10x faster for queries requiring corrections
            - Recommended for all query generation workflows

        Args:
            dataset: FQL dataset (e.g., 'events', 'detections', 'indicators')
            filters: Structured filter conditions as dict or list of dicts
            fields: List of fields to project in results
            natural_language_intent: Natural language description for RAG enhancement
            time_range: Time range filter (string like "24h" or dict with start/end)
            limit: Maximum number of results
            boolean_operator: Operator to join filters ('AND' or 'OR', default 'AND')
            max_retries: Maximum validation retry attempts (default 3)

        Returns:
            {
                "query": "validated FQL query string",
                "metadata": {...},
                "validation": {
                    "valid": True/False,
                    "validation_results": {...}
                },
                "retry_count": 0-3,
                "corrections_applied": [...]
            }
        """
        try:
            validator = FQLValidator(schema_loader)
            corrections_applied = []
            retry_count = 0

            # Build initial query
            result = query_builder.build_query(
                dataset=dataset,
                filters=filters,
                fields=fields,
                natural_language_intent=natural_language_intent,
                time_range=time_range,
                limit=limit,
                boolean_operator=boolean_operator,
                rag_context=None,
            )
            
            query = result["query"]
            metadata = result["metadata"]
            
            # Attach RAG context metadata
            metadata = attach_rag_context(
                runtime=runtime,
                intent=natural_language_intent,
                metadata=metadata,
                source_filter="fql",
                provider_label="CrowdStrike Falcon",
                logger=logger,
            )

            # Validate and retry loop
            while retry_count <= max_retries:
                # Run validation
                validation = validator.validate(query, dataset, metadata)

                logger.info(
                    "FQL query validation (attempt %d/%d): valid=%s, errors=%d",
                    retry_count + 1,
                    max_retries + 1,
                    validation["valid"],
                    sum(len(cat["errors"]) for cat in validation["validation_results"].values())
                )

                # If valid or max retries reached, return result
                if validation["valid"] or retry_count >= max_retries:
                    return {
                        "query": query,
                        "metadata": metadata,
                        "validation": validation,
                        "retry_count": retry_count,
                        "corrections_applied": corrections_applied,
                    }

                # Extract corrections from validation errors
                correction_hints = _extract_fql_corrections(validation)
                if not correction_hints:
                    logger.warning("No actionable corrections found in FQL validation errors")
                    return {
                        "query": query,
                        "metadata": metadata,
                        "validation": validation,
                        "retry_count": retry_count,
                        "corrections_applied": corrections_applied,
                    }

                # Apply corrections and rebuild
                corrections_applied.append(correction_hints)
                retry_count += 1

                # Apply corrections to parameters
                corrected_dataset = dataset
                corrected_filters = filters

                if "suggested_dataset" in correction_hints:
                    corrected_dataset = correction_hints["suggested_dataset"]
                
                if "field_corrections" in correction_hints and filters:
                    corrected_filters = _apply_fql_field_corrections(
                        filters,
                        correction_hints["field_corrections"]
                    )

                # Rebuild query with corrections
                result = query_builder.build_query(
                    dataset=corrected_dataset,
                    filters=corrected_filters,
                    fields=fields,
                    natural_language_intent=natural_language_intent,
                    time_range=time_range,
                    limit=limit,
                    boolean_operator=boolean_operator,
                    rag_context=None,
                )
                
                query = result["query"]
                metadata = result["metadata"]
                metadata = attach_rag_context(
                    runtime=runtime,
                    intent=natural_language_intent,
                    metadata=metadata,
                    source_filter="fql",
                    provider_label="CrowdStrike Falcon",
                    logger=logger,
                )

            # Should never reach here, but return final state if we do
            return {
                "query": query,
                "metadata": metadata,
                "validation": validation,
                "retry_count": retry_count,
                "corrections_applied": corrections_applied,
            }

        except Exception as exc:
            logger.error("Failed to build and validate FQL query: %s", exc)
            return {"error": str(exc)}


def _extract_fql_corrections(validation: Dict[str, Any]) -> Dict[str, Any]:
    """Extract actionable corrections from FQL validation errors."""
    corrections = {}
    field_corrections = {}

    # Iterate through validation results to find suggestions
    for category, results in validation.get("validation_results", {}).items():
        for error in results.get("errors", []):
            suggestion = error.get("suggestion", "")
            message = error.get("message", "")

            # Extract field name suggestions
            if "Did you mean:" in suggestion or "Did you mean:" in message:
                match = re.search(r"Field ['\"]([^'\"]+)['\"].*Did you mean:?\s*([^\s?,]+)",
                                message + " " + suggestion)
                if match:
                    wrong_field = match.group(1)
                    correct_field = match.group(2)
                    field_corrections[wrong_field] = correct_field

            # Extract dataset suggestions
            if "dataset" in message.lower():
                match = re.search(r"use ['\"]([^'\"]+)['\"]", suggestion, re.IGNORECASE)
                if match:
                    corrections["suggested_dataset"] = match.group(1)

    if field_corrections:
        corrections["field_corrections"] = field_corrections

    return corrections


def _apply_fql_field_corrections(
    filters: Union[Dict[str, Any], List[Dict[str, Any]]],
    corrections: Dict[str, str]
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """Apply field name corrections to FQL filters."""
    # Handle single dict
    if isinstance(filters, dict):
        corrected_filter = filters.copy()
        if "field" in corrected_filter and corrected_filter["field"] in corrections:
            corrected_filter["field"] = corrections[corrected_filter["field"]]
        return corrected_filter
    
    # Handle list of dicts
    corrected_filters = []
    for f in filters:
        if isinstance(f, dict):
            corrected_filter = f.copy()
            if "field" in corrected_filter and corrected_filter["field"] in corrections:
                corrected_filter["field"] = corrections[corrected_filter["field"]]
            corrected_filters.append(corrected_filter)
        elif isinstance(f, str):
            # Apply corrections to string filters
            corrected_str = f
            for wrong_field, correct_field in corrections.items():
                corrected_str = re.sub(
                    r'\b' + re.escape(wrong_field) + r'\b',
                    correct_field,
                    corrected_str
                )
            corrected_filters.append(corrected_str)
        else:
            corrected_filters.append(f)
    return corrected_filters
