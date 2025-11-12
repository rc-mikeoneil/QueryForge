from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP

from queryforge.platforms.kql.query_builder import (
    build_kql_query,
    suggest_columns,
    example_queries_for_table,
)
from queryforge.platforms.kql.validator import KQLValidator
from queryforge.server.server_runtime import ServerRuntime

from queryforge.server.server_tools_shared import (
    attach_rag_context,
    get_rag_enhanced_examples,
    get_rag_enhanced_fields,
    get_rag_enhanced_datasets,
)

logger = logging.getLogger(__name__)


def register_kql_tools(mcp: FastMCP, runtime: ServerRuntime) -> None:
    """Register Microsoft 365 Defender KQL tooling."""

    @mcp.tool
    def kql_list_datasets(
        keyword: Optional[str] = None,
        query_intent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        List available Advanced Hunting datasets (optionally filter by keyword or semantic search).
        
        Args:
            keyword: Optional keyword to filter dataset names (simple text matching)
            query_intent: Optional natural language description to find semantically relevant datasets
                         (e.g., "process execution", "network activity", "file operations")
        
        Returns:
            Dictionary with datasets, either filtered/ranked or all datasets
        """

        schema = runtime.kql_cache.load_or_refresh()
        
        # Convert schema to format expected by RAG helper (dict with metadata)
        datasets_dict = {name: {"description": name} for name in schema.keys()}
        
        # If query_intent provided, use RAG-enhanced retrieval
        if query_intent:
            logger.info("Using RAG-enhanced dataset discovery for intent: %s", query_intent[:100])
            result = get_rag_enhanced_datasets(
                runtime=runtime,
                query_intent=query_intent,
                source_filter="kql",
                all_datasets=datasets_dict,
                k=10,
            )
            # Convert back to list format
            if "datasets" in result and isinstance(result["datasets"], dict):
                result["datasets"] = sorted(result["datasets"].keys())
            return result
        
        # Legacy keyword filtering
        names = list(schema.keys())
        if keyword:
            kw = keyword.lower()
            names = [name for name in names if kw in name.lower()]
        logger.info("Found %d KQL datasets matching filter", len(names))
        return {"datasets": sorted(names)}

    @mcp.tool
    def kql_get_fields(
        dataset: str,
        query_intent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Return fields (columns) and docs URL for a given dataset.
        
        Args:
            dataset: KQL table name (e.g., 'DeviceProcessEvents', 'DeviceNetworkEvents')
            query_intent: Optional natural language description to filter semantically relevant fields
                         (e.g., "network fields", "process execution fields", "file operations")
        
        Returns:
            Dictionary with fields, either semantically filtered or all fields
        """

        schema = runtime.kql_cache.load_or_refresh()
        if dataset not in schema:
            try:
                from rapidfuzz import process

                choice, score, _ = process.extractOne(dataset, schema.keys())
                logger.warning(
                    "KQL dataset '%s' not found, suggesting '%s' with score %s",
                    dataset,
                    choice,
                    score,
                )
                return {"error": f"Unknown dataset '{dataset}'. Did you mean '{choice}' (score {score})?"}
            except ImportError:
                logger.error("rapidfuzz not available for fuzzy matching")
                return {"error": f"Unknown dataset '{dataset}'"}

        fields = schema[dataset]["columns"]
        
        # If query_intent provided, use RAG-enhanced field filtering
        if query_intent:
            logger.info("Using RAG-enhanced field filtering for intent: %s", query_intent[:100])
            result = get_rag_enhanced_fields(
                runtime=runtime,
                query_intent=query_intent,
                source_filter="kql",
                all_fields=fields,
                dataset_name=dataset,
                k=20,
            )
            # Add dataset info to result
            result["dataset"] = dataset
            result["url"] = schema[dataset]["url"]
            return result
        
        logger.info(
            "Retrieved fields for KQL dataset '%s' with %d columns",
            dataset,
            len(fields),
        )
        return {
            "dataset": dataset,
            "fields": fields,
            "url": schema[dataset]["url"],
        }

    @mcp.tool
    def kql_suggest_fields(
        dataset: str,
        keyword: Optional[str] = None,
        query_intent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Suggest fields (columns) for a dataset, optionally filtered by keyword or semantic search.
        
        Args:
            dataset: KQL table name
            keyword: Optional keyword to filter field names (simple text matching)
            query_intent: Optional natural language description for semantic field suggestions
                         (e.g., "network-related fields", "time-related fields")
        
        Returns:
            Dictionary with field suggestions
        """

        schema = runtime.kql_cache.load_or_refresh()
        
        # If query_intent provided, use RAG-enhanced field filtering (similar to get_fields)
        if query_intent:
            if dataset not in schema:
                return {"error": f"Unknown dataset '{dataset}'"}
            
            fields = schema[dataset]["columns"]
            logger.info("Using RAG-enhanced field suggestions for intent: %s", query_intent[:100])
            result = get_rag_enhanced_fields(
                runtime=runtime,
                query_intent=query_intent,
                source_filter="kql",
                all_fields=fields,
                dataset_name=dataset,
                k=20,
            )
            # Rename 'fields' to 'suggestions' for consistency with original API
            if "fields" in result:
                result["suggestions"] = result.pop("fields")
            return result
        
        # Legacy keyword-based suggestions
        suggestions = suggest_columns(schema, dataset, keyword)
        logger.info(
            "Found %d KQL field suggestions for dataset '%s'",
            len(suggestions),
            dataset,
        )
        return {"suggestions": suggestions}

    @mcp.tool
    def kql_get_examples(
        dataset: Optional[str] = None,
        query_intent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Return example KQL queries, optionally filtered by dataset or semantic search.

        Args:
            dataset: Optional dataset to generate examples for (e.g., 'DeviceProcessEvents')
            query_intent: Optional natural language description to find semantically relevant examples
                         (e.g., "find PowerShell execution", "detect network connections")

        Returns:
            Dictionary with examples, either:
            - Generated for specific dataset if dataset provided
            - Semantically relevant if query_intent provided (uses RAG)
            - Error if neither provided
        """

        schema = runtime.kql_cache.load_or_refresh()
        
        # If query_intent provided, use RAG-enhanced retrieval
        if query_intent:
            logger.info("Using RAG-enhanced example retrieval for intent: %s", query_intent[:100])
            # Use empty fallback since KQL examples are generated, not stored
            return get_rag_enhanced_examples(
                runtime=runtime,
                query_intent=query_intent,
                source_filter="kql",
                fallback_examples={},
                k=10,
            )
        
        # Legacy behavior: generate examples for specific dataset
        if dataset:
            examples = example_queries_for_table(schema, dataset)
            logger.info("Generated %d KQL examples for dataset '%s'", len(examples), dataset)
            return {"examples": examples}
        
        # Error if neither provided
        return {"error": "Must provide either 'dataset' or 'query_intent' parameter"}

    @mcp.tool
    def kql_build_query(
        dataset: Optional[str] = None,
        select: Optional[List[str]] = None,
        where: Optional[List[str]] = None,
        time_window: Optional[str] = None,
        summarize: Optional[str] = None,
        order_by: Optional[str] = None,
        limit: Optional[int] = None,
        natural_language_intent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build a KQL query from structured params or natural-language intent.

        RECOMMENDED WORKFLOW:
            1. Call kql_build_query to generate the initial query
            2. Call kql_validate_query on the generated query (kql field) and metadata (meta field)
            3. If validation fails (valid=False):
               - Review error messages and suggestions in validation_results
               - Adjust parameters based on feedback (e.g., fix column names, datasets)
               - Call kql_build_query again with corrected parameters
               - Repeat validation until valid=True
            4. Present the validated query to the user

            Always validate queries before presenting them as final results.
            Validation is a REQUIRED step, not optional.
        """

        schema = runtime.kql_cache.load_or_refresh()
        payload = {
            "table": dataset,  # Internal builder still uses 'table' parameter
            "select": select,
            "where": where,
            "time_window": time_window,
            "summarize": summarize,
            "order_by": order_by,
            "limit": limit,
            "natural_language_intent": natural_language_intent,
        }
        try:
            kql, meta = build_kql_query(schema=schema, **payload)

            intent = payload.get("natural_language_intent")
            meta = attach_rag_context(
                runtime=runtime,
                intent=intent,
                metadata=meta,
                source_filter="kql",
                provider_label="KQL",
                logger=logger,
            )

            logger.info(
                "Successfully built KQL query for dataset '%s'",
                meta.get("table", "unknown"),
            )
            return {"kql": kql, "meta": meta}
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to build KQL query: %s", exc)
            raise

    @mcp.tool
    def kql_validate_query(
        query: str,
        dataset: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate a KQL query for syntax, schema compliance, and best practices.

        Args:
            query: The KQL query string to validate
            dataset: Optional dataset name (for schema validation)
            metadata: Optional metadata from query building (enhances validation)

        Returns:
            Validation results with detailed feedback on errors, warnings, and suggestions

        IMPORTANT - Validation Failure Workflow:
            When valid=False (validation fails):
            1. Review ALL errors in validation_results for specific issues
            2. Use the 'suggestion' field from each error to understand fixes
            3. Call kql_build_query again with corrections based on suggestions
            4. Validate the corrected query with kql_validate_query
            5. Repeat steps 1-4 until valid=True

            Common fixes:
            - Field errors: Use suggested column names from error messages
            - Syntax errors: Follow suggestion text to fix KQL syntax issues
            - Schema errors: Adjust dataset (table) or column names as suggested
            - Operator errors: Use valid KQL operators for the field type

            You MUST attempt to fix validation errors before presenting queries to users.
            Do not present invalid queries as final results.
        """
        try:
            schema = runtime.kql_cache.load_or_refresh()
            validator = KQLValidator(schema)

            # Prepare metadata for validation
            if metadata is None:
                metadata = {}

            # If dataset provided but not in metadata, add it (validator expects 'table' key)
            if dataset and "table" not in metadata:
                metadata["table"] = dataset

            # Run validation
            result = validator.validate(query, metadata)

            logger.info(
                "Validated KQL query: valid=%s, errors=%d, warnings=%d",
                result["valid"],
                sum(len(cat["errors"]) for cat in result["validation_results"].values()),
                sum(len(cat["warnings"]) for cat in result["validation_results"].values())
            )

            return result
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to validate KQL query: %s", exc)
            return {"error": str(exc)}

    @mcp.tool
    def kql_build_query_validated(
        dataset: Optional[str] = None,
        select: Optional[List[str]] = None,
        where: Optional[List[str]] = None,
        time_window: Optional[str] = None,
        summarize: Optional[str] = None,
        order_by: Optional[str] = None,
        limit: Optional[int] = None,
        natural_language_intent: Optional[str] = None,
        max_retries: int = 3,
    ) -> Dict[str, Any]:
        """
        Build and validate a KQL query in a single optimized operation.

        This tool combines query building and validation with automatic retry logic,
        eliminating multiple round-trips and significantly improving performance.

        PERFORMANCE OPTIMIZATION:
            - Single API call instead of separate build + validate calls
            - Automatic error correction and retry (no LLM reasoning delay)
            - 10x faster for queries requiring corrections
            - Recommended for all query generation workflows

        Args:
            dataset: KQL table name (e.g., 'DeviceProcessEvents', 'DeviceNetworkEvents')
            select: List of columns to project
            where: List of filter conditions
            time_window: Time range filter (e.g., '7d', '24h')
            summarize: Aggregation expression
            order_by: Sort expression
            limit: Maximum number of results
            natural_language_intent: Natural language description for RAG enhancement
            max_retries: Maximum validation retry attempts (default 3)

        Returns:
            {
                "kql": "validated KQL query string",
                "meta": {...},
                "validation": {
                    "valid": True/False,
                    "validation_results": {...}
                },
                "retry_count": 0-3,
                "corrections_applied": [...]
            }
        """
        try:
            schema = runtime.kql_cache.load_or_refresh()
            validator = KQLValidator(schema)

            corrections_applied = []
            retry_count = 0

            payload = {
                "table": dataset,
                "select": select,
                "where": where,
                "time_window": time_window,
                "summarize": summarize,
                "order_by": order_by,
                "limit": limit,
                "natural_language_intent": natural_language_intent,
            }

            # Build initial query
            kql, meta = build_kql_query(schema=schema, **payload)

            # Attach RAG context metadata
            intent = payload.get("natural_language_intent")
            meta = attach_rag_context(
                runtime=runtime,
                intent=intent,
                metadata=meta,
                source_filter="kql",
                provider_label="KQL",
                logger=logger,
            )

            # Validate and retry loop
            while retry_count <= max_retries:
                # Prepare metadata for validation
                validation_metadata = meta.copy()
                if dataset and "table" not in validation_metadata:
                    validation_metadata["table"] = dataset

                # Run validation
                validation = validator.validate(kql, validation_metadata)

                logger.info(
                    "KQL query validation (attempt %d/%d): valid=%s, errors=%d",
                    retry_count + 1,
                    max_retries + 1,
                    validation["valid"],
                    sum(len(cat["errors"]) for cat in validation["validation_results"].values())
                )

                # If valid or max retries reached, return result
                if validation["valid"] or retry_count >= max_retries:
                    return {
                        "kql": kql,
                        "meta": meta,
                        "validation": validation,
                        "retry_count": retry_count,
                        "corrections_applied": corrections_applied,
                    }

                # Extract corrections from validation errors
                correction_hints = _extract_kql_corrections(validation)
                if not correction_hints:
                    # No actionable corrections found, return as-is
                    logger.warning("No actionable corrections found in validation errors")
                    return {
                        "kql": kql,
                        "meta": meta,
                        "validation": validation,
                        "retry_count": retry_count,
                        "corrections_applied": corrections_applied,
                    }

                # Apply corrections and rebuild
                corrections_applied.append(correction_hints)
                retry_count += 1

                # Rebuild query with corrections
                corrected_payload = payload.copy()
                if "suggested_dataset" in correction_hints:
                    corrected_payload["table"] = correction_hints["suggested_dataset"]
                if "field_corrections" in correction_hints:
                    # Apply field corrections to select and where clauses
                    if select:
                        corrected_payload["select"] = _apply_kql_field_corrections_list(
                            select,
                            correction_hints["field_corrections"]
                        )
                    if where:
                        corrected_payload["where"] = _apply_kql_field_corrections_list(
                            where,
                            correction_hints["field_corrections"]
                        )

                kql, meta = build_kql_query(schema=schema, **corrected_payload)
                meta = attach_rag_context(
                    runtime=runtime,
                    intent=intent,
                    metadata=meta,
                    source_filter="kql",
                    provider_label="KQL",
                    logger=logger,
                )

            # Should never reach here, but return final state if we do
            return {
                "kql": kql,
                "meta": meta,
                "validation": validation,
                "retry_count": retry_count,
                "corrections_applied": corrections_applied,
            }

        except Exception as exc:
            logger.error("Failed to build and validate KQL query: %s", exc)
            return {"error": str(exc)}


def _extract_kql_corrections(validation: Dict[str, Any]) -> Dict[str, Any]:
    """Extract actionable corrections from KQL validation errors."""
    corrections = {}
    field_corrections = {}

    # Iterate through validation results to find suggestions
    for category, results in validation.get("validation_results", {}).items():
        for error in results.get("errors", []):
            suggestion = error.get("suggestion", "")
            message = error.get("message", "")

            # Extract field name suggestions
            if "Did you mean:" in suggestion or "Did you mean:" in message:
                # Parse "Column 'X' not found. Did you mean: Y?"
                match = re.search(r"(?:Field|Column) ['\"]([^'\"]+)['\"].*Did you mean:?\s*([^\s?,]+)",
                                message + " " + suggestion)
                if match:
                    wrong_field = match.group(1)
                    correct_field = match.group(2)
                    field_corrections[wrong_field] = correct_field

            # Extract dataset suggestions
            if "table" in message.lower() or "dataset" in message.lower():
                match = re.search(r"use ['\"]([^'\"]+)['\"]", suggestion, re.IGNORECASE)
                if match:
                    corrections["suggested_dataset"] = match.group(1)

    if field_corrections:
        corrections["field_corrections"] = field_corrections

    return corrections


def _apply_kql_field_corrections_list(
    items: List[str],
    corrections: Dict[str, str]
) -> List[str]:
    """Apply field name corrections to a list of KQL expressions."""
    corrected_items = []
    for item in items:
        corrected_item = item
        for wrong_field, correct_field in corrections.items():
            # Replace field names in KQL expressions (handle column references)
            corrected_item = re.sub(
                r'\b' + re.escape(wrong_field) + r'\b',
                correct_field,
                corrected_item
            )
        corrected_items.append(corrected_item)
    return corrected_items
