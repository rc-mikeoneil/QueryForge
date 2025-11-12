from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP

from queryforge.platforms.cbc.query_builder import (
    DEFAULT_BOOLEAN_OPERATOR,
    build_cbc_query,
)
from queryforge.platforms.cbc.schema_loader import normalise_search_type
from queryforge.platforms.cbc.validator import CBCValidator
from queryforge.server.server_runtime import ServerRuntime

from queryforge.server.server_tools_shared import (
    attach_rag_context,
    get_rag_enhanced_examples,
    get_rag_enhanced_fields,
    get_rag_enhanced_datasets,
)

logger = logging.getLogger(__name__)


def register_cbc_tools(mcp: FastMCP, runtime: ServerRuntime) -> None:
    """Register Carbon Black Cloud tooling with the MCP runtime."""

    @mcp.tool
    def cbc_list_datasets(query_intent: Optional[str] = None) -> Dict[str, Any]:
        """
        List Carbon Black Cloud datasets (search types) with their descriptions.
        
        Args:
            query_intent: Optional natural language description to find semantically relevant datasets
                         (e.g., "process execution", "network activity", "file operations")
        
        Returns:
            Dictionary with datasets, either semantically ranked or all datasets
        """

        schema = runtime.cbc_cache.load()
        search_types = schema.get("search_types", {})
        
        # If query_intent provided, use RAG-enhanced retrieval
        if query_intent:
            logger.info("Using RAG-enhanced dataset discovery for intent: %s", query_intent[:100])
            return get_rag_enhanced_datasets(
                runtime=runtime,
                query_intent=query_intent,
                source_filter="cbc",
                all_datasets=search_types,
                k=10,
            )
        
        logger.info("Listing %d CBC datasets", len(search_types))
        return {"datasets": search_types}

    @mcp.tool
    def cbc_get_fields(
        search_type: str,
        query_intent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Return available fields for a given search type.
        
        Args:
            search_type: CBC search type (e.g., 'process_search', 'binary_search')
            query_intent: Optional natural language description to filter semantically relevant fields
                         (e.g., "network fields", "process execution fields", "file modification")
        
        Returns:
            Dictionary with fields, either semantically filtered or all fields
        """

        schema = runtime.cbc_cache.load()
        search_type_normalised, log_entries = normalise_search_type(
            search_type,
            schema.get("search_types", {}).keys(),
        )
        fields = runtime.cbc_cache.list_fields(search_type_normalised)
        
        # If query_intent provided, use RAG-enhanced field filtering
        if query_intent:
            logger.info("Using RAG-enhanced field filtering for intent: %s", query_intent[:100])
            result = get_rag_enhanced_fields(
                runtime=runtime,
                query_intent=query_intent,
                source_filter="cbc",
                all_fields=fields,
                dataset_name=search_type_normalised,
                k=20,
            )
            # Add normalisation info to result
            result["search_type"] = search_type_normalised
            result["normalisation"] = log_entries
            return result
        
        logger.info(
            "Resolved CBC search type %s (%s) with %d fields",
            search_type,
            search_type_normalised,
            len(fields),
        )
        return {
            "search_type": search_type_normalised,
            "fields": fields,
            "normalisation": log_entries,
        }

    @mcp.tool
    def cbc_get_operator_reference() -> Dict[str, Any]:
        """Return the logical, wildcard, and field operator reference."""

        operators = runtime.cbc_cache.operator_reference()
        logger.info("Returning CBC operator reference with categories: %s", list(operators.keys()))
        return {"operators": operators}

    @mcp.tool
    def cbc_get_best_practices() -> Dict[str, Any]:
        """Return documented query-building best practices."""

        best = runtime.cbc_cache.best_practices()
        logger.info(
            "Returning %s best practice entries",
            len(best) if isinstance(best, list) else "structured",
        )
        return {"best_practices": best}

    @mcp.tool
    def cbc_get_examples(
        category: Optional[str] = None,
        query_intent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Return example queries, optionally filtered by category or semantic search.

        Args:
            category: Optional category to filter examples (e.g., 'process_search', 'binary_search')
            query_intent: Optional natural language description to find semantically relevant examples
                         (e.g., "find processes with network connections", "detect lateral movement")

        Returns:
            Dictionary with examples, either:
            - Filtered by category if category provided
            - Semantically relevant if query_intent provided (uses RAG)
            - All examples if neither provided

        Examples:
            # Get all examples
            cbc_get_examples()

            # Get examples for specific category
            cbc_get_examples(category="process_search")

            # Get semantically relevant examples (RAG-powered)
            cbc_get_examples(query_intent="find suspicious PowerShell activity")
        """

        examples = runtime.cbc_cache.example_queries()
        
        # If query_intent provided, use RAG-enhanced retrieval
        if query_intent:
            logger.info("Using RAG-enhanced example retrieval for intent: %s", query_intent[:100])
            return get_rag_enhanced_examples(
                runtime=runtime,
                query_intent=query_intent,
                source_filter="cbc",
                fallback_examples=examples,
                k=10,
            )
        
        # Legacy behavior: filter by category
        if category:
            key = category
            if key not in examples:
                available = ", ".join(sorted(examples.keys()))
                logger.warning("Unknown CBC example category %s", key)
                return {"error": f"Unknown category '{key}'. Available: {available}"}
            return {"category": key, "examples": examples[key]}
        
        # Return all examples
        return {"examples": examples}

    @mcp.tool
    def cbc_build_query(
        dataset: Optional[str] = None,
        terms: Optional[List[str]] = None,
        natural_language_intent: Optional[str] = None,
        boolean_operator: str = DEFAULT_BOOLEAN_OPERATOR,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Build a Carbon Black Cloud query from structured parameters or natural language.

        RECOMMENDED WORKFLOW:
            1. Call cbc_build_query to generate the initial query
            2. Call cbc_validate_query on the generated query and metadata
            3. If validation fails (valid=False):
               - Review error messages and suggestions in validation_results
               - Adjust parameters based on feedback (e.g., fix field names, search types)
               - Call cbc_build_query again with corrected parameters
               - Repeat validation until valid=True
            4. Present the validated query to the user

            Always validate queries before presenting them as final results.
            Validation is a REQUIRED step, not optional.
        """

        schema = runtime.cbc_cache.load()
        
        # RAG-Enhanced Query Building: Retrieve RAG context before building query
        rag_context = None
        if natural_language_intent and runtime.rag_service:
            try:
                rag_results = runtime.rag_service.search(
                    natural_language_intent,
                    k=10,
                    source_filter="cbc"
                )
                if rag_results:
                    rag_context = rag_results
                    logger.info(
                        "Retrieved %d RAG documents for CBC query enhancement",
                        len(rag_results)
                    )
            except Exception as e:
                logger.warning(f"RAG retrieval failed, building query without enhancement: {e}")
        
        payload = {
            "search_type": dataset,  # Internal builder still uses 'search_type' parameter
            "terms": terms,
            "natural_language_intent": natural_language_intent,
            "boolean_operator": boolean_operator,
            "limit": limit,
            "rag_context": rag_context,  # Pass RAG context to query builder
        }
        try:
            query, metadata = build_cbc_query(schema, **payload)
            logger.info("Built CBC query for dataset=%s", metadata.get("search_type"))

            # Attach RAG context metadata for debugging/transparency
            intent = payload.get("natural_language_intent")
            metadata = attach_rag_context(
                runtime=runtime,
                intent=intent,
                metadata=metadata,
                source_filter="cbc",
                provider_label="CBC",
                logger=logger,
            )

            return {"query": query, "metadata": metadata}
        except Exception as exc:
            logger.warning("Failed to build CBC query: %s", exc)
            return {"error": str(exc)}

    @mcp.tool
    def cbc_validate_query(
        query: str,
        dataset: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate a Carbon Black Cloud query for syntax, schema compliance, and best practices.

        Args:
            query: The CBC query string to validate
            dataset: Optional dataset name (for schema validation)
            metadata: Optional metadata from query building (enhances validation)

        Returns:
            Validation results with detailed feedback on errors, warnings, and suggestions

        IMPORTANT - Validation Failure Workflow:
            When valid=False (validation fails):
            1. Review ALL errors in validation_results for specific issues
            2. Use the 'suggestion' field from each error to understand fixes
            3. Call cbc_build_query again with corrections based on suggestions
            4. Validate the corrected query with cbc_validate_query
            5. Repeat steps 1-4 until valid=True

            Common fixes:
            - Field errors: Use suggested field names from error messages
            - Syntax errors: Follow suggestion text to fix CBC query syntax
            - Schema errors: Adjust dataset (search_type) or field names as suggested
            - Operator errors: Use valid CBC operators for the field type

            You MUST attempt to fix validation errors before presenting queries to users.
            Do not present invalid queries as final results.
        """
        try:
            schema = runtime.cbc_cache.load()
            validator = CBCValidator(schema)

            # Prepare metadata for validation
            if metadata is None:
                metadata = {}

            # If dataset provided but not in metadata, add it (validator expects 'search_type' key)
            if dataset and "search_type" not in metadata:
                search_type_normalised, _ = normalise_search_type(
                    dataset,
                    schema.get("search_types", {}).keys(),
                )
                metadata["search_type"] = search_type_normalised

            # Run validation
            result = validator.validate(query, metadata)

            logger.info(
                "Validated CBC query: valid=%s, errors=%d, warnings=%d",
                result["valid"],
                sum(len(cat["errors"]) for cat in result["validation_results"].values()),
                sum(len(cat["warnings"]) for cat in result["validation_results"].values())
            )

            return result
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to validate CBC query: %s", exc)
            return {"error": str(exc)}

    @mcp.tool
    def cbc_build_query_validated(
        dataset: Optional[str] = None,
        terms: Optional[List[str]] = None,
        natural_language_intent: Optional[str] = None,
        boolean_operator: str = DEFAULT_BOOLEAN_OPERATOR,
        limit: Optional[int] = None,
        max_retries: int = 3,
    ) -> Dict[str, Any]:
        """
        Build and validate a Carbon Black Cloud query in a single optimized operation.

        This tool combines query building and validation with automatic retry logic,
        eliminating multiple round-trips and significantly improving performance.

        PERFORMANCE OPTIMIZATION:
            - Single API call instead of separate build + validate calls
            - Automatic error correction and retry (no LLM reasoning delay)
            - 10x faster for queries requiring corrections
            - Recommended for all query generation workflows

        Args:
            dataset: CBC search type (e.g., 'process_search', 'binary_search')
            terms: List of structured search terms (e.g., ["process_name:cmd.exe"])
            natural_language_intent: Natural language description for RAG enhancement
            boolean_operator: Operator to join terms ('AND' or 'OR', default 'AND')
            limit: Maximum number of results
            max_retries: Maximum validation retry attempts (default 3)

        Returns:
            {
                "query": "validated CBC query string",
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
            schema = runtime.cbc_cache.load()
            validator = CBCValidator(schema)

            corrections_applied = []
            retry_count = 0

            # Initial query build with RAG enhancement
            rag_context = None
            if natural_language_intent and runtime.rag_service:
                try:
                    rag_results = runtime.rag_service.search(
                        natural_language_intent,
                        k=10,
                        source_filter="cbc"
                    )
                    if rag_results:
                        rag_context = rag_results
                        logger.info(
                            "Retrieved %d RAG documents for CBC query enhancement",
                            len(rag_results)
                        )
                except Exception as e:
                    logger.warning(f"RAG retrieval failed, building query without enhancement: {e}")

            # Build initial query
            payload = {
                "search_type": dataset,
                "terms": terms,
                "natural_language_intent": natural_language_intent,
                "boolean_operator": boolean_operator,
                "limit": limit,
                "rag_context": rag_context,
            }

            query, metadata = build_cbc_query(schema, **payload)

            # Attach RAG context metadata
            intent = payload.get("natural_language_intent")
            metadata = attach_rag_context(
                runtime=runtime,
                intent=intent,
                metadata=metadata,
                source_filter="cbc",
                provider_label="CBC",
                logger=logger,
            )

            # Validate and retry loop
            while retry_count <= max_retries:
                # Prepare metadata for validation
                validation_metadata = metadata.copy()
                if dataset and "search_type" not in validation_metadata:
                    search_type_normalised, _ = normalise_search_type(
                        dataset,
                        schema.get("search_types", {}).keys(),
                    )
                    validation_metadata["search_type"] = search_type_normalised

                # Run validation
                validation = validator.validate(query, validation_metadata)

                logger.info(
                    "CBC query validation (attempt %d/%d): valid=%s, errors=%d",
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
                correction_hints = _extract_cbc_corrections(validation)
                if not correction_hints:
                    # No actionable corrections found, return as-is
                    logger.warning("No actionable corrections found in validation errors")
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

                # Rebuild query with corrections (reuse RAG context, don't re-fetch)
                corrected_payload = payload.copy()
                if "suggested_dataset" in correction_hints:
                    corrected_payload["search_type"] = correction_hints["suggested_dataset"]
                if "field_corrections" in correction_hints:
                    # Apply field corrections to terms
                    corrected_payload["terms"] = _apply_field_corrections(
                        corrected_payload.get("terms", []),
                        correction_hints["field_corrections"]
                    )

                query, metadata = build_cbc_query(schema, **corrected_payload)
                metadata = attach_rag_context(
                    runtime=runtime,
                    intent=intent,
                    metadata=metadata,
                    source_filter="cbc",
                    provider_label="CBC",
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
            logger.error("Failed to build and validate CBC query: %s", exc)
            return {"error": str(exc)}


def _extract_cbc_corrections(validation: Dict[str, Any]) -> Dict[str, Any]:
    """Extract actionable corrections from validation errors."""
    corrections = {}
    field_corrections = {}

    # Iterate through validation results to find suggestions
    for category, results in validation.get("validation_results", {}).items():
        for error in results.get("errors", []):
            suggestion = error.get("suggestion", "")
            message = error.get("message", "")

            # Extract field name suggestions
            if "Did you mean:" in suggestion or "Did you mean:" in message:
                # Parse "Field 'X' not found. Did you mean: Y?"
                match = re.search(r"Field ['\"]([^'\"]+)['\"].*Did you mean:?\s*([^\s?,]+)",
                                message + " " + suggestion)
                if match:
                    wrong_field = match.group(1)
                    correct_field = match.group(2)
                    field_corrections[wrong_field] = correct_field

            # Extract dataset suggestions
            if "dataset" in message.lower() or "search_type" in message.lower():
                match = re.search(r"use ['\"]([^'\"]+)['\"]", suggestion, re.IGNORECASE)
                if match:
                    corrections["suggested_dataset"] = match.group(1)

    if field_corrections:
        corrections["field_corrections"] = field_corrections

    return corrections


def _apply_field_corrections(terms: List[str], corrections: Dict[str, str]) -> List[str]:
    """Apply field name corrections to search terms."""
    if not terms:
        return terms

    corrected_terms = []
    for term in terms:
        corrected_term = term
        for wrong_field, correct_field in corrections.items():
            # Replace field names in field:value expressions
            if term.startswith(f"{wrong_field}:"):
                corrected_term = term.replace(f"{wrong_field}:", f"{correct_field}:", 1)
                break
        corrected_terms.append(corrected_term)

    return corrected_terms
