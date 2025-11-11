from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Union

from fastmcp import FastMCP

from queryforge.platforms.cortex.query_builder import (
    build_cortex_query,
    DEFAULT_DATASET as CORTEX_DEFAULT_DATASET,
)
from queryforge.platforms.cortex.schema_loader import normalise_dataset
from queryforge.platforms.cortex.validator import CortexValidator
from queryforge.server.server_runtime import ServerRuntime

from queryforge.server.server_tools_shared import attach_rag_context

logger = logging.getLogger(__name__)


def register_cortex_tools(mcp: FastMCP, runtime: ServerRuntime) -> None:
    """Register Cortex XDR tooling with the MCP runtime."""

    @mcp.tool
    def cortex_list_datasets() -> Dict[str, Any]:
        """List Cortex XDR datasets with their descriptions."""

        datasets = runtime.cortex_cache.datasets()
        logger.info("Listing %d Cortex datasets", len(datasets))
        return {"datasets": datasets}

    @mcp.tool
    def cortex_get_fields(dataset: str) -> Dict[str, Any]:
        """Return available fields for a given Cortex XDR dataset."""

        datasets = runtime.cortex_cache.datasets()
        dataset_normalised, log_entries = normalise_dataset(dataset, datasets.keys())
        fields = runtime.cortex_cache.list_fields(dataset_normalised)
        logger.info(
            "Resolved Cortex dataset %s (%s) with %d fields",
            dataset,
            dataset_normalised,
            len(fields),
        )
        return {
            "dataset": dataset_normalised,
            "fields": fields,
            "normalisation": log_entries,
        }

    @mcp.tool
    def cortex_get_xql_functions() -> Dict[str, Any]:
        """Return documented XQL functions."""

        functions = runtime.cortex_cache.function_reference()
        logger.info("Returning %d Cortex XQL functions", len(functions))
        return {"functions": functions}

    @mcp.tool
    def cortex_get_operator_reference() -> Dict[str, Any]:
        """Return XQL operator reference grouped by category."""

        operators = runtime.cortex_cache.operator_reference()
        logger.info("Returning Cortex operator reference with categories: %s", list(operators.keys()))
        return {"operators": operators}

    @mcp.tool
    def cortex_get_enum_reference() -> Dict[str, Any]:
        """Return enumerated value mappings from the Cortex schema."""

        enums = runtime.cortex_cache.enum_values()
        logger.info("Returning Cortex enum reference for %d fields", len(enums))
        return {"enum_values": enums}

    @mcp.tool
    def cortex_get_field_groups() -> Dict[str, Any]:
        """Return logical field groupings to assist with projection selection."""

        groups = runtime.cortex_cache.field_groups()
        logger.info("Returning %d Cortex field groups", len(groups))
        return {"field_groups": groups}

    @mcp.tool
    def cortex_get_examples() -> Dict[str, Any]:
        """Return example XQL queries organized by category (process_execution, network_activity, file_operations, etc.)."""

        examples = runtime.cortex_cache.example_queries()
        logger.info("Returning Cortex example queries with %d categories", len(examples))
        return {"examples": examples}

    @mcp.tool
    def cortex_build_query(
        dataset: Optional[str] = None,
        filters: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None,
        fields: Optional[List[str]] = None,
        natural_language_intent: Optional[str] = None,
        time_range: Optional[Union[str, Dict[str, Any]]] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Build a Cortex XDR XQL query from structured params or natural language.

        RECOMMENDED WORKFLOW:
            1. Call cortex_build_query to generate the initial query
            2. Call cortex_validate_query on the generated query and metadata
            3. If validation fails (valid=False):
               - Review error messages and suggestions in validation_results
               - Adjust parameters based on feedback (e.g., fix field names, datasets)
               - Call cortex_build_query again with corrected parameters
               - Repeat validation until valid=True
            4. Present the validated query to the user

            Always validate queries before presenting them as final results.
            Validation is a REQUIRED step, not optional.
        """

        # Validate filters format before processing
        if filters is not None:
            if isinstance(filters, list):
                for i, f in enumerate(filters):
                    if not isinstance(f, dict):
                        error_msg = (
                            f"Invalid filter format at index {i}: expected dict with "
                            f"'field', 'operator', 'value' keys, got {type(f).__name__}. "
                            f"Received value: {repr(f)[:100]}. "
                            f"Correct format example: {{'field': 'action_local_port', 'operator': '=', 'value': 444}}"
                        )
                        logger.error(error_msg)
                        return {"error": error_msg}
                    if "field" not in f:
                        error_msg = (
                            f"Filter at index {i} missing required 'field' key. "
                            f"Received: {f}. "
                            f"Correct format example: {{'field': 'action_local_port', 'operator': '=', 'value': 444}}"
                        )
                        logger.error(error_msg)
                        return {"error": error_msg}
            elif isinstance(filters, dict):
                if "field" not in filters:
                    error_msg = (
                        f"Filter dict missing required 'field' key. "
                        f"Received: {filters}. "
                        f"Correct format example: {{'field': 'action_local_port', 'operator': '=', 'value': 444}}"
                    )
                    logger.error(error_msg)
                    return {"error": error_msg}
            else:
                error_msg = (
                    f"Invalid filters type: expected dict or list of dicts, got {type(filters).__name__}. "
                    f"Received value: {repr(filters)[:100]}. "
                    f"Correct format example: [{{'field': 'action_local_port', 'operator': '=', 'value': 444}}]"
                )
                logger.error(error_msg)
                return {"error": error_msg}

        dataset_name = dataset or CORTEX_DEFAULT_DATASET
        builder_kwargs = {
            "filters": filters,
            "fields": fields,
            "natural_language_intent": natural_language_intent,
            "time_range": time_range,
            "limit": limit,
        }
        builder_kwargs = {k: v for k, v in builder_kwargs.items() if v is not None}
        try:
            query, metadata = build_cortex_query(
                runtime.cortex_cache,
                dataset=dataset_name,
                **builder_kwargs,
            )
            logger.info("Built Cortex query for dataset=%s", metadata.get("dataset"))

            intent = builder_kwargs.get("natural_language_intent")
            metadata = attach_rag_context(
                runtime=runtime,
                intent=intent,
                metadata=metadata,
                source_filter="cortex",
                provider_label="Cortex",
                logger=logger,
            )

            return {"query": query, "metadata": metadata}
        except (CortexQueryBuildError, ValueError) as exc:
            logger.warning("Failed to build Cortex query: %s", exc)
            return {"error": str(exc)}

    @mcp.tool
    def cortex_validate_query(
        query: str,
        dataset: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate a Cortex XDR XQL query for syntax, schema compliance, and best practices.

        Args:
            query: The XQL query string to validate
            dataset: Optional dataset name (for schema validation)
            metadata: Optional metadata from query building (enhances validation)

        Returns:
            Validation results with detailed feedback on errors, warnings, and suggestions

        IMPORTANT - Validation Failure Workflow:
            When valid=False (validation fails):
            1. Review ALL errors in validation_results for specific issues
            2. Use the 'suggestion' field from each error to understand fixes
            3. Call cortex_build_query again with corrections based on suggestions
            4. Validate the corrected query with cortex_validate_query
            5. Repeat steps 1-4 until valid=True

            Common fixes:
            - Field errors: Use suggested field names from error messages
            - Syntax errors: Follow suggestion text to fix XQL syntax issues
            - Schema errors: Adjust dataset or field names as suggested
            - Operator errors: Use valid XQL operators and functions for the field type

            You MUST attempt to fix validation errors before presenting queries to users.
            Do not present invalid queries as final results.
        """
        try:
            schema = runtime.cortex_cache.load()
            validator = CortexValidator(schema)

            # Prepare metadata for validation
            if metadata is None:
                metadata = {}

            # If dataset provided but not in metadata, add it
            if dataset and "dataset" not in metadata:
                datasets = runtime.cortex_cache.datasets()
                dataset_normalised, _ = normalise_dataset(dataset, datasets.keys())
                metadata["dataset"] = dataset_normalised

            # Run validation
            result = validator.validate(query, metadata)

            logger.info(
                "Validated Cortex query: valid=%s, errors=%d, warnings=%d",
                result["valid"],
                sum(len(cat["errors"]) for cat in result["validation_results"].values()),
                sum(len(cat["warnings"]) for cat in result["validation_results"].values())
            )

            return result
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to validate Cortex query: %s", exc)
            return {"error": str(exc)}

    @mcp.tool
    def cortex_build_query_validated(
        dataset: Optional[str] = None,
        filters: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None,
        fields: Optional[List[str]] = None,
        natural_language_intent: Optional[str] = None,
        time_range: Optional[Union[str, Dict[str, Any]]] = None,
        limit: Optional[int] = None,
        max_retries: int = 3,
    ) -> Dict[str, Any]:
        """
        Build and validate a Cortex XDR XQL query in a single optimized operation.

        This tool combines query building and validation with automatic retry logic,
        eliminating multiple round-trips and significantly improving performance.

        PERFORMANCE OPTIMIZATION:
            - Single API call instead of separate build + validate calls
            - Automatic error correction and retry (no LLM reasoning delay)
            - 10x faster for queries requiring corrections
            - Recommended for all query generation workflows

        Args:
            dataset: Cortex XDR dataset (e.g., 'xdr_data')
            filters: Field filters as dict or list of dicts with field/operator/value
            fields: List of fields to project in results
            natural_language_intent: Natural language description for RAG enhancement
            time_range: Time range filter (string or dict)
            limit: Maximum number of results
            max_retries: Maximum validation retry attempts (default 3)

        Returns:
            {
                "query": "validated XQL query string",
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
            # Validate filters format before processing
            if filters is not None:
                if isinstance(filters, list):
                    for i, f in enumerate(filters):
                        if not isinstance(f, dict):
                            error_msg = (
                                f"Invalid filter format at index {i}: expected dict with "
                                f"'field', 'operator', 'value' keys, got {type(f).__name__}. "
                                f"Received value: {repr(f)[:100]}. "
                                f"Correct format example: {{'field': 'action_local_port', 'operator': '=', 'value': 444}}"
                            )
                            logger.error(error_msg)
                            return {"error": error_msg}
                        if "field" not in f:
                            error_msg = (
                                f"Filter at index {i} missing required 'field' key. "
                                f"Received: {f}. "
                                f"Correct format example: {{'field': 'action_local_port', 'operator': '=', 'value': 444}}"
                            )
                            logger.error(error_msg)
                            return {"error": error_msg}
                elif isinstance(filters, dict):
                    if "field" not in filters:
                        error_msg = (
                            f"Filter dict missing required 'field' key. "
                            f"Received: {filters}. "
                            f"Correct format example: {{'field': 'action_local_port', 'operator': '=', 'value': 444}}"
                        )
                        logger.error(error_msg)
                        return {"error": error_msg}
                else:
                    error_msg = (
                        f"Invalid filters type: expected dict or list of dicts, got {type(filters).__name__}. "
                        f"Received value: {repr(filters)[:100]}. "
                        f"Correct format example: [{{'field': 'action_local_port', 'operator': '=', 'value': 444}}]"
                    )
                    logger.error(error_msg)
                    return {"error": error_msg}

            schema = runtime.cortex_cache.load()
            validator = CortexValidator(schema)

            corrections_applied = []
            retry_count = 0

            dataset_name = dataset or CORTEX_DEFAULT_DATASET
            builder_kwargs = {
                "filters": filters,
                "fields": fields,
                "natural_language_intent": natural_language_intent,
                "time_range": time_range,
                "limit": limit,
            }
            builder_kwargs = {k: v for k, v in builder_kwargs.items() if v is not None}

            # Build initial query
            query, metadata = build_cortex_query(
                runtime.cortex_cache,
                dataset=dataset_name,
                **builder_kwargs,
            )

            # Attach RAG context metadata
            intent = builder_kwargs.get("natural_language_intent")
            metadata = attach_rag_context(
                runtime=runtime,
                intent=intent,
                metadata=metadata,
                source_filter="cortex",
                provider_label="Cortex",
                logger=logger,
            )

            # Validate and retry loop
            while retry_count <= max_retries:
                # Prepare metadata for validation
                validation_metadata = metadata.copy()
                if dataset and "dataset" not in validation_metadata:
                    datasets = runtime.cortex_cache.datasets()
                    dataset_normalised, _ = normalise_dataset(dataset, datasets.keys())
                    validation_metadata["dataset"] = dataset_normalised

                # Run validation
                validation = validator.validate(query, validation_metadata)

                logger.info(
                    "Cortex query validation (attempt %d/%d): valid=%s, errors=%d",
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
                correction_hints = _extract_cortex_corrections(validation)
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

                # Rebuild query with corrections
                corrected_kwargs = builder_kwargs.copy()
                if "suggested_dataset" in correction_hints:
                    dataset_name = correction_hints["suggested_dataset"]
                if "field_corrections" in correction_hints and filters:
                    # Apply field corrections to filters
                    corrected_kwargs["filters"] = _apply_cortex_field_corrections(
                        filters,
                        correction_hints["field_corrections"]
                    )

                query, metadata = build_cortex_query(
                    runtime.cortex_cache,
                    dataset=dataset_name,
                    **corrected_kwargs,
                )
                metadata = attach_rag_context(
                    runtime=runtime,
                    intent=intent,
                    metadata=metadata,
                    source_filter="cortex",
                    provider_label="Cortex",
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
            logger.error("Failed to build and validate Cortex query: %s", exc)
            return {"error": str(exc)}


def _extract_cortex_corrections(validation: Dict[str, Any]) -> Dict[str, Any]:
    """Extract actionable corrections from Cortex validation errors."""
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
            if "dataset" in message.lower():
                match = re.search(r"use ['\"]([^'\"]+)['\"]", suggestion, re.IGNORECASE)
                if match:
                    corrections["suggested_dataset"] = match.group(1)

    if field_corrections:
        corrections["field_corrections"] = field_corrections

    return corrections


def _apply_cortex_field_corrections(
    filters: Union[Dict[str, Any], List[Dict[str, Any]]],
    corrections: Dict[str, str]
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """Apply field name corrections to Cortex filters."""
    if isinstance(filters, dict):
        corrected = filters.copy()
        if "field" in corrected and corrected["field"] in corrections:
            corrected["field"] = corrections[corrected["field"]]
        return corrected
    elif isinstance(filters, list):
        corrected_list = []
        for f in filters:
            corrected_filter = f.copy()
            if "field" in corrected_filter and corrected_filter["field"] in corrections:
                corrected_filter["field"] = corrections[corrected_filter["field"]]
            corrected_list.append(corrected_filter)
        return corrected_list
    return filters
