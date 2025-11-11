from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Union

from fastmcp import FastMCP

from queryforge.platforms.s1.query_builder import (
    DEFAULT_BOOLEAN_OPERATOR as S1_DEFAULT_BOOLEAN_OPERATOR,
    DEFAULT_DATASET as S1_DEFAULT_DATASET,
    QueryBuildError as S1QueryBuildError,
    build_s1_query,
    infer_dataset,
)
from queryforge.platforms.s1.validator import S1Validator
from queryforge.server.server_runtime import ServerRuntime

from queryforge.server.server_tools_shared import attach_rag_context

logger = logging.getLogger(__name__)


def register_s1_tools(mcp: FastMCP, runtime: ServerRuntime) -> None:
    """Register SentinelOne S1QL tooling."""

    @mcp.tool
    def s1_list_datasets() -> Dict[str, Any]:
        """List SentinelOne datasets with display names and descriptions."""

        schema = runtime.s1_cache.load()
        datasets = runtime.s1_cache.datasets()
        items: List[Dict[str, Any]] = []
        for key in sorted(datasets.keys()):
            meta = datasets.get(key, {})
            if not isinstance(meta, dict):
                continue
            metadata = meta.get("metadata", {})
            description = metadata.get("description") if isinstance(metadata, dict) else None
            items.append(
                {
                    "key": key,
                    "name": meta.get("name", key),
                    "description": description,
                }
            )
        logger.info("Listing %d SentinelOne datasets", len(items))
        return {"datasets": items}

    @mcp.tool
    def s1_get_fields(dataset: str) -> Dict[str, Any]:
        """Return available fields for a SentinelOne dataset."""

        schema = runtime.s1_cache.load()
        dataset_key = infer_dataset(dataset, None, schema)
        if not dataset_key:
            return {"error": f"Unknown dataset '{dataset}'"}

        fields = runtime.s1_cache.list_fields(dataset_key)
        logger.info(
            "Resolved SentinelOne dataset %s (%s) with %d fields",
            dataset,
            dataset_key,
            len(fields),
        )
        return {
            "dataset": dataset_key,
            "name": schema.get("datasets", {}).get(dataset_key, {}).get("name", dataset_key),
            "fields": fields,
        }

    @mcp.tool
    def s1_build_query(
        dataset: Optional[str] = None,
        filters: Optional[List[Union[str, Dict[str, Any]]]] = None,
        natural_language_intent: Optional[str] = None,
        boolean_operator: str = S1_DEFAULT_BOOLEAN_OPERATOR,
    ) -> Dict[str, Any]:
        """
        Build a SentinelOne S1QL query from structured inputs or intent.

        RECOMMENDED WORKFLOW:
            1. Call s1_build_query to generate the initial query
            2. Call s1_validate_query on the generated query and metadata
            3. If validation fails (valid=False):
               - Review error messages and suggestions in validation_results
               - Adjust parameters based on feedback (e.g., fix field names, datasets)
               - Call s1_build_query again with corrected parameters
               - Repeat validation until valid=True
            4. Present the validated query to the user

            Always validate queries before presenting them as final results.
            Validation is a REQUIRED step, not optional.
        """

        # Validate filters format before processing
        if filters is not None:
            if not isinstance(filters, list):
                if isinstance(filters, dict):
                    filters = [filters]
                else:
                    error_msg = (
                        f"Invalid filters type: expected list of strings or dicts, got {type(filters).__name__}. "
                        f"Received value: {repr(filters)[:100]}. "
                        f"Correct format examples: "
                        f"['src.process.name = \"chrome.exe\"'] OR "
                        f"[{{'field': 'src.process.name', 'operator': '=', 'value': 'chrome.exe'}}]"
                    )
                    logger.error(error_msg)
                    return {"error": error_msg}
            else:
                # Validate each filter in the list
                for i, f in enumerate(filters):
                    if isinstance(f, dict):
                        if "field" not in f:
                            error_msg = (
                                f"Filter dict at index {i} missing required 'field' key. "
                                f"Received: {f}. "
                                f"Correct format example: {{'field': 'src.process.name', 'operator': '=', 'value': 'chrome.exe'}}"
                            )
                            logger.error(error_msg)
                            return {"error": error_msg}
                    elif not isinstance(f, str):
                        error_msg = (
                            f"Invalid filter format at index {i}: expected string or dict, got {type(f).__name__}. "
                            f"Received value: {repr(f)[:100]}. "
                            f"Correct format examples: "
                            f"'src.process.name = \"chrome.exe\"' OR "
                            f"{{'field': 'src.process.name', 'operator': '=', 'value': 'chrome.exe'}}"
                        )
                        logger.error(error_msg)
                        return {"error": error_msg}

        schema = runtime.s1_cache.load()
        payload = {
            "dataset": dataset,
            "filters": filters,
            "natural_language_intent": natural_language_intent,
            "boolean_operator": boolean_operator,
        }
        try:
            query, metadata = build_s1_query(schema=schema, **payload)
            logger.info(
                "Built SentinelOne query for dataset=%s",
                metadata.get("dataset") or S1_DEFAULT_DATASET,
            )
            intent = payload.get("natural_language_intent")
            metadata = attach_rag_context(
                runtime=runtime,
                intent=intent,
                metadata=metadata,
                source_filter="s1",
                provider_label="SentinelOne",
                logger=logger,
            )
            return {"query": query, "metadata": metadata}
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to build SentinelOne query: %s", exc)
            return {"error": str(exc)}

    @mcp.tool
    def s1_validate_query(
        query: str,
        dataset: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate a SentinelOne S1QL query for syntax, schema compliance, and best practices.

        Args:
            query: The S1QL query string to validate
            dataset: Optional dataset name (for schema validation)
            metadata: Optional metadata from query building (enhances validation)

        Returns:
            Validation results with detailed feedback on errors, warnings, and suggestions

        IMPORTANT - Validation Failure Workflow:
            When valid=False (validation fails):
            1. Review ALL errors in validation_results for specific issues
            2. Use the 'suggestion' field from each error to understand fixes
            3. Call s1_build_query again with corrections based on suggestions
            4. Validate the corrected query with s1_validate_query
            5. Repeat steps 1-4 until valid=True

            Common fixes:
            - Field errors: Use suggested field names from error messages
            - Syntax errors: Follow suggestion text to fix quotes, parentheses, etc.
            - Schema errors: Adjust dataset or field names as suggested
            - Operator errors: Use valid operators for the field type

            You MUST attempt to fix validation errors before presenting queries to users.
            Do not present invalid queries as final results.
        """
        try:
            schema = runtime.s1_cache.load()
            validator = S1Validator(schema)

            # Prepare metadata for validation
            if metadata is None:
                metadata = {}

            # If dataset provided but not in metadata, add it
            if dataset and "dataset" not in metadata:
                dataset_key = infer_dataset(dataset, None, schema)
                metadata["dataset"] = dataset_key

            # Run validation
            result = validator.validate(query, metadata)

            logger.info(
                "Validated S1 query: valid=%s, errors=%d, warnings=%d",
                result["valid"],
                len(result["validation_results"]["syntax"]["errors"]) +
                len(result["validation_results"]["schema"]["errors"]) +
                len(result["validation_results"]["operators"]["errors"]) +
                len(result["validation_results"]["performance"]["errors"]) +
                len(result["validation_results"]["best_practices"]["errors"]),
                len(result["validation_results"]["syntax"]["warnings"]) +
                len(result["validation_results"]["schema"]["warnings"]) +
                len(result["validation_results"]["operators"]["warnings"]) +
                len(result["validation_results"]["performance"]["warnings"]) +
                len(result["validation_results"]["best_practices"]["warnings"])
            )

            return result
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to validate SentinelOne query: %s", exc)
            return {"error": str(exc)}

    @mcp.tool
    def s1_build_query_validated(
        dataset: Optional[str] = None,
        filters: Optional[List[Union[str, Dict[str, Any]]]] = None,
        natural_language_intent: Optional[str] = None,
        boolean_operator: str = S1_DEFAULT_BOOLEAN_OPERATOR,
        max_retries: int = 3,
    ) -> Dict[str, Any]:
        """
        Build and validate a SentinelOne S1QL query in a single optimized operation.

        This tool combines query building and validation with automatic retry logic,
        eliminating multiple round-trips and significantly improving performance.

        PERFORMANCE OPTIMIZATION:
            - Single API call instead of separate build + validate calls
            - Automatic error correction and retry (no LLM reasoning delay)
            - 10x faster for queries requiring corrections
            - Recommended for all query generation workflows

        Args:
            dataset: SentinelOne dataset (e.g., 'processes', 'network')
            filters: List of filter strings or dicts with field/operator/value
            natural_language_intent: Natural language description for RAG enhancement
            boolean_operator: Operator to join filters ('AND' or 'OR', default 'AND')
            max_retries: Maximum validation retry attempts (default 3)

        Returns:
            {
                "query": "validated S1QL query string",
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
                if not isinstance(filters, list):
                    if isinstance(filters, dict):
                        filters = [filters]
                    else:
                        error_msg = (
                            f"Invalid filters type: expected list of strings or dicts, got {type(filters).__name__}. "
                            f"Received value: {repr(filters)[:100]}. "
                            f"Correct format examples: "
                            f"['src.process.name = \"chrome.exe\"'] OR "
                            f"[{{'field': 'src.process.name', 'operator': '=', 'value': 'chrome.exe'}}]"
                        )
                        logger.error(error_msg)
                        return {"error": error_msg}
                else:
                    # Validate each filter in the list
                    for i, f in enumerate(filters):
                        if isinstance(f, dict):
                            if "field" not in f:
                                error_msg = (
                                    f"Filter dict at index {i} missing required 'field' key. "
                                    f"Received: {f}. "
                                    f"Correct format example: {{'field': 'src.process.name', 'operator': '=', 'value': 'chrome.exe'}}"
                                )
                                logger.error(error_msg)
                                return {"error": error_msg}
                        elif not isinstance(f, str):
                            error_msg = (
                                f"Invalid filter format at index {i}: expected string or dict, got {type(f).__name__}. "
                                f"Received value: {repr(f)[:100]}. "
                                f"Correct format examples: "
                                f"'src.process.name = \"chrome.exe\"' OR "
                                f"{{'field': 'src.process.name', 'operator': '=', 'value': 'chrome.exe'}}"
                            )
                            logger.error(error_msg)
                            return {"error": error_msg}

            schema = runtime.s1_cache.load()
            validator = S1Validator(schema)

            corrections_applied = []
            retry_count = 0

            payload = {
                "dataset": dataset,
                "filters": filters,
                "natural_language_intent": natural_language_intent,
                "boolean_operator": boolean_operator,
            }

            # Build initial query
            query, metadata = build_s1_query(schema=schema, **payload)

            # Attach RAG context metadata
            intent = payload.get("natural_language_intent")
            metadata = attach_rag_context(
                runtime=runtime,
                intent=intent,
                metadata=metadata,
                source_filter="s1",
                provider_label="SentinelOne",
                logger=logger,
            )

            # Validate and retry loop
            while retry_count <= max_retries:
                # Prepare metadata for validation
                validation_metadata = metadata.copy()
                if dataset and "dataset" not in validation_metadata:
                    dataset_key = infer_dataset(dataset, None, schema)
                    validation_metadata["dataset"] = dataset_key

                # Run validation
                validation = validator.validate(query, validation_metadata)

                logger.info(
                    "S1 query validation (attempt %d/%d): valid=%s, errors=%d",
                    retry_count + 1,
                    max_retries + 1,
                    validation["valid"],
                    len(validation["validation_results"]["syntax"]["errors"]) +
                    len(validation["validation_results"]["schema"]["errors"]) +
                    len(validation["validation_results"]["operators"]["errors"]) +
                    len(validation["validation_results"]["performance"]["errors"]) +
                    len(validation["validation_results"]["best_practices"]["errors"])
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
                correction_hints = _extract_s1_corrections(validation)
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
                corrected_payload = payload.copy()
                if "suggested_dataset" in correction_hints:
                    corrected_payload["dataset"] = correction_hints["suggested_dataset"]
                if "field_corrections" in correction_hints and filters:
                    # Apply field corrections to filters
                    corrected_payload["filters"] = _apply_s1_field_corrections(
                        filters,
                        correction_hints["field_corrections"]
                    )

                query, metadata = build_s1_query(schema=schema, **corrected_payload)
                metadata = attach_rag_context(
                    runtime=runtime,
                    intent=intent,
                    metadata=metadata,
                    source_filter="s1",
                    provider_label="SentinelOne",
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
            logger.error("Failed to build and validate S1 query: %s", exc)
            return {"error": str(exc)}


def _extract_s1_corrections(validation: Dict[str, Any]) -> Dict[str, Any]:
    """Extract actionable corrections from S1 validation errors."""
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


def _apply_s1_field_corrections(
    filters: List[Union[str, Dict[str, Any]]],
    corrections: Dict[str, str]
) -> List[Union[str, Dict[str, Any]]]:
    """Apply field name corrections to S1 filters."""
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
                # Replace field names in filter strings (handle S1QL syntax)
                corrected_str = re.sub(
                    r'\b' + re.escape(wrong_field) + r'\b',
                    correct_field,
                    corrected_str
                )
            corrected_filters.append(corrected_str)
        else:
            corrected_filters.append(f)
    return corrected_filters
