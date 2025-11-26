"""
Shared validation framework for QueryForge query builders.

This module provides base classes and utilities for validating queries across all platforms.
Validators check syntax, schema compliance, performance characteristics, and best practices.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import hashlib
import re
import time
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed


class ValidationSeverity(Enum):
    """Severity levels for validation issues."""

    ERROR = "error"      # Critical issue that prevents query execution
    WARNING = "warning"  # Non-critical issue that may cause problems
    INFO = "info"        # Informational suggestion for improvement


@dataclass
class ValidationIssue:
    """Represents a single validation issue found in a query."""

    severity: ValidationSeverity
    category: str  # "syntax", "schema", "operators", "performance", "best_practices"
    message: str
    location: Optional[str] = None  # e.g., "filter[2].field", "where[0]"
    suggestion: Optional[str] = None  # Actionable recommendation

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "severity": self.severity.value,
            "category": self.category,
            "message": self.message,
            "location": self.location,
            "suggestion": self.suggestion
        }


@dataclass
class ValidationResult:
    """Results from validating a query."""

    valid: bool
    errors: List[ValidationIssue] = field(default_factory=list)
    warnings: List[ValidationIssue] = field(default_factory=list)
    info: List[ValidationIssue] = field(default_factory=list)

    def add_issue(self, issue: ValidationIssue) -> None:
        """Add an issue to the appropriate list based on severity."""
        if issue.severity == ValidationSeverity.ERROR:
            self.errors.append(issue)
            self.valid = False
        elif issue.severity == ValidationSeverity.WARNING:
            self.warnings.append(issue)
        else:
            self.info.append(issue)

    def add_issues(self, issues: List[ValidationIssue]) -> None:
        """Add multiple issues."""
        for issue in issues:
            self.add_issue(issue)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "valid": self.valid,
            "errors": [e.to_dict() for e in self.errors],
            "warnings": [w.to_dict() for w in self.warnings],
            "info": [i.to_dict() for i in self.info],
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "info_count": len(self.info)
        }


class BaseValidator(ABC):
    """
    Abstract base class for platform-specific query validators.

    Each platform (S1, KQL, CBC, Cortex) should implement this interface
    to provide comprehensive query validation.
    """

    # Class-level cache for validation results (shared across all instances)
    # Optimization 2: Increased cache size from 1,000 to 10,000 entries
    _validation_cache: Dict[str, Dict[str, Any]] = {}
    _cache_max_size: int = 10_000
    _cache_hits: int = 0
    _cache_misses: int = 0

    def __init__(self, schema: Dict[str, Any], enable_cache: bool = True):
        """
        Initialize validator with platform schema.

        Args:
            schema: Platform-specific schema containing fields, operators, etc.
            enable_cache: Whether to enable validation result caching (default: True)
        """
        self.schema = schema
        self.enable_cache = enable_cache

    def _get_cache_key(self, query: str, metadata: Optional[Dict[str, Any]]) -> str:
        """
        Generate a cache key from query and metadata.

        Args:
            query: The query string
            metadata: Query metadata

        Returns:
            SHA256 hash of query + relevant metadata fields
        """
        # Include only stable metadata fields that affect validation
        stable_metadata = {}
        if metadata:
            # Include platform-specific identifying fields
            for key in ['search_type', 'dataset', 'table']:
                if key in metadata:
                    stable_metadata[key] = metadata[key]

        # Create deterministic string representation
        cache_input = f"{query}:{str(sorted(stable_metadata.items()))}"
        return hashlib.sha256(cache_input.encode()).hexdigest()

    def _get_from_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get validation result from cache if available (Optimization 2)."""
        if not self.enable_cache:
            return None
        
        result = BaseValidator._validation_cache.get(cache_key)
        if result is not None:
            BaseValidator._cache_hits += 1
        else:
            BaseValidator._cache_misses += 1
        return result

    def _add_to_cache(self, cache_key: str, result: Dict[str, Any]) -> None:
        """Add validation result to cache with timestamp (Optimization 2)."""
        if not self.enable_cache:
            return

        # Simple LRU eviction: if cache is full, clear 10% of entries
        if len(BaseValidator._validation_cache) >= BaseValidator._cache_max_size:
            # Remove oldest 10% of entries (simple FIFO for now)
            num_to_remove = max(1, BaseValidator._cache_max_size // 10)
            keys_to_remove = list(BaseValidator._validation_cache.keys())[:num_to_remove]
            for key in keys_to_remove:
                del BaseValidator._validation_cache[key]

        # Store result with timestamp for potential TTL implementation
        cached_result = result.copy()
        cached_result["_cached_at"] = time.time()
        BaseValidator._validation_cache[cache_key] = cached_result

    @classmethod
    def clear_cache(cls) -> None:
        """Clear the validation cache. Useful for testing or memory management."""
        cls._validation_cache.clear()

    @classmethod
    def get_cache_stats(cls) -> Dict[str, Any]:
        """Get cache statistics (Optimization 2: Enhanced metrics)."""
        total_requests = cls._cache_hits + cls._cache_misses
        hit_rate = cls._cache_hits / total_requests if total_requests > 0 else 0.0
        
        return {
            "size": len(cls._validation_cache),
            "max_size": cls._cache_max_size,
            "utilization": len(cls._validation_cache) / cls._cache_max_size if cls._cache_max_size > 0 else 0,
            "hits": cls._cache_hits,
            "misses": cls._cache_misses,
            "hit_rate": hit_rate,
            "total_requests": total_requests
        }

    def validate(self, query: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Run all validation checks and return comprehensive results.

        Optimization 2: Enhanced caching with metrics tracking
        Optimization 3: Parallel validation execution for 3x speedup

        Args:
            query: The query string to validate
            metadata: Optional metadata from query building (fields, operators, etc.)

        Returns:
            Dictionary with validation results containing:
                - valid: Overall validation status
                - validation_results: Detailed results by category
                - metadata: Additional context (complexity, estimated size, etc.)
                - cache_hit: Whether result came from cache (only present if cached)
        """
        # Prepare metadata if not provided
        if metadata is None:
            metadata = {}

        # Check cache first (Optimization 2)
        cache_key = self._get_cache_key(query, metadata)
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            # Add cache hit indicator and remove internal timestamp
            result = {k: v for k, v in cached_result.items() if k != "_cached_at"}
            result["cache_hit"] = True
            return result

        # Optimization 3: Run validation categories in parallel
        validation_results_dict = {}
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            # Submit all validation tasks
            future_to_category = {
                executor.submit(self.validate_syntax, query): 'syntax',
                executor.submit(self.validate_schema, query, metadata): 'schema',
                executor.submit(self.validate_operators, query, metadata): 'operators',
                executor.submit(self.validate_performance, query, metadata): 'performance',
                executor.submit(self.validate_best_practices, query, metadata): 'best_practices'
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_category):
                category = future_to_category[future]
                try:
                    issues = future.result()
                    result_obj = ValidationResult(valid=True)
                    result_obj.add_issues(issues)
                    validation_results_dict[category] = result_obj
                except Exception as exc:
                    # If a validation category fails, create an error result
                    result_obj = ValidationResult(valid=False)
                    result_obj.add_issue(ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        category=category,
                        message=f"Validation failed: {exc}",
                        suggestion="Check query syntax and try again"
                    ))
                    validation_results_dict[category] = result_obj

        # Determine overall validity (only ERRORs make query invalid)
        overall_valid = all(result.valid for result in validation_results_dict.values())

        # Calculate additional metadata
        complexity_score = self._calculate_complexity(query, metadata)
        estimated_size = self._estimate_result_size(query, metadata)

        result = {
            "valid": overall_valid,
            "query": query,
            "validation_results": {
                category: result_obj.to_dict() 
                for category, result_obj in validation_results_dict.items()
            },
            "metadata": {
                "platform": self.get_platform_name(),
                "complexity_score": complexity_score,
                "estimated_result_size": estimated_size,
                **self._get_additional_metadata(query, metadata)
            }
        }

        # Add to cache for future lookups (Optimization 2)
        self._add_to_cache(cache_key, result)

        return result

    @abstractmethod
    def validate_syntax(self, query: str) -> List[ValidationIssue]:
        """
        Validate query syntax (parsing, structure, dangerous characters).

        Args:
            query: The query string to validate

        Returns:
            List of validation issues found
        """
        pass

    @abstractmethod
    def validate_schema(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Validate query against schema (field existence, types, compatibility).

        Args:
            query: The query string
            metadata: Query metadata containing fields, dataset, etc.

        Returns:
            List of validation issues found
        """
        pass

    @abstractmethod
    def validate_operators(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Validate operators (existence, compatibility with field types).

        Args:
            query: The query string
            metadata: Query metadata containing operators used

        Returns:
            List of validation issues found
        """
        pass

    @abstractmethod
    def validate_performance(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Detect performance issues (unbounded queries, expensive operations).

        Args:
            query: The query string
            metadata: Query metadata

        Returns:
            List of validation issues found (typically WARNINGs)
        """
        pass

    @abstractmethod
    def validate_best_practices(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Check against platform-specific best practices.

        Args:
            query: The query string
            metadata: Query metadata

        Returns:
            List of validation issues found (typically INFO/WARNINGs)
        """
        pass

    @abstractmethod
    def get_platform_name(self) -> str:
        """Return the platform name (e.g., 's1', 'kql', 'cbc', 'cortex')."""
        pass

    def _calculate_complexity(self, query: str, metadata: Dict[str, Any]) -> int:
        """
        Calculate query complexity score (1-10).

        Default implementation considers:
        - Number of conditions/filters
        - Use of regex/wildcards
        - Number of fields
        - Boolean operators

        Platform-specific validators can override for custom scoring.

        Returns:
            Complexity score from 1 (simple) to 10 (very complex)
        """
        score = 1

        # Add points for conditions
        if metadata.get("conditions_count"):
            score += min(metadata["conditions_count"] // 2, 3)

        # Add points for regex patterns
        regex_count = len(re.findall(r'regex|matches|~', query, re.IGNORECASE))
        score += min(regex_count, 2)

        # Add points for wildcards
        wildcard_count = query.count('*')
        score += min(wildcard_count // 3, 2)

        # Add points for OR operators (more complex than AND)
        or_count = len(re.findall(r'\bOR\b', query, re.IGNORECASE))
        score += min(or_count, 2)

        return min(score, 10)

    def _estimate_result_size(self, query: str, metadata: Dict[str, Any]) -> str:
        """
        Estimate result set size.

        Returns: "small", "medium", "large", or "unbounded"
        """
        # Check for explicit limit
        limit = metadata.get("limit")
        if limit:
            if limit <= 100:
                return "small"
            elif limit <= 1000:
                return "medium"
            else:
                return "large"

        # Check for time constraints
        has_time_filter = (
            "time" in query.lower() or
            "timestamp" in query.lower() or
            "ago(" in query.lower() or
            metadata.get("time_window") is not None
        )

        # Check for specific field filters
        conditions_count = metadata.get("conditions_count", 0)

        if has_time_filter and conditions_count >= 2:
            return "medium"
        elif has_time_filter or conditions_count >= 3:
            return "large"
        else:
            return "unbounded"

    def _get_additional_metadata(self, query: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get additional platform-specific metadata.

        Platform validators can override to add custom metadata.

        Returns:
            Dictionary of additional metadata
        """
        return {}


# Common validation utilities

def check_balanced_quotes(text: str, quote_char: str = '"') -> Optional[ValidationIssue]:
    """
    Check if quotes are balanced in text.

    Args:
        text: Text to check
        quote_char: Quote character to check (' or ")

    Returns:
        ValidationIssue if unbalanced, None otherwise
    """
    # Count non-escaped quotes
    escaped = text.replace(f'\\{quote_char}', '')
    count = escaped.count(quote_char)

    if count % 2 != 0:
        return ValidationIssue(
            severity=ValidationSeverity.ERROR,
            category="syntax",
            message=f"Unbalanced {quote_char} quotes detected",
            suggestion=f"Ensure all {quote_char} quotes are properly closed or escaped"
        )
    return None


def check_balanced_parentheses(text: str) -> Optional[ValidationIssue]:
    """
    Check if parentheses are balanced.

    Returns:
        ValidationIssue if unbalanced, None otherwise
    """
    count = 0
    for char in text:
        if char == '(':
            count += 1
        elif char == ')':
            count -= 1
        if count < 0:
            return ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="syntax",
                message="Unbalanced parentheses: closing ')' without matching opening '('",
                suggestion="Check parentheses pairing in the query"
            )

    if count != 0:
        return ValidationIssue(
            severity=ValidationSeverity.ERROR,
            category="syntax",
            message=f"Unbalanced parentheses: {count} unclosed '('",
            suggestion="Ensure all opening '(' have matching closing ')'"
        )
    return None


def check_dangerous_characters(text: str, dangerous_chars: Set[str]) -> List[ValidationIssue]:
    """
    Check for dangerous or disallowed characters.

    Args:
        text: Text to check
        dangerous_chars: Set of characters to flag

    Returns:
        List of validation issues found
    """
    issues = []
    found_chars = set()

    for char in text:
        if char in dangerous_chars and char not in found_chars:
            found_chars.add(char)
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="syntax",
                message=f"Dangerous character '{char}' detected in query",
                suggestion=f"Remove or escape the '{char}' character"
            ))

    return issues


def suggest_similar_fields(field: str, available_fields: List[str], max_suggestions: int = 3) -> List[str]:
    """
    Find similar field names using simple string matching.

    Args:
        field: The field name that wasn't found
        available_fields: List of valid field names
        max_suggestions: Maximum number of suggestions to return

    Returns:
        List of suggested field names
    """
    if not available_fields:
        return []

    field_lower = field.lower()

    # Exact substring matches first
    exact_matches = [f for f in available_fields if field_lower in f.lower()]
    if exact_matches:
        return exact_matches[:max_suggestions]

    # Then check if any field contains parts of the input
    partial_matches = []
    for avail_field in available_fields:
        avail_lower = avail_field.lower()
        # Check if input is substring or vice versa
        if avail_lower in field_lower or field_lower in avail_lower:
            partial_matches.append(avail_field)

    if partial_matches:
        return partial_matches[:max_suggestions]

    # Fall back to fields with similar prefixes
    prefix = field_lower[:3] if len(field_lower) >= 3 else field_lower
    prefix_matches = [f for f in available_fields if f.lower().startswith(prefix)]

    return prefix_matches[:max_suggestions]


def format_field_list(fields: List[str], max_display: int = 5) -> str:
    """
    Format a list of fields for display in error messages.

    Args:
        fields: List of field names
        max_display: Maximum fields to display before truncating

    Returns:
        Formatted string like "field1, field2, field3... (and 10 more)"
    """
    if not fields:
        return "(none)"

    if len(fields) <= max_display:
        return ", ".join(fields)

    displayed = ", ".join(fields[:max_display])
    remaining = len(fields) - max_display
    return f"{displayed}... (and {remaining} more)"
