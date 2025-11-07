"""
Carbon Black Cloud (CBC) Query Validator.

Validates CBC queries for syntax, schema compliance, performance, and best practices.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from shared.validation import (
    BaseValidator,
    ValidationIssue,
    ValidationSeverity,
    check_dangerous_characters,
    suggest_similar_fields,
    format_field_list,
)


# Dangerous characters for CBC queries (security validation)
DANGEROUS_CHARS = {';', '|', '(', ')', '{', '}', '\n', '\r', '\t'}

# Performance thresholds
MAX_QUERY_LENGTH = 10000
MAX_TERMS = 100

# Common CBC fields across search types
COMMON_FIELDS = {
    'md5', 'sha256', 'process_name', 'process_md5', 'process_sha256',
    'parent_name', 'parent_md5', 'parent_sha256', 'cmdline', 'username',
    'hostname', 'ipaddr', 'domain', 'path', 'filemod'
}


class CBCValidator(BaseValidator):
    """Validator for Carbon Black Cloud queries."""

    def get_platform_name(self) -> str:
        """Return platform name."""
        return "cbc"

    def validate_syntax(self, query: str) -> List[ValidationIssue]:
        """
        Validate CBC query syntax.

        Checks:
        - Query length within limits
        - Dangerous characters
        - Field:value format
        - Boolean operator usage
        - Proper quoting
        """
        issues = []

        # Check query length
        if len(query) > MAX_QUERY_LENGTH:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="syntax",
                message=f"Query exceeds maximum length of {MAX_QUERY_LENGTH} characters ({len(query)} chars)",
                suggestion="Simplify the query or use fewer search terms"
            ))

        # Check for dangerous characters
        issues.extend(check_dangerous_characters(query, DANGEROUS_CHARS))

        # Check for proper field:value format
        # CBC queries use field:value or field:"value" syntax
        terms = query.split(' AND ') if ' AND ' in query else query.split(' OR ') if ' OR ' in query else [query]

        for idx, term in enumerate(terms):
            term = term.strip()
            if not term:
                continue

            # Check if term has field:value format or is just a keyword
            if ':' in term:
                # Field-based search
                if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*:[^:]+$', term):
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        category="syntax",
                        message=f"Term '{term[:50]}...' may have malformed field:value syntax",
                        location=f"term[{idx}]",
                        suggestion="Use format: field:value or field:\"value with spaces\""
                    ))

                # Check for spaces in unquoted values
                field_value = term.split(':', 1)
                if len(field_value) == 2:
                    value = field_value[1]
                    if ' ' in value and not (value.startswith('"') and value.endswith('"')):
                        issues.append(ValidationIssue(
                            severity=ValidationSeverity.WARNING,
                            category="syntax",
                            message=f"Value '{value[:30]}...' contains spaces but is not quoted",
                            location=f"term[{idx}]",
                            suggestion="Quote values with spaces: field:\"value with spaces\""
                        ))

            # Check for unescaped backslashes
            if '\\' in term and not '\\\\' in term:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="syntax",
                    message=f"Term contains single backslashes - CBC may require escaping",
                    location=f"term[{idx}]",
                    suggestion="Escape backslashes in Windows paths: C:\\\\Windows\\\\System32"
                ))

        # Check boolean operator casing
        if ' and ' in query.lower():
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="syntax",
                message="Boolean operators should be uppercase in CBC queries",
                suggestion="Use 'AND' instead of 'and', 'OR' instead of 'or'"
            ))

        return issues

    def validate_schema(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Validate query against CBC schema.

        Checks:
        - Search type exists
        - Fields exist in the selected search type
        - Field usage is appropriate
        """
        issues = []

        # Get search type from metadata
        search_type = metadata.get("search_type")
        if not search_type:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="schema",
                message="Cannot validate schema without search_type information",
                suggestion="Provide search_type in metadata for schema validation"
            ))
            return issues

        # Check search type exists
        search_types = self.schema.get("search_types", {})
        if search_type not in search_types:
            available = list(search_types.keys())
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="schema",
                message=f"Search type '{search_type}' not found in CBC schema",
                suggestion=f"Available search types: {format_field_list(available)}"
            ))
            return issues

        # Get fields for this search type
        field_map_key = {
            "process_search": "process_search_fields",
            "binary_search": "binary_search_fields",
            "alert_search": "alert_search_fields",
            "threat_report_search": "threat_report_search_fields",
        }.get(search_type)

        if not field_map_key:
            return issues

        field_map = self.schema.get(field_map_key, {})
        valid_fields = set(field_map.keys())

        # Validate fields used in query (from metadata)
        if metadata.get("recognised"):
            for idx, item in enumerate(metadata["recognised"]):
                # Check if this is a structured field search
                if item.get("type") in ["md5", "sha256", "ipv4", "ipv6", "process_name", "cmdline", "path", "username", "domain", "port"]:
                    field = item.get("field")
                    if field and field not in valid_fields:
                        suggestions = suggest_similar_fields(field, list(valid_fields))
                        suggestion_text = f"Did you mean: {', '.join(suggestions)}" if suggestions else f"Available fields: {format_field_list(list(valid_fields))}"

                        issues.append(ValidationIssue(
                            severity=ValidationSeverity.WARNING,
                            category="schema",
                            message=f"Field '{field}' may not exist in search type '{search_type}'",
                            location=f"recognised[{idx}]",
                            suggestion=suggestion_text
                        ))

        return issues

    def validate_operators(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Validate operators used in query.

        CBC primarily uses field:value syntax and Boolean operators (AND, OR).
        """
        issues = []

        # Check boolean operator
        boolean_op = metadata.get("boolean_operator", "AND")
        if boolean_op not in ["AND", "OR"]:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="operators",
                message=f"Invalid boolean operator '{boolean_op}'",
                suggestion="CBC supports AND and OR operators"
            ))

        # Check for unsupported operators
        unsupported_patterns = ['!=', '<', '>', '<=', '>=', '~=']
        for op in unsupported_patterns:
            if op in query:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="operators",
                    message=f"Operator '{op}' is not typically supported in CBC queries",
                    suggestion="CBC uses field:value syntax; use wildcards (*) for partial matches"
                ))

        return issues

    def validate_performance(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Detect performance issues in query.

        Checks:
        - Unbounded keyword searches
        - Excessive wildcards
        - Missing specific field constraints
        - Too many terms
        """
        issues = []

        # Check number of terms
        recognised = metadata.get("recognised", [])
        if len(recognised) > MAX_TERMS:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="performance",
                message=f"Query has {len(recognised)} terms - this may be slow",
                suggestion="Consider reducing the number of search terms or splitting into multiple queries"
            ))

        # Check for keyword-only searches (no structured fields)
        has_structured = any(item.get("type") not in ["keyword", "structured"] for item in recognised)
        has_keywords_only = any(item.get("type") == "keyword" for item in recognised) and not has_structured

        if has_keywords_only and len(recognised) <= 2:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="performance",
                message="Query uses only keyword searches without specific field filters",
                suggestion="Add field-specific searches (e.g., process_name:, md5:) for better performance"
            ))

        # Check for excessive wildcards
        wildcard_count = query.count('*')
        if wildcard_count > 5:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="performance",
                message=f"Query contains {wildcard_count} wildcards - may be slow",
                suggestion="Reduce wildcard usage or add more specific filters"
            ))

        # Check for wildcards at the beginning of terms (especially slow)
        if re.search(r':"\*', query) or re.search(r":\'\*", query):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="performance",
                message="Leading wildcards (*value) are particularly slow",
                suggestion="Avoid wildcards at the start of search terms if possible"
            ))

        # Check for limit
        limit = metadata.get("limit")
        if limit and limit > 5000:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="performance",
                message=f"Query requests {limit} results (CBC max is 5000)",
                suggestion="Limit will be clamped to 5000"
            ))

        return issues

    def validate_best_practices(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Check against CBC best practices.

        Checks:
        - Using hash fields for IOC searches
        - Structured searches over keywords
        - Appropriate search type selection
        """
        issues = []

        # Suggest using hash fields for hash values
        hash_patterns = {
            'MD5': re.compile(r'\b[a-f0-9]{32}\b', re.IGNORECASE),
            'SHA256': re.compile(r'\b[a-f0-9]{64}\b', re.IGNORECASE),
        }

        for hash_type, pattern in hash_patterns.items():
            if pattern.search(query):
                # Check if using appropriate hash field
                has_hash_field = f"{hash_type.lower()}:" in query.lower() or f"process_{hash_type.lower()}:" in query.lower()
                if not has_hash_field:
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.INFO,
                        category="best_practices",
                        message=f"Query contains {hash_type} hash but may not be using dedicated hash field",
                        suggestion=f"Use hash fields like md5: or process_md5: for {hash_type} hashes"
                    ))

        # Suggest using structured searches over keywords
        recognised = metadata.get("recognised", [])
        keyword_count = sum(1 for item in recognised if item.get("type") == "keyword")
        structured_count = len(recognised) - keyword_count

        if keyword_count > structured_count and keyword_count > 2:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="best_practices",
                message=f"Query uses {keyword_count} keywords vs {structured_count} structured searches",
                suggestion="Structured field searches (field:value) are faster than keyword searches"
            ))

        # Check for IP addresses not using ipaddr field
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        if ip_pattern.search(query) and 'ipaddr:' not in query.lower():
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="best_practices",
                message="Query contains IP addresses - consider using ipaddr: field",
                suggestion="Use ipaddr:1.2.3.4 for better performance on IP searches"
            ))

        # Suggest appropriate search type
        search_type = metadata.get("search_type")
        if search_type == "process_search":
            # Check if looking for file operations (should use binary_search)
            if any(term in query.lower() for term in ['filemod', 'file_path', 'file_name']):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    category="best_practices",
                    message="Query on process_search includes file-related terms",
                    suggestion="Consider using binary_search for file-specific queries"
                ))

        return issues

    def _calculate_complexity(self, query: str, metadata: Dict[str, Any]) -> int:
        """Calculate CBC query complexity (1-10)."""
        score = 1

        # Add points for number of terms
        recognised = metadata.get("recognised", [])
        term_count = len(recognised)
        score += min(term_count // 5, 3)

        # Add points for boolean operators
        and_count = query.count(' AND ')
        or_count = query.count(' OR ')
        score += min((and_count + or_count) // 3, 2)

        # Add points for wildcards (indicates complex pattern matching)
        wildcard_count = query.count('*')
        score += min(wildcard_count // 3, 2)

        # Add point for mixed search types
        keyword_count = sum(1 for item in recognised if item.get("type") == "keyword")
        if 0 < keyword_count < len(recognised):
            score += 1

        return min(score, 10)

    def _estimate_result_size(self, query: str, metadata: Dict[str, Any]) -> str:
        """Estimate result set size for CBC query."""
        # Check for explicit limit
        limit = metadata.get("limit")
        if limit:
            if limit <= 100:
                return "small"
            elif limit <= 1000:
                return "medium"
            else:
                return "large"

        # Estimate based on query specificity
        recognised = metadata.get("recognised", [])
        structured_count = sum(1 for item in recognised if item.get("type") != "keyword")

        # Hash searches are very specific
        has_hash = any("md5" in str(item.get("type")) or "sha256" in str(item.get("type")) for item in recognised)
        if has_hash:
            return "small"

        # Multiple structured searches
        if structured_count >= 3:
            return "medium"
        elif structured_count >= 1:
            return "large"
        else:
            return "unbounded"

    def _get_additional_metadata(self, query: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Get CBC-specific metadata."""
        recognised = metadata.get("recognised", [])
        keyword_count = sum(1 for item in recognised if item.get("type") == "keyword")

        return {
            "search_type": metadata.get("search_type"),
            "boolean_operator": metadata.get("boolean_operator"),
            "term_count": len(recognised),
            "keyword_count": keyword_count,
            "structured_count": len(recognised) - keyword_count,
            "has_hash": any("md5" in str(item.get("type")) or "sha256" in str(item.get("type")) for item in recognised),
            "wildcard_count": query.count('*')
        }
