"""
SentinelOne (S1QL) Query Validator.

Validates S1QL queries for syntax, schema compliance, performance, and best practices.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from queryforge.shared.validation import (
    BaseValidator,
    ValidationIssue,
    ValidationSeverity,
    check_balanced_quotes,
    check_balanced_parentheses,
    check_dangerous_characters,
    suggest_similar_fields,
    format_field_list,
)


# Dangerous characters for S1QL queries (security validation)
DANGEROUS_CHARS = {';', '\n', '\r', '\t', '|'}

# Performance thresholds
MAX_QUERY_LENGTH = 10000
UNBOUNDED_WARNING_THRESHOLD = 1000  # Warn if no limit and query seems unbounded

# Common S1QL functions
S1QL_FUNCTIONS = {'contains', 'startswith', 'endswith', 'in', 'between', 'regex', 'matches', 'matchcase', 'anycase'}


class S1Validator(BaseValidator):
    """Validator for SentinelOne S1QL queries."""

    def get_platform_name(self) -> str:
        """Return platform name."""
        return "s1"

    def validate_syntax(self, query: str) -> List[ValidationIssue]:
        """
        Validate S1QL query syntax.

        Checks:
        - Query length within limits
        - Balanced quotes (single quotes for S1QL)
        - Balanced parentheses
        - Dangerous characters
        - Proper operator syntax
        - IN clause format
        """
        issues = []

        # Check query length
        if len(query) > MAX_QUERY_LENGTH:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="syntax",
                message=f"Query exceeds maximum length of {MAX_QUERY_LENGTH} characters ({len(query)} chars)",
                suggestion="Simplify the query or reduce the number of conditions"
            ))

        # Check for balanced quotes (S1QL uses single quotes)
        quote_issue = check_balanced_quotes(query, "'")
        if quote_issue:
            issues.append(quote_issue)

        # Also check double quotes (should be rare in S1QL but possible)
        double_quote_issue = check_balanced_quotes(query, '"')
        if double_quote_issue:
            issues.append(double_quote_issue)

        # Check for balanced parentheses
        paren_issue = check_balanced_parentheses(query)
        if paren_issue:
            issues.append(paren_issue)

        # Check for dangerous characters
        issues.extend(check_dangerous_characters(query, DANGEROUS_CHARS))

        # Check for proper IN clause syntax: "field in:matchcase ('val1', 'val2')"
        in_clauses = re.findall(r'\bin\s*:\s*matchcase\s*\([^)]+\)', query, re.IGNORECASE)
        for in_clause in in_clauses:
            # Verify values are quoted
            values_section = re.search(r'\(([^)]+)\)', in_clause)
            if values_section:
                values = values_section.group(1)
                # Each value should be quoted
                unquoted_values = re.findall(r'\b\w+\b(?![^\']*\')', values)
                if unquoted_values:
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        category="syntax",
                        message=f"IN clause may have unquoted values: {in_clause[:50]}...",
                        suggestion="Ensure all values in IN clauses are single-quoted, e.g., in:matchcase ('val1', 'val2')"
                    ))

        # Check for potential escape issues with backslashes
        if '\\' in query and '\\\\' not in query:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="syntax",
                message="Query contains single backslashes - S1QL requires double backslashes for Windows paths",
                suggestion="Use double backslashes for literal backslashes, e.g., 'C:\\\\Windows\\\\System32'"
            ))

        return issues

    def validate_schema(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Validate query against S1 schema.

        Checks:
        - Dataset exists
        - Fields exist in the selected dataset
        - Field data types match usage
        """
        issues = []

        # Get dataset from metadata
        dataset = metadata.get("dataset")
        if not dataset:
            # Try to infer from metadata
            if metadata.get("dataset_display_name"):
                dataset = metadata["dataset_display_name"]
            else:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="schema",
                    message="Cannot validate schema without dataset information",
                    suggestion="Provide dataset in metadata for schema validation"
                ))
                return issues

        # Check dataset exists in schema
        datasets = self.schema.get("datasets", {})
        if dataset not in datasets:
            available = list(datasets.keys())[:5]
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="schema",
                message=f"Dataset '{dataset}' not found in S1 schema",
                suggestion=f"Available datasets: {format_field_list(available)}"
            ))
            return issues

        # Get fields for this dataset
        dataset_info = datasets[dataset]
        dataset_fields = dataset_info.get("fields", {})
        common_fields = self.schema.get("common_fields", {})
        all_fields = {**common_fields, **dataset_fields}

        # Validate fields used in query (from metadata)
        if metadata.get("inferred_conditions"):
            for idx, condition in enumerate(metadata["inferred_conditions"]):
                field = condition.get("field")
                if not field:
                    continue

                # Check field exists
                if field not in all_fields:
                    suggestions = suggest_similar_fields(field, list(all_fields.keys()))
                    suggestion_text = f"Did you mean: {', '.join(suggestions)}" if suggestions else f"Available fields: {format_field_list(list(all_fields.keys()))}"

                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        category="schema",
                        message=f"Field '{field}' not found in dataset '{dataset}'",
                        location=f"filter[{idx}]",
                        suggestion=suggestion_text
                    ))
                else:
                    # Validate field data type matches usage
                    field_info = all_fields[field]
                    field_type = field_info.get("data_type", "string")
                    value = condition.get("value")
                    operator = condition.get("operator")

                    # Check numeric fields
                    if field_type == "numeric" and value is not None:
                        try:
                            float(str(value))
                        except (ValueError, TypeError):
                            issues.append(ValidationIssue(
                                severity=ValidationSeverity.WARNING,
                                category="schema",
                                message=f"Field '{field}' expects numeric value, got '{value}'",
                                location=f"filter[{idx}]",
                                suggestion=f"Use numeric value for field '{field}'"
                            ))

                    # Check string operators on numeric fields
                    if field_type == "numeric" and operator in ["contains", "startswith", "endswith"]:
                        issues.append(ValidationIssue(
                            severity=ValidationSeverity.WARNING,
                            category="schema",
                            message=f"String operator '{operator}' used on numeric field '{field}'",
                            location=f"filter[{idx}]",
                            suggestion="Use comparison operators (=, <, >, <=, >=) for numeric fields"
                        ))

        return issues

    def validate_operators(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Validate operators used in query.

        Checks:
        - Operators exist in schema
        - Operators are appropriate for field types
        - Boolean operators are valid (AND, OR)
        """
        issues = []

        # Get operator map from schema
        operator_info = self.schema.get("operators", {})
        operators_list = operator_info.get("operators", [])

        # Build operator map
        valid_operators = set()
        for op in operators_list:
            if isinstance(op, dict):
                name = op.get("name")
                symbols = op.get("symbols", [])
                if name:
                    valid_operators.add(name.lower())
                for symbol in symbols:
                    if isinstance(symbol, str):
                        valid_operators.add(symbol.lower())

        # Validate operators from metadata
        if metadata.get("inferred_conditions"):
            for idx, condition in enumerate(metadata["inferred_conditions"]):
                operator = condition.get("operator")
                if not operator:
                    continue

                # Check operator exists (case-insensitive)
                if operator.lower() not in valid_operators:
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        category="operators",
                        message=f"Operator '{operator}' may not be recognized by S1",
                        location=f"filter[{idx}]",
                        suggestion=f"Common operators: =, <>, >, <, >=, <=, contains, in, between"
                    ))

        # Validate boolean operator
        boolean_op = metadata.get("boolean_operator", "AND")
        if boolean_op not in ["AND", "OR"]:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="operators",
                message=f"Invalid boolean operator '{boolean_op}'",
                suggestion="Use 'AND' or 'OR' to combine conditions"
            ))

        return issues

    def validate_performance(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Detect performance issues in query.

        Checks:
        - Missing event type filters (for datasets that require them)
        - Unbounded queries (no time filter, no limit)
        - Expensive operations (regex, contains on large text fields)
        - Missing matchcase directive on contains
        """
        issues = []

        # Check for event type filters on datasets that need them
        dataset = metadata.get("dataset")
        if dataset and dataset in ["processes", "files", "network_actions"]:
            # Check if event type filter exists
            has_event_filter = False
            if metadata.get("inferred_conditions"):
                for condition in metadata["inferred_conditions"]:
                    field = condition.get("field", "")
                    if condition.get("type") == "event_filter":
                        has_event_filter = True
                        break
                    if "event" in field.lower() and "type" in field.lower():
                        has_event_filter = True
                        break

            if not has_event_filter:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="performance",
                    message=f"Query on '{dataset}' dataset without event type filter may be slow",
                    suggestion=f"Add event type filter for better performance, e.g., EventType in:matchcase ('PROCESSCREATION')"
                ))

        # Check for unbounded queries
        conditions_count = metadata.get("conditions_count")
        if (not conditions_count) and metadata.get("inferred_conditions"):
            inferred = metadata["inferred_conditions"]
            non_event_filters = [
                condition for condition in inferred
                if condition.get("type") != "event_filter"
            ]
            conditions_count = len(non_event_filters)
            if not conditions_count and any(
                condition.get("type") == "event_filter" for condition in inferred
            ):
                # Treat auto-added event filter as at least one condition
                conditions_count = 1

        if not conditions_count:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="performance",
                message="Query has no filters - would return all records",
                suggestion="Add at least one filter condition to narrow results"
            ))

        # Check for time filters
        has_time_filter = any([
            "createdAt" in query,
            "time" in query.lower(),
            "timestamp" in query.lower(),
            "date" in query.lower()
        ])

        if not has_time_filter and conditions_count < 3:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="performance",
                message="Query lacks time-based filtering - may return large result set",
                suggestion="Add time filter to improve performance, e.g., createdAt > '2024-01-01T00:00:00Z'"
            ))

        # Check for unanchored regex
        regex_patterns = re.findall(r'regex\s*\([^)]+\)', query, re.IGNORECASE)
        for pattern in regex_patterns:
            if not ('^' in pattern or '\\A' in pattern):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    category="performance",
                    message="Regex pattern without anchor may be slow",
                    location=pattern[:50],
                    suggestion="Consider anchoring regex with ^ or \\A for better performance"
                ))

        # Check for contains without matchcase
        contains_patterns = re.findall(r'\bcontains\s+(?!matchcase|anycase)\w+', query, re.IGNORECASE)
        if contains_patterns:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="performance",
                message="Using 'contains' without explicit case directive",
                suggestion="Specify matchcase or anycase for clarity: contains matchcase (...)"
            ))

        # Check for IN clauses with many values
        in_clauses = re.findall(r'in\s*:\s*matchcase\s*\([^)]+\)', query, re.IGNORECASE)
        for in_clause in in_clauses:
            # Count comma-separated values
            values_count = in_clause.count(',') + 1
            if values_count > 100:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="performance",
                    message=f"IN clause with {values_count} values may be slow",
                    suggestion="Consider splitting into multiple queries or using alternative filters"
                ))

        return issues

    def validate_best_practices(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Check against S1QL best practices.

        Checks:
        - Using hash fields for IOC searches
        - Field ordering (specific before generic)
        - Using IN instead of multiple OR conditions
        - Case sensitivity considerations
        """
        issues = []

        # Suggest using hash fields for hash values
        hash_patterns = {
            'MD5': re.compile(r'\b[a-f0-9]{32}\b', re.IGNORECASE),
            'SHA1': re.compile(r'\b[a-f0-9]{40}\b', re.IGNORECASE),
            'SHA256': re.compile(r'\b[a-f0-9]{64}\b', re.IGNORECASE),
        }

        for hash_type, pattern in hash_patterns.items():
            if pattern.search(query):
                # Check if using appropriate hash field
                has_hash_field = f"tgt.file.{hash_type.lower()}" in query.lower() or f"{hash_type.lower()}" in query.lower()
                if not has_hash_field:
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.INFO,
                        category="best_practices",
                        message=f"Query contains {hash_type} hash but may not be using dedicated hash field",
                        suggestion=f"Use hash-specific fields like tgt.file.{hash_type.lower()} for better performance"
                    ))

        # Check for multiple OR conditions that could be IN clause
        or_count = len(re.findall(r'\bOR\b', query, re.IGNORECASE))
        if or_count > 3:
            # Check if they're on the same field
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="best_practices",
                message=f"Query uses {or_count} OR operators",
                suggestion="Consider using IN clause if checking same field against multiple values"
            ))

        # Check for case-sensitive searches that might miss results
        equals_without_case = re.findall(r'=\s*[\'"][^\'"]+[\'"]', query)
        if equals_without_case and 'anycase' not in query.lower() and 'matchcase' not in query.lower():
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="best_practices",
                message="Using exact equality without case directive",
                suggestion="Consider if case-insensitive search would be more appropriate"
            ))

        # Suggest using event type filters for better performance
        dataset = metadata.get("dataset")
        if dataset in ["processes", "files"]:
            has_event_type = "eventtype" in query.lower() or "event_type" in query.lower()
            if not has_event_type:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    category="best_practices",
                    message=f"Consider adding event type filter for {dataset} dataset",
                    suggestion="Event type filters significantly improve query performance"
                ))

        return issues

    def _get_additional_metadata(self, query: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Get S1-specific metadata."""
        return {
            "dataset": metadata.get("dataset"),
            "boolean_operator": metadata.get("boolean_operator"),
            "conditions_count": metadata.get("conditions_count", 0),
            "has_time_filter": any(t in query.lower() for t in ["createdat", "timestamp", "time"]),
            "uses_regex": "regex" in query.lower() or "matches" in query.lower(),
            "uses_in_clause": "in:matchcase" in query.lower() or "contains" in query.lower()
        }
