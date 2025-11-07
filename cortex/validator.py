"""
Cortex XDR (XQL) Query Validator.

Validates Cortex XQL queries for syntax, schema compliance, performance, and best practices.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from shared.validation import (
    BaseValidator,
    ValidationIssue,
    ValidationSeverity,
    check_balanced_quotes,
    check_balanced_parentheses,
    check_dangerous_characters,
    suggest_similar_fields,
    format_field_list,
)


# Dangerous characters for XQL queries
DANGEROUS_CHARS = {';', '\r', '\t'}  # \n is allowed for multiline queries

# Performance thresholds
MAX_QUERY_LENGTH = 10000
LARGE_LIMIT_THRESHOLD = 5000

# XQL stages in typical order
XQL_STAGES = ['dataset', 'filter', 'fields', 'alter', 'join', 'union', 'sort', 'limit', 'comp']

# XQL operators
XQL_OPERATORS = {'=', '!=', '<', '>', '<=', '>=', 'in', 'contains', 'matches', 'not in'}


class CortexValidator(BaseValidator):
    """Validator for Cortex XDR XQL queries."""

    def get_platform_name(self) -> str:
        """Return platform name."""
        return "cortex"

    def validate_syntax(self, query: str) -> List[ValidationIssue]:
        """
        Validate XQL query syntax.

        Checks:
        - Query length within limits
        - Balanced quotes and parentheses
        - Dangerous characters
        - XQL stage ordering (dataset → filter → fields → limit)
        - Pipe operator usage
        - Function syntax
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

        # Check for balanced quotes (XQL uses double quotes for strings)
        double_quote_issue = check_balanced_quotes(query, '"')
        if double_quote_issue:
            issues.append(double_quote_issue)

        # Check for balanced parentheses
        paren_issue = check_balanced_parentheses(query)
        if paren_issue:
            issues.append(paren_issue)

        # Check for dangerous characters
        issues.extend(check_dangerous_characters(query, DANGEROUS_CHARS))

        # Check for pipe operators
        pipes = query.count('|')
        if pipes == 0:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="syntax",
                message="XQL query without pipe operators - may be incomplete",
                suggestion="XQL queries typically use pipes: dataset = xdr_data | filter ..."
            ))

        # Validate XQL stage ordering
        stage_positions = {}
        for stage in XQL_STAGES:
            # Find all occurrences of this stage
            pattern = re.compile(r'\|\s*' + stage + r'\b', re.IGNORECASE)
            matches = list(pattern.finditer(query))
            if matches:
                stage_positions[stage] = [m.start() for m in matches]

        # Check critical ordering: dataset should be first
        if 'dataset' in stage_positions and stage_positions['dataset'][0] > 0:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="syntax",
                message="'dataset' clause should typically be at the start of the query",
                suggestion="Start query with: dataset = xdr_data | ..."
            ))

        # Check filter before fields
        if 'filter' in stage_positions and 'fields' in stage_positions:
            last_filter = max(stage_positions['filter'])
            first_fields = min(stage_positions['fields'])
            if last_filter > first_fields:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="syntax",
                    message="'filter' appears after 'fields' - this may be inefficient",
                    suggestion="Apply filters before selecting fields for better performance"
                ))

        # Check limit is near the end
        if 'limit' in stage_positions and 'fields' in stage_positions:
            last_limit = max(stage_positions['limit'])
            last_fields = max(stage_positions['fields'])
            if last_limit < last_fields:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    category="syntax",
                    message="'limit' appears before 'fields' - this is unusual",
                    suggestion="Typically limit is applied after field selection"
                ))

        # Check for assignment operator (=) usage
        if ' = ' in query and 'dataset' not in query:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="syntax",
                message="Query uses assignment operator (=) but doesn't specify dataset",
                suggestion="Ensure query starts with: dataset = xdr_data"
            ))

        return issues

    def validate_schema(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Validate query against Cortex schema.

        Checks:
        - Dataset exists
        - Fields exist in the selected dataset
        - Enum values are properly prefixed
        """
        issues = []

        # Get dataset from metadata
        dataset = metadata.get("dataset")
        if not dataset:
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
            available = list(datasets.keys())
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="schema",
                message=f"Dataset '{dataset}' not found in Cortex schema",
                suggestion=f"Available datasets: {format_field_list(available)}"
            ))
            return issues

        # Get fields for this dataset
        field_map_key = f"{dataset}_fields"
        field_map = self.schema.get(field_map_key, {})
        valid_fields = set(field_map.keys())

        # Validate fields used in query (from metadata)
        if metadata.get("recognised"):
            for idx, item in enumerate(metadata["recognised"]):
                field = item.get("field")
                if not field:
                    continue

                # Check field exists
                if field not in valid_fields:
                    suggestions = suggest_similar_fields(field, list(valid_fields))
                    suggestion_text = f"Did you mean: {', '.join(suggestions)}" if suggestions else f"Available fields: {format_field_list(list(valid_fields))}"

                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        category="schema",
                        message=f"Field '{field}' may not exist in dataset '{dataset}'",
                        location=f"filter[{idx}]",
                        suggestion=suggestion_text
                    ))
                else:
                    # Check enum fields have proper prefix
                    field_info = field_map[field]
                    field_type = field_info.get("type", "")

                    if "enum" in field_type.lower():
                        value = item.get("value")
                        if value and not str(value).startswith("ENUM."):
                            issues.append(ValidationIssue(
                                severity=ValidationSeverity.WARNING,
                                category="schema",
                                message=f"Enum field '{field}' value should use ENUM. prefix",
                                location=f"filter[{idx}]",
                                suggestion=f"Use: {field} = ENUM.{value}"
                            ))

        return issues

    def validate_operators(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Validate operators used in query.

        Checks:
        - Operators are valid XQL operators
        - Operator usage is appropriate for field types
        """
        issues = []

        # Validate operators from metadata
        if metadata.get("recognised"):
            for idx, item in enumerate(metadata["recognised"]):
                operator = item.get("operator")
                if not operator:
                    continue

                # Check operator is valid
                if operator not in XQL_OPERATORS:
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        category="operators",
                        message=f"Operator '{operator}' may not be a standard XQL operator",
                        location=f"filter[{idx}]",
                        suggestion=f"Common XQL operators: {', '.join(sorted(XQL_OPERATORS))}"
                    ))

        # Check for case sensitivity issues
        if '=' in query and 'contains' not in query.lower():
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="operators",
                message="Using exact equality (=) - XQL is case-sensitive",
                suggestion="Consider using 'contains' for case-insensitive partial matches"
            ))

        return issues

    def validate_performance(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Detect performance issues in query.

        Checks:
        - Missing dataset filters
        - Unbounded queries
        - Missing time filters
        - Excessive field selection
        - Large limits
        """
        issues = []

        # Check for dataset specification
        if 'dataset' not in query.lower():
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="performance",
                message="Query missing dataset specification",
                suggestion="Start query with: dataset = xdr_data | ..."
            ))

        # Check for time filters
        has_time_filter = any([
            "_time" in query,
            "action_local_time" in query,
            "current_time()" in query,
            "interval" in query.lower(),
            metadata.get("has_time_filter")
        ])

        if not has_time_filter:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="performance",
                message="Query lacks time-based filtering - may scan large amounts of data",
                suggestion="Add time filter: | filter _time > current_time() - interval '1 hour'"
            ))

        # Check for limit clause
        limit = metadata.get("limit")
        if not limit:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="performance",
                message="Query has no limit - may return large result set",
                suggestion="Add | limit N to control result size"
            ))
        elif limit > LARGE_LIMIT_THRESHOLD:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="performance",
                message=f"Query requests {limit} results - this may be slow",
                suggestion="Consider reducing the limit or adding more specific filters"
            ))

        # Check for contains operations without other filters
        contains_count = len(re.findall(r'\bcontains\b', query, re.IGNORECASE))
        filter_count = len(re.findall(r'\|\s*filter\b', query, re.IGNORECASE))

        if contains_count > 0 and filter_count == 1:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="performance",
                message="Using 'contains' as the only filter may be slow",
                suggestion="Add more specific filters to narrow the search"
            ))

        # Check for regex operations
        if 'matches' in query.lower():
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="performance",
                message="Regex matching (matches) can be expensive on large datasets",
                suggestion="Use simpler operators like 'contains' or '=' when possible"
            ))

        # Check number of fields being selected
        fields = metadata.get("fields")
        if fields and len(fields) > 20:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="performance",
                message=f"Selecting {len(fields)} fields may impact performance",
                suggestion="Select only necessary fields to improve query performance"
            ))

        return issues

    def validate_best_practices(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Check against Cortex XQL best practices.

        Checks:
        - Using appropriate datasets
        - Field selection practices
        - Time-based queries
        - Proper function usage
        """
        issues = []

        # Check for field selection
        has_fields = '| fields' in query.lower()
        if not has_fields and len(query) > 100:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="best_practices",
                message="Query returns all fields - consider selecting specific fields",
                suggestion="Use | fields field1, field2, ... to select needed columns"
            ))

        # Suggest using default fields
        dataset = metadata.get("dataset")
        if dataset:
            datasets_info = self.schema.get("datasets", {})
            dataset_info = datasets_info.get(dataset, {})
            default_fields = dataset_info.get("default_fields", [])

            if default_fields and not has_fields:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    category="best_practices",
                    message=f"Dataset '{dataset}' has recommended default fields",
                    suggestion=f"Consider using: | fields {', '.join(default_fields[:5])}"
                ))

        # Check for time-based analysis
        has_time_filter = metadata.get("has_time_filter", False)
        if dataset == "xdr_data" and not has_time_filter:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="best_practices",
                message="Querying xdr_data without time filter is not recommended",
                suggestion="Add time filter to improve performance and relevance"
            ))

        # Suggest using enum prefixes
        if '=' in query and 'ENUM.' not in query:
            # Check if any enum fields might be in use
            recognised = metadata.get("recognised", [])
            for item in recognised:
                field = item.get("field", "")
                if field and any(enum_keyword in field.lower() for enum_keyword in ['type', 'category', 'action', 'status']):
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.INFO,
                        category="best_practices",
                        message=f"Field '{field}' may be an enum field",
                        suggestion="Use ENUM. prefix for enum values: field = ENUM.VALUE"
                    ))
                    break

        # Check for proper filter ordering (specific before generic)
        if '| filter' in query:
            # Look for contains after exact matches
            filters = re.findall(r'\|\s*filter\s+([^|]+)', query, re.IGNORECASE)
            for idx, filter_clause in enumerate(filters):
                if 'contains' in filter_clause and idx > 0:
                    prev_filter = filters[idx-1]
                    if '=' in prev_filter and 'contains' not in prev_filter:
                        # Good - exact match before contains
                        pass
                    else:
                        issues.append(ValidationIssue(
                            severity=ValidationSeverity.INFO,
                            category="best_practices",
                            message="Consider placing exact-match filters before 'contains' filters",
                            suggestion="Order filters from most to least specific for better performance"
                        ))
                        break

        return issues

    def _calculate_complexity(self, query: str, metadata: Dict[str, Any]) -> int:
        """Calculate Cortex XQL query complexity (1-10)."""
        score = 1

        # Add points for filters
        filter_count = len(re.findall(r'\|\s*filter\b', query, re.IGNORECASE))
        score += min(filter_count // 2, 3)

        # Add points for joins
        join_count = len(re.findall(r'\|\s*join\b', query, re.IGNORECASE))
        score += join_count * 2

        # Add points for complex operations
        if 'matches' in query.lower():
            score += 2

        if 'alter' in query.lower():
            score += 1

        # Add for number of fields
        fields = metadata.get("fields", [])
        if len(fields) > 10:
            score += 1

        return min(score, 10)

    def _estimate_result_size(self, query: str, metadata: Dict[str, Any]) -> str:
        """Estimate result set size for Cortex XQL query."""
        # Check for explicit limit
        limit = metadata.get("limit")
        if limit:
            if limit <= 100:
                return "small"
            elif limit <= 1000:
                return "medium"
            else:
                return "large"

        # Check for time filter + other conditions
        has_time_filter = "_time" in query or "current_time()" in query
        filter_count = len(re.findall(r'\|\s*filter\b', query, re.IGNORECASE))

        if has_time_filter and filter_count >= 2:
            return "medium"
        elif has_time_filter or filter_count >= 1:
            return "large"
        else:
            return "unbounded"

    def _get_additional_metadata(self, query: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Get Cortex-specific metadata."""
        return {
            "dataset": metadata.get("dataset"),
            "has_time_filter": "_time" in query or "current_time()" in query,
            "has_limit": "| limit" in query.lower(),
            "filter_count": len(re.findall(r'\|\s*filter\b', query, re.IGNORECASE)),
            "has_join": "| join" in query.lower(),
            "field_count": len(metadata.get("fields", [])),
            "uses_contains": "contains" in query.lower(),
            "uses_regex": "matches" in query.lower()
        }
