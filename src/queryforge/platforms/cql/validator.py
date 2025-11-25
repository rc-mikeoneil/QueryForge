"""
CrowdStrike Query Language (CQL) Query Validator.

Validates CQL queries for syntax, schema compliance, performance, and best practices.
"""

from __future__ import annotations

import logging
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


# Dangerous characters for CQL queries (security validation)
# Note: '|' is NOT dangerous in CQL - it's the pipe operator for chaining commands
DANGEROUS_CHARS = {';', '\n', '\r', '\t'}

# Performance thresholds
MAX_QUERY_LENGTH = 10000
UNBOUNDED_WARNING_THRESHOLD = 1000

# Common CQL operators and functions
CQL_OPERATORS = {'=', '!=', '>', '>=', '<', '<=', 'contains', 'startswith', 'endswith', 'in()', 'not in', '=~', '!~'}
CQL_FUNCTIONS = {'now', 'hour', 'day', 'week', 'month', 'year', 'in'}

logger = logging.getLogger(__name__)


class CQLValidator(BaseValidator):
    """Validator for CrowdStrike Query Language (CQL)."""

    def __init__(self, schema_loader) -> None:
        """
        Initialize CQL validator.

        Parameters
        ----------
        schema_loader : CQLSchemaLoader
            Schema loader instance for accessing CQL schema definitions.
        """
        self.schema_loader = schema_loader
        # Load schema from schema_loader
        self.schema = {
            "operators": schema_loader.get_operators(),
            "field_types": schema_loader.get_field_types(),
            "best_practices": schema_loader.get_best_practices(),
        }
        
        # Load valid pipeline functions from schema
        self._load_valid_pipeline_functions()
    
    def _load_valid_pipeline_functions(self) -> None:
        """Load valid pipeline functions from the schema."""
        try:
            functions_index = self.schema_loader._load_json("metadata/functions_index.json")
            functions_list = functions_index.get("functions", [])
            
            # Extract function names
            self.valid_pipeline_functions = {func["name"].lower() for func in functions_list if isinstance(func, dict)}
            
            # Add common aliases and legacy operators
            self.valid_pipeline_functions.update({'where', 'limit'})
            
            logger.debug("Loaded %d valid CQL pipeline functions", len(self.valid_pipeline_functions))
        except Exception as exc:
            logger.warning("Failed to load CQL functions from schema, using fallback list: %s", exc)
            # Fallback to basic set if loading fails
            self.valid_pipeline_functions = {
                'select', 'groupby', 'count', 'sort', 'where', 'limit', 'table',
                'stats', 'top', 'head', 'tail', 'timechart', 'bucket', 'join'
            }

    def get_platform_name(self) -> str:
        """Return platform name."""
        return "cql"

    def validate_syntax(self, query: str) -> List[ValidationIssue]:
        """
        Validate CQL query syntax.

        Checks:
        - Query length within limits
        - Balanced quotes (single quotes for CQL)
        - Balanced parentheses
        - Dangerous characters
        - Proper operator syntax
        - Pipeline operator usage
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

        # Check for balanced quotes (CQL uses single quotes)
        quote_issue = check_balanced_quotes(query, "'")
        if quote_issue:
            issues.append(quote_issue)

        # Check for balanced parentheses
        paren_issue = check_balanced_parentheses(query)
        if paren_issue:
            issues.append(paren_issue)

        # Check for dangerous characters
        issues.extend(check_dangerous_characters(query, DANGEROUS_CHARS))

        # Check for proper pipeline syntax (| select, | limit, | stats, | groupBy, etc.)
        pipeline_operators = re.findall(r'\|\s*(\w+)', query)
        for op in pipeline_operators:
            if op.lower() not in self.valid_pipeline_functions:
                # Get a sample of common functions for suggestion
                common_funcs = ['select', 'groupBy', 'count', 'limit', 'stats', 'sort', 'table', 'where']
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="syntax",
                    message=f"Unknown pipeline operator '| {op}'",
                    suggestion=f"Common pipeline operators: {', '.join(common_funcs)}. Check CQL documentation for full list."
                ))

        # Check for potential escape issues with backslashes
        if '\\' in query and '\\\\' not in query:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="syntax",
                message="Query contains single backslashes - CQL may require double backslashes for Windows paths",
                suggestion="Use double backslashes for literal backslashes, e.g., 'C:\\\\Windows\\\\System32'"
            ))

        # Check for SQL-style IN operator (field_name IN (values))
        # This is SQL syntax, not valid CQL syntax which uses in() function
        
        # Process the query line by line for better accuracy
        lines = query.split("\n")
        for i, line in enumerate(lines):
            # Skip lines that are part of CQL in() function syntax
            if "in(" in line.lower() and "values=" in line.lower():
                continue
            
            # Look specifically for SQL-style IN operator
            # Pattern: word boundary + field name + whitespace + IN + whitespace + opening paren
            matches = re.findall(r'\b([a-zA-Z_]\w*)\s+IN\s*\(', line, re.IGNORECASE)
            for field_name in matches:
                # Skip special cases and keywords
                if field_name.lower() in ['processrollup2', 'networkconnectip4', 'in', 'not', 'and', 'or', 'where']:
                    continue
                
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    category="syntax",
                    message=f"SQL-style 'IN' syntax is not valid in CQL: '{field_name} IN (...)'",
                    suggestion=f"Use CQL function syntax instead: in({field_name}, values=[...])"
                ))

        # Validate proper CQL in() function syntax
        cql_in_pattern = re.findall(r'\bin\s*\([^,]+,\s*values\s*=\s*\[[^\]]*\]\)', query, re.IGNORECASE)
        for in_func in cql_in_pattern:
            # Validate that string values in the array are properly quoted
            # Extract the values array
            values_match = re.search(r'values\s*=\s*\[([^\]]*)\]', in_func, re.IGNORECASE)
            if values_match:
                values_str = values_match.group(1)
                # Check for unquoted string values (strings that aren't numbers and aren't quoted)
                # Split by comma and check each value
                values = [v.strip() for v in values_str.split(',')]
                for value in values:
                    # Skip empty values
                    if not value:
                        continue
                    # Check if it's a number (int or float)
                    try:
                        float(value)
                        continue  # It's a number, which is fine unquoted
                    except ValueError:
                        pass
                    # Check if it's properly quoted
                    if not (value.startswith('"') and value.endswith('"')) and \
                       not (value.startswith("'") and value.endswith("'")):
                        # Might be an unquoted string
                        issues.append(ValidationIssue(
                            severity=ValidationSeverity.WARNING,
                            category="syntax",
                            message=f"in() function may have unquoted string value: {value}",
                            suggestion="Ensure string values in in() function are quoted: in(field, values=['val1', 'val2'])"
                        ))
                        break  # Only report once per in() function

        return issues

    def validate_schema(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Validate query against CQL schema.

        Checks:
        - Dataset exists
        - Fields exist in the selected dataset
        - Field data types match usage
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

        # Get fields for this dataset
        fields_data = self.schema_loader.get_fields(dataset)
        available_fields = {f["name"]: f for f in fields_data.get("fields", [])}

        if not available_fields:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="schema",
                message=f"No fields found for dataset '{dataset}'",
                suggestion="Dataset may not be properly configured in schema"
            ))
            return issues

        # Validate fields used in query (from metadata)
        if metadata.get("inferred_conditions"):
            for idx, condition in enumerate(metadata["inferred_conditions"]):
                field = condition.get("field")
                if not field:
                    continue

                # Check field exists
                if field not in available_fields:
                    suggestions = suggest_similar_fields(field, list(available_fields.keys()))
                    suggestion_text = f"Did you mean: {', '.join(suggestions)}" if suggestions else f"Available fields: {format_field_list(list(available_fields.keys()))}"

                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        category="schema",
                        message=f"Field '{field}' not found in dataset '{dataset}'",
                        location=f"filter[{idx}]",
                        suggestion=suggestion_text
                    ))
                else:
                    # Validate field data type matches usage
                    field_info = available_fields[field]
                    field_type = field_info.get("type", "string")
                    value = condition.get("value")
                    operator = condition.get("operator")

                    # Check numeric fields
                    if field_type in ["number", "integer"] and value is not None:
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
                    if field_type in ["number", "integer"] and operator in ["contains", "startswith", "endswith"]:
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

        # Get valid operators from schema
        operators_data = self.schema.get("operators", {})
        operators_list = operators_data.get("operators", [])

        # Build set of valid operators
        valid_operators = set()
        # Handle list structure (CQL uses list of operator objects)
        if isinstance(operators_list, list):
            for op_def in operators_list:
                if isinstance(op_def, dict):
                    # Add the operator symbol
                    op_symbol = op_def.get("operator", "")
                    if op_symbol:
                        valid_operators.add(op_symbol.lower())
                    # Add the operator name
                    op_name = op_def.get("name", "")
                    if op_name:
                        valid_operators.add(op_name.lower())
        # Handle dict structure (legacy support)
        elif isinstance(operators_list, dict):
            for op_name, op_def in operators_list.items():
                if isinstance(op_def, dict):
                    variants = op_def.get("operators", [])
                    normalized = op_def.get("normalized")
                    if normalized:
                        valid_operators.add(normalized.lower())
                    for variant in variants:
                        if isinstance(variant, str):
                            valid_operators.add(variant.lower())

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
                        message=f"Operator '{operator}' may not be recognized by CQL",
                        location=f"filter[{idx}]",
                        suggestion=f"Common operators: =, !=, >, <, >=, <=, contains, startswith, endswith, IN"
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
        - Unbounded queries (no time filter, no limit)
        - Missing time bounds
        - Expensive operations (regex, wildcard)
        - Leading wildcards
        """
        issues = []

        # Check for time filter
        has_time_filter = metadata.get("has_time_filter", False)
        if not has_time_filter:
            has_time_filter = any([
                "@timestamp" in query,
                "time" in query.lower(),
                "now()" in query.lower()
            ])

        if not has_time_filter:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="performance",
                message="Query lacks time-based filtering - may return large result set",
                suggestion="Add time filter to improve performance, e.g., @timestamp >= now() - 24h"
            ))

        # Check for limit clause
        has_limit = "| limit" in query.lower()
        if not has_limit:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="performance",
                message="Query lacks LIMIT clause - may return large result set",
                suggestion="Add | limit N to restrict result size"
            ))

        # Check for unbounded queries
        conditions_count = metadata.get("conditions_count", 0)
        if conditions_count == 0:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="performance",
                message="Query has no filters - would return all records",
                suggestion="Add at least one filter condition to narrow results"
            ))

        # Check for leading wildcards
        leading_wildcard = re.findall(r"=\s*['\"]?\*", query)
        if leading_wildcard:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="performance",
                message="Query uses leading wildcards which prevent index usage",
                suggestion="Avoid patterns like '*value' - use 'value*' or exact matches instead"
            ))

        # Check for broad regex patterns
        regex_patterns = re.findall(r'=~\s*/[^/]+/', query)
        for pattern in regex_patterns:
            if '.*' in pattern:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    category="performance",
                    message="Regex pattern contains .* which may be slow",
                    location=pattern[:50],
                    suggestion="Use more specific patterns or anchor with ^ and $ for better performance"
                ))

        return issues

    def validate_best_practices(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Check against CQL best practices.

        Checks:
        - Using indexed fields
        - Field projection for performance
        - Quoting conventions
        - Time range best practices
        """
        issues = []

        # Check for field projection
        has_projection = metadata.get("has_projection", False) or "| select" in query.lower()
        if not has_projection:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="best_practices",
                message="Query returns all fields - consider projecting only needed fields",
                suggestion="Use | select field1, field2 to limit returned fields for better performance"
            ))

        # Check for proper quoting
        unquoted_values = re.findall(r'=\s+([a-zA-Z0-9_.-]+)\s+(?:AND|OR|$)', query)
        if unquoted_values:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="best_practices",
                message="Query may contain unquoted string values",
                suggestion="Quote string values with single quotes for clarity and correctness"
            ))

        # Suggest using hash fields for hash values
        hash_patterns = {
            'MD5': re.compile(r'\b[a-f0-9]{32}\b', re.IGNORECASE),
            'SHA1': re.compile(r'\b[a-f0-9]{40}\b', re.IGNORECASE),
            'SHA256': re.compile(r'\b[a-f0-9]{64}\b', re.IGNORECASE),
        }

        for hash_type, pattern in hash_patterns.items():
            if pattern.search(query):
                has_hash_field = "file_hash" in query.lower() or hash_type.lower() in query.lower()
                if not has_hash_field:
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.INFO,
                        category="best_practices",
                        message=f"Query contains {hash_type} hash but may not be using dedicated hash field",
                        suggestion=f"Use hash-specific fields like file_hash for better performance"
                    ))

        # Check for multiple OR conditions that could be IN clause
        or_count = len(re.findall(r'\bOR\b', query, re.IGNORECASE))
        if or_count > 3:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="best_practices",
                message=f"Query uses {or_count} OR operators",
                suggestion="Consider using IN clause if checking same field against multiple values"
            ))

        # Check for parentheses with complex boolean logic
        and_count = len(re.findall(r'\bAND\b', query, re.IGNORECASE))
        if or_count > 0 and and_count > 0 and '(' not in query:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="best_practices",
                message="Query mixes AND/OR without parentheses - may have unexpected precedence",
                suggestion="Use parentheses to make boolean logic explicit: (condition1 OR condition2) AND condition3"
            ))

        return issues

    def validate(
        self,
        query: str,
        dataset: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate a CQL query.

        Parameters
        ----------
        query : str
            CQL query string to validate
        dataset : Optional[str]
            Dataset name for schema validation
        metadata : Optional[Dict[str, Any]]
            Query metadata from builder for enhanced validation

        Returns
        -------
        Dict[str, Any]
            Validation results with structure:
            {
                "valid": bool,
                "validation_results": {
                    "syntax": {"errors": [...], "warnings": [...], "info": [...]},
                    "schema": {"errors": [...], "warnings": [...], "info": [...]},
                    "operators": {"errors": [...], "warnings": [...], "info": [...]},
                    "performance": {"errors": [...], "warnings": [...], "info": [...]},
                    "best_practices": {"errors": [...], "warnings": [...], "info": [...]}
                },
                "suggestions": [...]
            }
        """
        if metadata is None:
            metadata = {}
        if dataset:
            metadata["dataset"] = dataset

        # Run all validation checks
        syntax_issues = self.validate_syntax(query)
        schema_issues = self.validate_schema(query, metadata)
        operator_issues = self.validate_operators(query, metadata)
        performance_issues = self.validate_performance(query, metadata)
        best_practice_issues = self.validate_best_practices(query, metadata)

        # Organize by category and severity
        all_issues = (
            syntax_issues + schema_issues + operator_issues +
            performance_issues + best_practice_issues
        )

        validation_results = {
            "syntax": self._categorize_by_severity(syntax_issues),
            "schema": self._categorize_by_severity(schema_issues),
            "operators": self._categorize_by_severity(operator_issues),
            "performance": self._categorize_by_severity(performance_issues),
            "best_practices": self._categorize_by_severity(best_practice_issues),
        }

        # Determine if query is valid (no errors)
        has_errors = any(
            len(category.get("errors", [])) > 0
            for category in validation_results.values()
        )
        valid = not has_errors

        # Collect all suggestions
        suggestions = [
            issue.suggestion for issue in all_issues
            if issue.suggestion and issue.severity in [ValidationSeverity.ERROR, ValidationSeverity.WARNING]
        ]

        return {
            "valid": valid,
            "validation_results": validation_results,
            "suggestions": suggestions,
        }

    def _categorize_by_severity(self, issues: List[ValidationIssue]) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize issues by severity."""
        result = {
            "errors": [],
            "warnings": [],
            "info": []
        }

        for issue in issues:
            issue_dict = {
                "message": issue.message,
                "location": issue.location,
                "suggestion": issue.suggestion,
            }

            if issue.severity == ValidationSeverity.ERROR:
                result["errors"].append(issue_dict)
            elif issue.severity == ValidationSeverity.WARNING:
                result["warnings"].append(issue_dict)
            else:
                result["info"].append(issue_dict)

        return result


def validate_cql_query(
    schema_loader,
    query: str,
    dataset: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Validate a CQL query (convenience function).

    Parameters match CQLValidator.validate() method.
    """
    validator = CQLValidator(schema_loader)
    return validator.validate(query, dataset, metadata)
