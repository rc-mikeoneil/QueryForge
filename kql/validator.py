"""
KQL (Kusto Query Language) Query Validator for Microsoft Defender.

Validates KQL queries for syntax, schema compliance, performance, and best practices.
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


# Dangerous characters and patterns
DANGEROUS_CHARS = {';', '\t'}  # \n and \r are allowed in KQL for multiline queries
SQL_INJECTION_PATTERNS = [
    re.compile(r';\s*(?:drop|delete|update|insert|alter|create|truncate)', re.IGNORECASE),
    re.compile(r';\s*(?:exec|execute)\s+', re.IGNORECASE),
    re.compile(r'union\s+select', re.IGNORECASE),
    re.compile(r'--'),
]

# Performance thresholds
MAX_QUERY_LENGTH = 10000
LARGE_LIMIT_THRESHOLD = 10000

# KQL operators
KQL_OPERATORS = {'==', '!=', '=~', '!~', '>', '<', '>=', '<=', 'contains', 'startswith', 'endswith', 'has', 'in', 'between'}

# KQL clauses (in typical order)
KQL_CLAUSES = ['where', 'summarize', 'extend', 'project', 'join', 'union', 'order', 'limit', 'take', 'top']


class KQLValidator(BaseValidator):
    """Validator for Kusto Query Language (KQL) queries."""

    def get_platform_name(self) -> str:
        """Return platform name."""
        return "kql"

    def validate_syntax(self, query: str) -> List[ValidationIssue]:
        """
        Validate KQL query syntax.

        Checks:
        - Query length within limits
        - Balanced quotes and parentheses
        - Dangerous SQL injection patterns
        - Pipe operator usage
        - Clause ordering
        - Comment syntax
        """
        issues = []

        # Check query length
        if len(query) > MAX_QUERY_LENGTH:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="syntax",
                message=f"Query exceeds maximum length of {MAX_QUERY_LENGTH} characters ({len(query)} chars)",
                suggestion="Simplify the query or break it into multiple queries"
            ))

        # Check for balanced quotes (KQL uses single and double quotes)
        single_quote_issue = check_balanced_quotes(query, "'")
        if single_quote_issue:
            issues.append(single_quote_issue)

        double_quote_issue = check_balanced_quotes(query, '"')
        if double_quote_issue:
            issues.append(double_quote_issue)

        # Check for balanced parentheses
        paren_issue = check_balanced_parentheses(query)
        if paren_issue:
            issues.append(paren_issue)

        # Check for SQL injection patterns
        for pattern in SQL_INJECTION_PATTERNS:
            if pattern.search(query):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    category="syntax",
                    message="Query contains potentially dangerous SQL injection pattern",
                    suggestion="Remove SQL injection attempts from the query"
                ))

        # Check for dangerous standalone semicolons
        dangerous_semicolons = check_dangerous_characters(query, {';'})
        if dangerous_semicolons:
            issues.extend(dangerous_semicolons)

        # Validate pipe operators
        pipes = query.count('|')
        if pipes == 0:
            # KQL query without pipes is unusual (just table name?)
            if len(query.strip()) > 50:  # If it's more than just a table name
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="syntax",
                    message="KQL query without pipe operators is unusual",
                    suggestion="Use pipe (|) to chain KQL operators: TableName | where ..."
                ))

        # Check for proper clause ordering
        clause_positions = {}
        for clause in KQL_CLAUSES:
            # Find all occurrences of this clause
            pattern = re.compile(r'\|\s*' + clause + r'\b', re.IGNORECASE)
            matches = list(pattern.finditer(query))
            if matches:
                clause_positions[clause] = [m.start() for m in matches]

        # Validate typical ordering: where before summarize, summarize before project (if both exist)
        if 'where' in clause_positions and 'summarize' in clause_positions:
            last_where = max(clause_positions['where'])
            first_summarize = min(clause_positions['summarize'])
            if last_where > first_summarize:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="syntax",
                    message="'where' clause appears after 'summarize' - this is unusual and may be inefficient",
                    suggestion="Typically, filter with 'where' before aggregating with 'summarize'"
                ))

        # Check for malformed comments
        block_comments = re.findall(r'/\*', query)
        block_comment_closes = re.findall(r'\*/', query)
        if len(block_comments) != len(block_comment_closes):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="syntax",
                message="Unbalanced block comments (/* ... */)",
                suggestion="Ensure all /* have matching */"
            ))

        return issues

    def validate_schema(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Validate query against KQL schema.

        Checks:
        - Table exists in schema
        - Columns exist in table
        - Column usage is appropriate
        """
        issues = []

        # Get table from metadata
        table = metadata.get("table")
        if not table:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="schema",
                message="Cannot validate schema without table information",
                suggestion="Provide table name in metadata for schema validation"
            ))
            return issues

        # Check table exists in schema
        if table not in self.schema:
            available_tables = list(self.schema.keys())[:10]
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="schema",
                message=f"Table '{table}' not found in KQL schema",
                suggestion=f"Available tables: {format_field_list(available_tables)}"
            ))
            return issues

        # Get columns for this table
        table_schema = self.schema[table]
        columns_list = table_schema.get("columns", [])
        valid_columns = {col["name"] for col in columns_list if isinstance(col, dict) and "name" in col}

        # Extract column references from query
        # This is a simple heuristic - just look for identifiers that might be columns
        # More sophisticated parsing would be needed for complete validation

        # Look for columns in where clauses
        where_clauses = re.findall(r'\|\s*where\s+([^|]+)', query, re.IGNORECASE)
        for where_clause in where_clauses:
            # Extract potential column names (before operators)
            potential_columns = re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:==|!=|=~|!~|>|<|>=|<=|contains|startswith|endswith|has|in)', where_clause, re.IGNORECASE)
            for col in potential_columns:
                if col.lower() not in {'and', 'or', 'not', 'in'}:  # Filter out keywords
                    if col not in valid_columns:
                        suggestions = suggest_similar_fields(col, list(valid_columns))
                        suggestion_text = f"Did you mean: {', '.join(suggestions)}" if suggestions else f"Available columns: {format_field_list(list(valid_columns))}"

                        issues.append(ValidationIssue(
                            severity=ValidationSeverity.WARNING,
                            category="schema",
                            message=f"Column '{col}' may not exist in table '{table}'",
                            location=f"where clause",
                            suggestion=suggestion_text
                        ))

        # Look for columns in project clauses
        project_clauses = re.findall(r'\|\s*project\s+([^|]+)', query, re.IGNORECASE)
        for project_clause in project_clauses:
            # Split by comma to get individual columns
            columns = [c.strip() for c in project_clause.split(',')]
            for col in columns:
                # Remove any aliases (e.g., "NewName = OldColumn")
                col_name = col.split('=')[-1].strip()
                # Remove function calls
                if '(' in col_name:
                    continue

                if col_name and col_name not in valid_columns and col_name != '*':
                    suggestions = suggest_similar_fields(col_name, list(valid_columns))
                    suggestion_text = f"Did you mean: {', '.join(suggestions)}" if suggestions else ""

                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        category="schema",
                        message=f"Column '{col_name}' may not exist in table '{table}'",
                        location="project clause",
                        suggestion=suggestion_text
                    ))

        return issues

    def validate_operators(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Validate operators used in query.

        Checks:
        - Operators are valid KQL operators
        - Operator usage is appropriate (case sensitivity, etc.)
        """
        issues = []

        # Extract operators from where clauses
        where_patterns = re.findall(r'([A-Za-z_][A-Za-z0-9_]*)\s+(==|!=|=~|!~|>|<|>=|<=|contains|startswith|endswith|has|in|between)\s+', query, re.IGNORECASE)

        for field, operator in where_patterns:
            # Check if operator is valid
            if operator.lower() not in KQL_OPERATORS:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="operators",
                    message=f"Operator '{operator}' may not be a standard KQL operator",
                    suggestion=f"Common KQL operators: {', '.join(sorted(KQL_OPERATORS))}"
                ))

            # Suggest case-insensitive operators for string comparisons
            if operator == '==' and not any(func in query for func in ['tolower(', 'toupper(']):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    category="operators",
                    message=f"Using case-sensitive operator '==' on field '{field}'",
                    suggestion="Consider using '=~' for case-insensitive string comparison"
                ))

        return issues

    def validate_performance(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Detect performance issues in query.

        Checks:
        - Missing time filters
        - Large or unbounded limits
        - Expensive operations
        - Full table scans
        """
        issues = []

        # Check for time filters
        has_time_filter = any([
            "Timestamp" in query,
            "TimeGenerated" in query,
            "ago(" in query,
            "between(" in query and "datetime" in query,
            metadata.get("time_window") is not None,
            metadata.get("has_timestamp") is True
        ])

        if not has_time_filter:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="performance",
                message="Query lacks time-based filtering - may scan large amounts of data",
                suggestion="Add Timestamp or TimeGenerated filter: | where Timestamp > ago(7d)"
            ))

        # Check for limit/take clauses
        has_limit = bool(re.search(r'\|\s*(?:limit|take|top)\s+\d+', query, re.IGNORECASE))
        limit_match = re.search(r'\|\s*(?:limit|take|top)\s+(\d+)', query, re.IGNORECASE)

        if limit_match:
            limit_value = int(limit_match.group(1))
            if limit_value > LARGE_LIMIT_THRESHOLD:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="performance",
                    message=f"Query requests {limit_value} results - this may be slow",
                    suggestion="Consider reducing the limit or adding more specific filters"
                ))
        elif not has_limit:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="performance",
                message="Query has no limit clause - may return large result set",
                suggestion="Add | limit N to control result size"
            ))

        # Check for summarize without time binning on large time ranges
        if 'summarize' in query.lower() and not has_time_filter:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="performance",
                message="Summarizing data without time filter may be slow",
                suggestion="Add time filter and consider using bin() for time aggregation"
            ))

        # Check for contains without other filters (potentially expensive)
        contains_count = len(re.findall(r'\bcontains\b', query, re.IGNORECASE))
        where_count = len(re.findall(r'\|\s*where\b', query, re.IGNORECASE))

        if contains_count > 0 and where_count == contains_count:
            # Only using contains, no other filters
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="performance",
                message="Using 'contains' without additional filters may be slow",
                suggestion="Add more specific filters to narrow the search"
            ))

        # Check for regex operators (potentially expensive)
        if 'matches regex' in query.lower():
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="performance",
                message="Regex matching can be expensive on large datasets",
                suggestion="Use simpler operators like 'contains' or 'startswith' if possible"
            ))

        return issues

    def validate_best_practices(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Check against KQL best practices.

        Checks:
        - Filter early (where before project/extend)
        - Use indexed columns for filtering
        - Appropriate aggregation functions
        - Proper time windowing
        """
        issues = []

        # Check for project before where (inefficient)
        project_pos = query.lower().find('| project')
        where_pos = query.lower().find('| where')

        if project_pos != -1 and where_pos != -1 and project_pos < where_pos:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="best_practices",
                message="'project' appears before 'where' - this is inefficient",
                suggestion="Filter data with 'where' before projecting columns for better performance"
            ))

        # Check for select * equivalent (no project clause)
        has_project = '| project' in query.lower()
        if not has_project and len(query) > 100:  # Not just a simple table query
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="best_practices",
                message="Query returns all columns - consider projecting only needed columns",
                suggestion="Use | project Col1, Col2, ... to select specific columns"
            ))

        # Check for appropriate time filtering
        table = metadata.get("table")
        if table and any(keyword in table for keyword in ["Device", "Email", "Alert", "Event"]):
            has_time_filter = "Timestamp" in query or "ago(" in query or metadata.get("has_timestamp")
            if not has_time_filter:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    category="best_practices",
                    message=f"Table '{table}' typically requires time-based filtering",
                    suggestion="Add time filter: | where Timestamp > ago(7d)"
                ))

        # Suggest using has instead of contains for token matching
        if 'contains' in query.lower() and 'has' not in query.lower():
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="best_practices",
                message="Consider using 'has' operator for whole-word matching",
                suggestion="'has' is faster than 'contains' for exact token matches"
            ))

        # Check for summarize without bin() on time fields
        if 'summarize' in query.lower() and ('Timestamp' in query or 'TimeGenerated' in query):
            if 'bin(' not in query.lower():
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    category="best_practices",
                    message="Summarizing time-series data without bin() function",
                    suggestion="Use bin(Timestamp, 1h) to group by time intervals"
                ))

        return issues

    def _calculate_complexity(self, query: str, metadata: Dict[str, Any]) -> int:
        """Calculate KQL query complexity (1-10)."""
        score = 1

        # Count pipe operators (each operation adds complexity)
        pipe_count = query.count('|')
        score += min(pipe_count // 2, 3)

        # Count joins (expensive operations)
        join_count = len(re.findall(r'\|\s*join\b', query, re.IGNORECASE))
        score += join_count * 2

        # Count summarize operations
        summarize_count = len(re.findall(r'\|\s*summarize\b', query, re.IGNORECASE))
        score += summarize_count

        # Add complexity for regex
        if 'matches regex' in query.lower():
            score += 2

        # Add for subqueries
        if query.count('|') > 5:
            score += 1

        return min(score, 10)

    def _estimate_result_size(self, query: str, metadata: Dict[str, Any]) -> str:
        """Estimate result set size for KQL query."""
        # Check for explicit limit
        limit_match = re.search(r'\|\s*(?:limit|take|top)\s+(\d+)', query, re.IGNORECASE)
        if limit_match:
            limit = int(limit_match.group(1))
            if limit <= 100:
                return "small"
            elif limit <= 1000:
                return "medium"
            else:
                return "large"

        # Check for summarize (typically reduces result size)
        if '| summarize' in query.lower():
            return "medium"

        # Check for time filter + other conditions
        has_time_filter = "Timestamp" in query or "ago(" in query or metadata.get("has_timestamp")
        where_count = len(re.findall(r'\|\s*where\b', query, re.IGNORECASE))

        if has_time_filter and where_count >= 2:
            return "medium"
        elif has_time_filter or where_count >= 1:
            return "large"
        else:
            return "unbounded"

    def _get_additional_metadata(self, query: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Get KQL-specific metadata."""
        return {
            "table": metadata.get("table"),
            "time_window": metadata.get("time_window"),
            "has_time_filter": "Timestamp" in query or "ago(" in query or metadata.get("has_timestamp"),
            "has_limit": bool(re.search(r'\|\s*(?:limit|take|top)\s+\d+', query, re.IGNORECASE)),
            "pipe_count": query.count('|'),
            "has_summarize": '| summarize' in query.lower(),
            "has_join": '| join' in query.lower()
        }
