"""
Carbon Black Response (CBR) Query Validator.

Validates CBR queries for syntax, schema compliance, performance, and best practices.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from shared.validation import (
    BaseValidator,
    ValidationIssue,
    ValidationSeverity,
    check_dangerous_characters,
    suggest_similar_fields,
    format_field_list,
)


# Dangerous characters for CBR queries (security validation)
DANGEROUS_CHARS = {';', '|', '(', ')', '{', '}', '\n', '\r', '\t'}

# Performance thresholds
MAX_QUERY_LENGTH = 10000
MAX_TERMS = 100
MAX_LIMIT = 5000


class CBRValidator(BaseValidator):
    """Validator for Carbon Black Response queries."""

    def get_platform_name(self) -> str:
        """Return platform name."""
        return "cbr"

    def validate_syntax(self, query: str) -> List[ValidationIssue]:
        """
        Validate CBR query syntax.

        Checks:
        - Query length within limits
        - Dangerous characters
        - Field:value format
        - Boolean operator usage
        - Proper quoting
        - Backslash escaping
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

        # Split query by boolean operators to analyze terms
        terms = []
        if ' AND ' in query:
            terms = [t.strip() for t in query.split(' AND ')]
        elif ' OR ' in query:
            terms = [t.strip() for t in query.split(' OR ')]
        else:
            terms = [query.strip()]

        for idx, term in enumerate(terms):
            if not term:
                continue

            # Check if term has field:value format or is just a keyword
            if ':' in term:
                # Field-based search - validate format
                # Check for double colons or other malformed syntax
                if '::' in term or not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*:[^:]+$', term):
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
                            suggestion='Quote values with spaces: field:"value with spaces"'
                        ))

            # Check for unescaped backslashes (Windows paths)
            if '\\' in term and '\\\\' not in term:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="syntax",
                    message="Term contains single backslashes - may need escaping for Windows paths",
                    location=f"term[{idx}]",
                    suggestion="Escape backslashes in Windows paths: C:\\\\Windows\\\\System32"
                ))

        # Check boolean operator casing
        if ' and ' in query or ' or ' in query:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="syntax",
                message="Boolean operators should be uppercase in CBR queries",
                suggestion="Use 'AND' instead of 'and', 'OR' instead of 'or'"
            ))

        return issues

    def validate_schema(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Validate query against CBR schema.

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
                message=f"Search type '{search_type}' not found in CBR schema",
                suggestion=f"Available search types: {format_field_list(available)}"
            ))
            return issues

        # Get field map for this search type
        # Server events and endpoint events have merged field sets
        if search_type == "server_event":
            field_map = {}
            # Merge all server event field sets
            for key in self.schema.keys():
                if key.endswith("_fields") and "server" in key.lower():
                    field_map.update(self.schema.get(key, {}))
        elif search_type == "endpoint_event":
            field_map = {}
            # Merge all endpoint event field sets
            for key in self.schema.keys():
                if key.endswith("_fields") and "endpoint" in key.lower():
                    field_map.update(self.schema.get(key, {}))
        else:
            # Granular field set
            field_map_key = f"{search_type}_fields"
            field_map = self.schema.get(field_map_key, {})

        if not field_map:
            # Try to get field map directly
            field_map = self.schema.get("fields", {})

        valid_fields = set(field_map.keys()) if field_map else set()

        # Validate fields used in query (from metadata's recognised list)
        if metadata.get("recognised"):
            for idx, item in enumerate(metadata["recognised"]):
                # Check if this is a structured field search
                field = item.get("field")
                if field and field not in valid_fields:
                    # Get suggestions for typos
                    suggestions = suggest_similar_fields(field, list(valid_fields))
                    suggestion_text = f"Did you mean: {', '.join(suggestions)}" if suggestions else f"Available fields: {format_field_list(list(valid_fields)[:10])}"

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

        CBR uses simple field:value syntax and Boolean operators (AND, OR).
        No inequality operators are supported.
        """
        issues = []

        # Check boolean operator
        boolean_op = metadata.get("boolean_operator", "AND")
        if boolean_op not in ["AND", "OR"]:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="operators",
                message=f"Invalid boolean operator '{boolean_op}'",
                suggestion="CBR supports only AND and OR operators"
            ))

        # Check for unsupported operators
        # CBR does not support inequality operators
        unsupported_patterns = ['!=', '<>', '<', '>', '<=', '>=', '~=']
        for op in unsupported_patterns:
            if op in query:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="operators",
                    message=f"Operator '{op}' is not supported in CBR queries",
                    suggestion="CBR uses field:value syntax; use wildcards (*) for partial matches"
                ))

        # Validate wildcard usage
        if '*' in query:
            # Check for wildcards in inappropriate contexts
            wildcard_terms = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*:\*', query)
            if wildcard_terms:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    category="operators",
                    message="Wildcard-only values may return very broad results",
                    suggestion="Use wildcards with partial values (e.g., process_name:*chrome*)"
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
        - Excessive result limits
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
        structured_count = sum(1 for item in recognised if item.get("field"))
        keyword_count = len(recognised) - structured_count

        if keyword_count > 0 and structured_count == 0:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="performance",
                message="Query uses only keyword searches without specific field filters",
                suggestion="Add field-specific searches (e.g., md5:, process_name:) for better performance"
            ))

        if keyword_count > structured_count and keyword_count > 2:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="performance",
                message=f"Query has more keywords ({keyword_count}) than structured searches ({structured_count})",
                suggestion="Structured field searches are faster and more precise than keyword searches"
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

        # Check for leading wildcards (especially slow)
        if re.search(r':\*[^*\s]', query) or re.search(r':"\*[^*"]+', query):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="performance",
                message="Leading wildcards (*value) are particularly slow",
                suggestion="Avoid wildcards at the start of search terms if possible"
            ))

        # Check limit
        limit = metadata.get("limit")
        if limit:
            if limit > MAX_LIMIT:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    category="performance",
                    message=f"Query requests {limit} results (CBR max is {MAX_LIMIT})",
                    suggestion=f"Limit will be clamped to {MAX_LIMIT}"
                ))
            if limit > 1000:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    category="performance",
                    message=f"Query requests {limit} results - large result sets may be slow",
                    suggestion="Consider using a smaller limit or adding more specific filters"
                ))

        # Warn on overly broad queries
        if structured_count == 0 and keyword_count <= 1:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="performance",
                message="Query is very broad and may return a large number of results",
                suggestion="Add more specific field filters to narrow the search"
            ))

        return issues

    def validate_best_practices(self, query: str, metadata: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Check against CBR best practices.

        Checks:
        - Using hash fields for IOC searches
        - Structured searches over keywords
        - Appropriate field selection for network events
        - Dataset selection recommendations
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
                hash_field_pattern = f"{hash_type.lower()}:"
                parent_hash_pattern = f"parent_{hash_type.lower()}:"
                process_hash_pattern = f"process_{hash_type.lower()}:"
                
                has_hash_field = any([
                    hash_field_pattern in query.lower(),
                    parent_hash_pattern in query.lower(),
                    process_hash_pattern in query.lower()
                ])
                
                if not has_hash_field:
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.INFO,
                        category="best_practices",
                        message=f"Query contains {hash_type} hash but may not be using dedicated hash field",
                        suggestion=f"Use hash fields like md5:, process_md5:, or parent_md5: for {hash_type} hashes"
                    ))

        # Suggest using structured searches over keywords
        recognised = metadata.get("recognised", [])
        structured_count = sum(1 for item in recognised if item.get("field"))
        keyword_count = len(recognised) - structured_count

        if keyword_count > structured_count and keyword_count > 2:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="best_practices",
                message=f"Query uses {keyword_count} keywords vs {structured_count} structured searches",
                suggestion="Structured field searches (field:value) are faster and more accurate than keyword searches"
            ))

        # Check for IP addresses not using appropriate field
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        if ip_pattern.search(query):
            has_ip_field = any([
                'ipv4:' in query.lower(),
                'remote_ip:' in query.lower(),
                'local_ip:' in query.lower(),
                'proxy_ip:' in query.lower()
            ])
            if not has_ip_field:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    category="best_practices",
                    message="Query contains IP addresses - consider using specific IP fields",
                    suggestion="Use ipv4:, remote_ip:, local_ip:, or proxy_ip: for better performance"
                ))

        # Check for domains not using domain field
        domain_pattern = re.compile(r'\b[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}\b', re.IGNORECASE)
        if domain_pattern.search(query):
            has_domain_field = any([
                'domain:' in query.lower(),
                'proxy_domain:' in query.lower()
            ])
            if not has_domain_field:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    category="best_practices",
                    message="Query contains domain names - consider using domain field",
                    suggestion="Use domain: or proxy_domain: for better performance on domain searches"
                ))

        # Suggest appropriate dataset based on query content
        search_type = metadata.get("search_type")
        
        # Check for network-related fields suggesting endpoint_event dataset
        network_fields = ['remote_ip', 'remote_port', 'local_ip', 'local_port', 'domain', 'ipv4']
        has_network_fields = any(f"{field}:" in query.lower() for field in network_fields)
        
        if has_network_fields and search_type != "endpoint_event":
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="best_practices",
                message="Query uses network-related fields - endpoint_event dataset may be more appropriate",
                suggestion="Consider using endpoint_event dataset for network connection queries"
            ))

        # Check for process fields suggesting server_event or endpoint_event
        process_fields = ['process_name', 'process_md5', 'parent_name', 'parent_md5', 'cmdline']
        has_process_fields = any(f"{field}:" in query.lower() for field in process_fields)
        
        if has_process_fields and search_type not in ["server_event", "endpoint_event"]:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                category="best_practices",
                message="Query uses process-related fields",
                suggestion="Consider using server_event or endpoint_event dataset for process queries"
            ))

        return issues

    def _calculate_complexity(self, query: str, metadata: Dict[str, Any]) -> int:
        """Calculate CBR query complexity (1-10)."""
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
        structured_count = sum(1 for item in recognised if item.get("field"))
        keyword_count = len(recognised) - structured_count
        if 0 < keyword_count < len(recognised):
            score += 1

        return min(score, 10)

    def _estimate_result_size(self, query: str, metadata: Dict[str, Any]) -> str:
        """Estimate result set size for CBR query."""
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
        structured_count = sum(1 for item in recognised if item.get("field"))

        # Hash searches are very specific
        has_hash = any(
            item.get("type") in ["md5", "sha256"] or 
            (item.get("field") and "md5" in item.get("field", "").lower())
            for item in recognised
        )
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
        """Get CBR-specific metadata."""
        recognised = metadata.get("recognised", [])
        structured_count = sum(1 for item in recognised if item.get("field"))
        keyword_count = len(recognised) - structured_count

        return {
            "search_type": metadata.get("search_type"),
            "boolean_operator": metadata.get("boolean_operator"),
            "term_count": len(recognised),
            "keyword_count": keyword_count,
            "structured_count": structured_count,
            "has_hash": any(
                item.get("type") in ["md5", "sha256"] or
                (item.get("field") and "md5" in item.get("field", "").lower())
                for item in recognised
            ),
            "wildcard_count": query.count('*'),
            "limit": metadata.get("limit")
        }
