"""
Query builder for CrowdStrike Falcon Query Language (FQL).

This module translates structured parameters and natural language intent
into FQL query strings with proper syntax, operators, and field validation.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

logger = logging.getLogger(__name__)


class QueryBuildError(ValueError):
    """Error raised during query building."""
    pass


# Default values
DEFAULT_BOOLEAN_OPERATOR = "AND"
DEFAULT_DATASET = "events"
DEFAULT_LIMIT = 100

# Security: Input length limits to prevent ReDoS and resource exhaustion
MAX_INTENT_LENGTH = 10000  # 10KB max for natural language intent
MAX_VALUE_LENGTH = 2000  # 2KB max for individual field values

# Regex patterns for extracting indicators from natural language
_MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
_SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.IGNORECASE)
_PORT_RE = re.compile(r"\bport\s*(?:=|is|:)?\s*(\d{1,5})\b", re.IGNORECASE)
_PROCESS_BINARY_RE = re.compile(r"\b([a-zA-Z0-9_\\-]+\.(?:exe|dll|bat|cmd|ps1|vbs|sh))\b", re.IGNORECASE)
_FILE_PATH_RE = re.compile(r"([A-Za-z]:\\[^\s'\"]+|/[^\s'\"]+)")
_USERNAME_RE = re.compile(
    r"user(?:name)?\s+(?:is|=|equals|like)?\s*['\"]?([A-Za-z0-9_.@-]+)['\"]?",
    re.IGNORECASE,
)
_DOMAIN_RE = re.compile(
    r"domain\s+(?:is|=|equals|like|contains)?\s*['\"]?([A-Za-z0-9_.-]+)['\"]?",
    re.IGNORECASE,
)
_QUOTED_RE = re.compile(r"\"([^\"]{0,2000})\"|'([^']{0,2000})'")

# Stop words to filter out during natural language processing
_STOPWORDS = {
    "find", "show", "list", "display", "search", "query", "get",
    "all", "events", "event", "process", "processes", "files", "file",
    "connections", "network", "where", "that", "with", "for", "and",
    "the", "a", "an", "from", "to", "in", "on", "at", "by", "last",
}

# Dataset keyword mapping for natural language intent
_DATASET_KEYWORDS = {
    "process": "events",
    "processes": "events",
    "executable": "events",
    "file": "events",
    "files": "events",
    "network": "events",
    "connection": "events",
    "connections": "events",
    "dns": "events",
    "http": "events",
    "registry": "events",
    "authentication": "events",
    "login": "events",
    "logon": "events",
    "detection": "detections",
    "detections": "detections",
    "alert": "detections",
    "alerts": "detections",
    "indicator": "indicators",
    "indicators": "indicators",
    "ioc": "indicators",
    "threat": "indicators",
}

# Field candidates for common data types
_HASH_FIELD_CANDIDATES = {
    "md5": ["file_hash", "file_md5", "hash_md5"],
    "sha1": ["file_hash", "file_sha1", "hash_sha1"],
    "sha256": ["file_hash", "file_sha256", "hash_sha256"],
}

_IP_FIELD_CANDIDATES = ["source_ip", "destination_ip", "remote_ip", "ip_address"]
_DOMAIN_FIELD_CANDIDATES = ["http_host", "dns_domain", "domain", "destination_domain"]
_PROCESS_NAME_FIELDS = ["process_name", "parent_process_name"]
_CMDLINE_FIELDS = ["command_line"]
_FILE_NAME_FIELDS = ["file_path", "file_name"]
_USERNAME_FIELDS = ["user_name", "username"]
_PORT_FIELDS = ["destination_port", "remote_port", "port"]


class FQLQueryBuilder:
    """Build FQL queries from structured parameters and natural language."""

    def __init__(self, schema_loader) -> None:
        """
        Initialize FQL query builder.

        Parameters
        ----------
        schema_loader : FQLSchemaLoader
            Schema loader instance for accessing FQL schema definitions.
        """
        self.schema_loader = schema_loader

    def build_query(
        self,
        dataset: Optional[str] = None,
        filters: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None,
        fields: Optional[List[str]] = None,
        natural_language_intent: Optional[str] = None,
        time_range: Optional[Union[str, Dict[str, Any]]] = None,
        limit: Optional[int] = None,
        boolean_operator: str = DEFAULT_BOOLEAN_OPERATOR,
        rag_context: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Build an FQL query from structured parameters or natural language.

        Parameters
        ----------
        dataset : Optional[str]
            Dataset to query (e.g., 'events', 'detections', 'indicators')
        filters : Optional[Union[Dict, List[Dict]]]
            Structured filter conditions. Can be:
            - Single dict: {"field": "process_name", "operator": "=", "value": "cmd.exe"}
            - List of dicts for multiple conditions
            - String filter expressions
        fields : Optional[List[str]]
            Fields to project in results (for | select clause)
        natural_language_intent : Optional[str]
            Natural language description of what to find
        time_range : Optional[Union[str, Dict]]
            Time range filter. Can be:
            - String: "24h", "7d", "30d"
            - Dict: {"start": "2024-01-01", "end": "2024-01-31"}
        limit : Optional[int]
            Maximum number of results
        boolean_operator : str
            Operator to combine filters ('AND' or 'OR')
        rag_context : Optional[List[Dict]]
            RAG-retrieved context documents for query enhancement

        Returns
        -------
        Dict[str, Any]
            Dictionary with keys:
            - query: FQL query string
            - metadata: Query metadata including dataset, filters, etc.
        """
        # Validate boolean operator
        operator = boolean_operator.strip().upper()
        if operator not in {"AND", "OR"}:
            raise ValueError("boolean_operator must be 'AND' or 'OR'")

        # Infer dataset from natural language or use provided/default
        dataset_key = self._infer_dataset(dataset, natural_language_intent)

        # Get field schema for the dataset
        fields_data = self.schema_loader.get_fields(dataset_key)
        available_fields = {f["name"]: f for f in fields_data.get("fields", [])}

        # Build filter expressions
        expressions: List[str] = []
        expression_details: List[Dict[str, Any]] = []

        # Security concept expansion (if available)
        if natural_language_intent:
            try:
                from queryforge.shared.security_concepts import (
                    detect_security_concepts,
                    generate_concept_hints,
                )

                detected_concepts = detect_security_concepts(natural_language_intent)
                if detected_concepts:
                    concept_hints = generate_concept_hints(detected_concepts, "fql")
                    concept_expressions = self._build_concept_expressions(
                        concept_hints, available_fields
                    )
                    expressions.extend(concept_expressions)
                    expression_details.extend([
                        {"type": "concept_expansion", "concepts": list(detected_concepts)}
                        for _ in concept_expressions
                    ])
                    logger.info(f"Added {len(concept_expressions)} concept-based FQL expressions")
            except Exception as e:
                logger.warning(f"Security concept expansion failed: {e}")

        # RAG-enhanced query building (if available)
        if rag_context and natural_language_intent:
            try:
                from queryforge.shared.rag_context_parser import create_rag_context_parser

                parser = create_rag_context_parser("fql")
                parsed_context = parser.parse_context(
                    rag_context, natural_language_intent, dataset_key
                )

                if parsed_context["confidence"] >= 0.1:
                    rag_expressions = self._build_rag_expressions(
                        parsed_context, available_fields
                    )
                    expressions.extend(rag_expressions)
                    expression_details.extend([
                        {"type": "rag_enhanced", "confidence": parsed_context["confidence"]}
                        for _ in rag_expressions
                    ])
                    logger.info(f"Added {len(rag_expressions)} RAG-enhanced expressions")
            except Exception as e:
                logger.warning(f"RAG enhancement failed: {e}")

        # Process structured filters
        if filters:
            filter_list = [filters] if isinstance(filters, dict) else filters
            for filter_item in filter_list:
                try:
                    expression, meta = self._build_filter_expression(
                        filter_item, available_fields
                    )
                    expressions.append(expression)
                    expression_details.append(meta)
                except Exception as e:
                    logger.warning(f"Failed to build filter expression: {e}")

        # Extract expressions from natural language
        if natural_language_intent:
            nl_expressions, nl_meta = self._expressions_from_intent(
                natural_language_intent, available_fields
            )
            expressions.extend(nl_expressions)
            expression_details.extend(nl_meta)

        # Build the base query from expressions
        if expressions:
            combined = f" {operator} ".join(expressions)
            if operator == "OR" and len(expressions) > 1:
                combined = f"({combined})"
            query = combined
        else:
            # If no expressions, create a minimal valid query
            if not natural_language_intent and not filters:
                raise ValueError("Must provide either natural_language_intent, filters, or both")
            query = ""

        # Add time range filter
        if time_range:
            time_filter = self._build_time_filter(time_range)
            if time_filter:
                query = f"{query} AND {time_filter}" if query else time_filter

        # Add field projection
        if fields:
            field_list = ", ".join(fields)
            query = f"{query} | select {field_list}" if query else f"| select {field_list}"

        # Add limit
        if limit:
            query = f"{query} | limit {limit}" if query else f"| limit {limit}"
        elif not limit and query:
            # Add default limit if not specified
            query = f"{query} | limit {DEFAULT_LIMIT}"

        # Validate final query
        if not query or not query.strip():
            raise ValueError("Unable to construct a meaningful query from the provided inputs")

        # Build metadata
        metadata = {
            "dataset": dataset_key,
            "boolean_operator": operator,
            "inferred_conditions": expression_details,
            "conditions_count": len(expression_details),
            "has_time_filter": time_range is not None,
            "has_projection": fields is not None,
            "limit": limit or DEFAULT_LIMIT,
        }

        return {"query": query, "metadata": metadata}

    def _infer_dataset(
        self, dataset: Optional[str], natural_language_intent: Optional[str]
    ) -> str:
        """Infer the most appropriate dataset from inputs."""
        datasets = self.schema_loader.get_datasets()
        available = {d["name"]: d for d in datasets.get("datasets", [])}

        if not available:
            return DEFAULT_DATASET

        # Use provided dataset if valid
        if dataset:
            dataset_key = dataset.strip().lower()
            if dataset_key in available:
                return dataset_key

        # Infer from natural language
        if natural_language_intent:
            lowered = natural_language_intent.lower()
            for keyword, key in _DATASET_KEYWORDS.items():
                if keyword in lowered and key in available:
                    return key

        # Use default or first available
        if DEFAULT_DATASET in available:
            return DEFAULT_DATASET
        return next(iter(available.keys()))

    def _build_filter_expression(
        self, filter_item: Any, fields: Dict[str, Dict[str, Any]]
    ) -> Tuple[str, Dict[str, Any]]:
        """Build a single filter expression from a filter item."""
        # Handle string filters
        if isinstance(filter_item, str):
            return filter_item.strip(), {"source": "user_string"}

        # Handle dict filters
        if not isinstance(filter_item, dict):
            raise TypeError("Filters must be either strings or dictionaries")

        field = filter_item.get("field")
        if not isinstance(field, str):
            raise ValueError("Filter dictionaries must include a string 'field'")

        # Validate field exists
        if field not in fields:
            raise ValueError(f"Field '{field}' is not present in the selected dataset")

        operator = filter_item.get("operator", "=")
        if not isinstance(operator, str) or not operator:
            raise ValueError("Operator must be a non-empty string")

        # Normalize operator
        operator = self.schema_loader.normalize_operator(operator)

        value = filter_item.get("value")
        if value is None:
            raise ValueError("Filter dictionaries must include a 'value'")

        # Get field metadata
        field_meta = fields.get(field, {})
        field_type = field_meta.get("type", "string")

        # Format the expression based on value type
        if isinstance(value, (list, tuple)):
            formatted_values = self._format_values(list(value), field_type)
            expression = f"{field} {operator} ({formatted_values})"
        elif isinstance(value, (int, float)):
            expression = f"{field} {operator} {value}"
        else:
            expression = f"{field} {operator} {self._quote(str(value))}"

        return expression, {
            "field": field,
            "operator": operator,
            "value": value,
            "type": field_type,
        }

    def _build_concept_expressions(
        self, concept_hints: Dict[str, List[str]], fields: Dict[str, Dict[str, Any]]
    ) -> List[str]:
        """Build filter expressions from security concept hints."""
        expressions = []
        # Implementation would map concept hints to FQL expressions
        # Placeholder for now
        return expressions

    def _build_rag_expressions(
        self, parsed_context: Dict[str, Any], fields: Dict[str, Dict[str, Any]]
    ) -> List[str]:
        """Build filter expressions from RAG-parsed context."""
        expressions = []
        # Extract field:value pairs from RAG context
        for field in parsed_context.get("fields", [])[:10]:
            if field not in fields:
                continue
            values = parsed_context.get("values", {}).get(field, [])
            for value in values[:7]:
                expression = f"{field} contains {self._quote(value)}"
                expressions.append(expression)
        return expressions

    def _expressions_from_intent(
        self, text: str, fields: Dict[str, Dict[str, Any]]
    ) -> Tuple[List[str], List[Dict[str, Any]]]:
        """Extract filter expressions from natural language intent."""
        # Security: Validate input length
        if len(text) > MAX_INTENT_LENGTH:
            raise ValueError(
                f"Intent exceeds maximum length of {MAX_INTENT_LENGTH} characters"
            )

        expressions = []
        metadata = []

        # Extract various indicators
        expressions.extend(self._collect_hash_expressions(text, fields))
        expressions.extend(self._collect_ip_expressions(text, fields))
        expressions.extend(self._collect_domain_expressions(text, fields))
        expressions.extend(self._collect_username_expressions(text, fields))
        expressions.extend(self._collect_process_expressions(text, fields))
        expressions.extend(self._collect_path_expressions(text, fields))
        expressions.extend(self._collect_cmdline_expressions(text, fields))
        expressions.extend(self._collect_port_expressions(text, fields))

        # Deduplicate
        seen = set()
        unique_expressions = []
        for expr in expressions:
            if expr not in seen:
                seen.add(expr)
                unique_expressions.append(expr)
                metadata.append({"type": "natural_language", "expression": expr})

        return unique_expressions, metadata

    def _collect_hash_expressions(
        self, text: str, fields: Dict[str, Dict[str, Any]]
    ) -> List[str]:
        """Extract hash-based filter expressions."""
        expressions = []
        for label, regex in [("sha256", _SHA256_RE), ("sha1", _SHA1_RE), ("md5", _MD5_RE)]:
            for match in regex.finditer(text):
                field = self._choose_field(fields, _HASH_FIELD_CANDIDATES.get(label, []))
                if field:
                    value = match.group(0)
                    expressions.append(f"{field} = {self._quote(value)}")
        return expressions

    def _collect_ip_expressions(
        self, text: str, fields: Dict[str, Dict[str, Any]]
    ) -> List[str]:
        """Extract IP address filter expressions."""
        expressions = []
        for regex in [_IPV4_RE, _IPV6_RE]:
            for match in regex.finditer(text):
                field = self._choose_field(fields, _IP_FIELD_CANDIDATES)
                if field:
                    value = match.group(0)
                    expressions.append(f"{field} = {self._quote(value)}")
        return expressions

    def _collect_domain_expressions(
        self, text: str, fields: Dict[str, Dict[str, Any]]
    ) -> List[str]:
        """Extract domain filter expressions."""
        expressions = []
        for match in _DOMAIN_RE.finditer(text):
            field = self._choose_field(fields, _DOMAIN_FIELD_CANDIDATES)
            if field:
                value = match.group(1)
                expressions.append(f"{field} contains {self._quote(value)}")
        return expressions

    def _collect_username_expressions(
        self, text: str, fields: Dict[str, Dict[str, Any]]
    ) -> List[str]:
        """Extract username filter expressions."""
        expressions = []
        for match in _USERNAME_RE.finditer(text):
            field = self._choose_field(fields, _USERNAME_FIELDS)
            if field:
                value = match.group(1)
                expressions.append(f"{field} contains {self._quote(value)}")
        return expressions

    def _collect_process_expressions(
        self, text: str, fields: Dict[str, Dict[str, Any]]
    ) -> List[str]:
        """Extract process name filter expressions."""
        expressions = []
        field = self._choose_field(fields, _PROCESS_NAME_FIELDS)
        if field:
            for match in _PROCESS_BINARY_RE.finditer(text):
                value = match.group(1)
                expressions.append(f"{field} = {self._quote(value)}")
        return expressions

    def _collect_path_expressions(
        self, text: str, fields: Dict[str, Dict[str, Any]]
    ) -> List[str]:
        """Extract file path filter expressions."""
        expressions = []
        field = self._choose_field(fields, _FILE_NAME_FIELDS)
        if field:
            for match in _FILE_PATH_RE.finditer(text):
                value = match.group(1)
                expressions.append(f"{field} contains {self._quote(value)}")
        return expressions

    def _collect_cmdline_expressions(
        self, text: str, fields: Dict[str, Dict[str, Any]]
    ) -> List[str]:
        """Extract command line filter expressions."""
        expressions = []
        field = self._choose_field(fields, _CMDLINE_FIELDS)
        if field:
            for match in _QUOTED_RE.finditer(text):
                value = match.group(1) or match.group(2)
                if value and value.lower() not in _STOPWORDS and len(value) >= 3:
                    expressions.append(f"{field} contains {self._quote(value)}")
        return expressions

    def _collect_port_expressions(
        self, text: str, fields: Dict[str, Dict[str, Any]]
    ) -> List[str]:
        """Extract port filter expressions."""
        expressions = []
        field = self._choose_field(fields, _PORT_FIELDS)
        if field:
            for match in _PORT_RE.finditer(text):
                port = int(match.group(1))
                if 0 < port <= 65535:
                    expressions.append(f"{field} = {port}")
        return expressions

    def _choose_field(
        self, fields: Dict[str, Dict[str, Any]], candidates: List[str]
    ) -> Optional[str]:
        """Choose the first available field from a list of candidates."""
        for candidate in candidates:
            if candidate in fields:
                return candidate
        return None

    def _build_time_filter(self, time_range: Union[str, Dict[str, Any]]) -> str:
        """Build a time filter expression."""
        if isinstance(time_range, str):
            # Handle relative time (e.g., "24h", "7d")
            return f"@timestamp >= now() - {time_range}"
        elif isinstance(time_range, dict):
            # Handle absolute time range
            start = time_range.get("start")
            end = time_range.get("end")
            if start and end:
                return f"@timestamp >= '{start}' AND @timestamp <= '{end}'"
            elif start:
                return f"@timestamp >= '{start}'"
            elif end:
                return f"@timestamp <= '{end}'"
        return ""

    def _quote(self, value: str) -> str:
        """Quote a string value for use in FQL queries."""
        # Escape backslashes and single quotes
        escaped = value.replace("\\", "\\\\").replace("'", "\\'")
        return f"'{escaped}'"

    def _format_values(
        self, values: Sequence[Any], field_type: str
    ) -> str:
        """Format a list of values for use in IN clauses."""
        formatted = []
        for value in values:
            if isinstance(value, (int, float)):
                formatted.append(str(value))
            else:
                formatted.append(self._quote(str(value)))
        return ", ".join(formatted)


def build_fql_query(
    schema_loader,
    dataset: Optional[str] = None,
    filters: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None,
    fields: Optional[List[str]] = None,
    natural_language_intent: Optional[str] = None,
    time_range: Optional[Union[str, Dict[str, Any]]] = None,
    limit: Optional[int] = None,
    boolean_operator: str = DEFAULT_BOOLEAN_OPERATOR,
    rag_context: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Build an FQL query (convenience function).

    Parameters match FQLQueryBuilder.build_query() method.
    """
    builder = FQLQueryBuilder(schema_loader)
    return builder.build_query(
        dataset=dataset,
        filters=filters,
        fields=fields,
        natural_language_intent=natural_language_intent,
        time_range=time_range,
        limit=limit,
        boolean_operator=boolean_operator,
        rag_context=rag_context,
    )
