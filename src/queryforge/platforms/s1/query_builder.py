"""Translate natural language intent into SentinelOne (S1QL) queries."""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

class QueryBuildError(ValueError):
    """Error raised during query building."""
    pass

DEFAULT_BOOLEAN_OPERATOR = "AND"
DEFAULT_DATASET = "processes"

# Security: Input length limits to prevent ReDoS and resource exhaustion
MAX_INTENT_LENGTH = 10000  # 10KB max for natural language intent
MAX_VALUE_LENGTH = 2000  # 2KB max for individual field values

logger = logging.getLogger(__name__)

_MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
_SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.IGNORECASE)
_PORT_RE = re.compile(r"\bport\s*(?:=|is|:)?\s*(\d{1,5})\b", re.IGNORECASE)
_PROCESS_BINARY_RE = re.compile(r"\b([a-zA-Z0-9_\\-]+\.(?:exe|dll|bat|cmd|ps1|vbs))\b", re.IGNORECASE)
_FILE_PATH_RE = re.compile(r"([A-Za-z]:\\[^\s'\"]+|/[^\s'\"]+)")
_USERNAME_RE = re.compile(
    r"user(?:name)?\s+(?:is|=|equals|like)?\s*['\"]?([A-Za-z0-9_.@-]+)['\"]?",
    re.IGNORECASE,
)
_DOMAIN_RE = re.compile(
    r"domain\s+(?:is|=|equals|like|contains)?\s*['\"]?([A-Za-z0-9_.-]+)['\"]?",
    re.IGNORECASE,
)
# CRITICAL SECURITY FIX: Replace catastrophic backtracking pattern
# OLD (DANGEROUS): r"\"([^\"\\]*(?:\\.[^\"\\]*)*)\"|'([^'\\]*(?:\\.[^'\\]*)*)'"
# This pattern has nested quantifiers and can cause exponential backtracking (O(2^n))
# A malicious input like '"' + 'a'*5000 + '\\'*5000 + '"' causes server hang
# NEW (SAFE): Simpler pattern with length bounds to prevent ReDoS
_QUOTED_RE = re.compile(r"\"([^\"]{0,2000})\"|'([^']{0,2000})'")

_STOPWORDS = {
    "find",
    "show",
    "list",
    "display",
    "all",
    "events",
    "event",
    "process",
    "processes",
    "files",
    "file",
    "connections",
    "network",
    "where",
    "that",
    "with",
    "for",
    "and",
    "the",
    "a",
    "an",
    "from",
    "to",
}

_DATASET_KEYWORDS = {
    "process": "processes",
    "processes": "processes",
    "executable": "processes",
    "file": "files",
    "files": "files",
    "dns": "dns",
    "network": "network_actions",
    "connection": "network_actions",
    "connections": "network_actions",
    "traffic": "network_actions",
    "url": "url",
    "http": "url",
    "login": "logins",
    "logon": "logins",
    "module": "modules",
    "driver": "driver",
    "registry": "registry",
    "scheduled task": "scheduled_tasks",
    "task": "scheduled_tasks",
    "indicator": "indicators",
    "script": "command_scripts",
    "cross process": "cross_process",
}

# Event filters are no longer automatically added to queries.
# This prevents over-restriction and gives users full control.
# Users can explicitly add event filters when needed using:
# filters = [{"field": "meta.event.name", "operator": "in", "value": ["PROCESSCREATION"]}]
_DATASET_EVENT_FILTERS = {}

_HASH_FIELD_CANDIDATES = {
    "md5": [
        "tgt.file.md5",
        "tgt.file.image.md5",
        "src.file.md5",
        "tgt.process.image.md5",
        "src.process.image.md5",
    ],
    "sha1": [
        "tgt.file.sha1",
        "src.file.sha1",
        "tgt.process.image.sha1",
        "src.process.image.sha1",
    ],
    "sha256": [
        "tgt.file.sha256",
        "src.file.sha256",
        "tgt.process.image.sha256",
        "src.process.image.sha256",
    ],
}

_IP_FIELD_CANDIDATES = [
    "dst.ip.address",
    "src.ip.address",
    "network.ip",
    "network.dns.resolvedIp",
]

_DOMAIN_FIELD_CANDIDATES = [
    "network.http.host",
    "dns.request.domain",
    "dns.response.domain",
    "url.address",
]

_PROCESS_NAME_FIELDS = [
    "tgt.process.displayName",
    "tgt.process.name",
    "src.process.displayName",
    "src.process.name",
    "osSrc.process.displayName",
    "osSrc.process.name",
]

_CMDLINE_FIELDS = [
    "tgt.process.cmdline",
    "src.process.cmdline",
    "osSrc.process.cmdline",
]

_FILE_NAME_FIELDS = [
    "tgt.file.name",
    "tgt.file.path",
    "src.file.name",
    "src.file.path",
]

_USERNAME_FIELDS = [
    "actor.user.name",
    "identity.user.username",
    "src.process.user",
    "tgt.process.user",
]

_PORT_FIELDS = [
    "dst.port.number",
    "src.port.number",
]


def infer_dataset(
    dataset: Optional[str],
    natural_language_intent: Optional[str],
    schema: Dict[str, Any],
) -> Optional[str]:
    """Return the most appropriate dataset key for the request."""

    datasets = schema.get("datasets", {})
    if not isinstance(datasets, dict) or not datasets:
        return None

    # BUG FIX: Validate dataset type before calling string methods
    if dataset:
        if not isinstance(dataset, str):
            raise TypeError(
                f"dataset must be a string, got {type(dataset).__name__}. "
                f"Valid datasets: {', '.join(datasets.keys())}"
            )
        key = dataset.strip().lower().replace(" ", "_")
        if key in datasets:
            return key
        # Try to match by display name
        for candidate, meta in datasets.items():
            name = meta.get("name")
            if isinstance(name, str) and name.lower() == dataset.lower():
                return candidate

    if natural_language_intent:
        lowered = natural_language_intent.lower()
        for keyword, key in _DATASET_KEYWORDS.items():
            if keyword in lowered and key in datasets:
                return key

    if DEFAULT_DATASET in datasets:
        return DEFAULT_DATASET

    return next(iter(datasets.keys()))


def _collect_fields(schema: Dict[str, Any], dataset: Optional[str]) -> Dict[str, Dict[str, Any]]:
    common = schema.get("common_fields", {}) if isinstance(schema.get("common_fields"), dict) else {}
    fields: Dict[str, Dict[str, Any]] = dict(common)
    if dataset:
        dataset_meta = schema.get("datasets", {}).get(dataset)
        if isinstance(dataset_meta, dict):
            dataset_fields = dataset_meta.get("fields", {})
            if isinstance(dataset_fields, dict):
                fields.update(dataset_fields)
    return fields


def _choose_field(
    fields: Dict[str, Dict[str, Any]],
    candidates: Sequence[str],
) -> Optional[str]:
    for candidate in candidates:
        if candidate in fields:
            return candidate
    return None


def _build_operator_map(schema: Dict[str, Any]) -> Dict[str, str]:
    """Build a case-insensitive operator normalization map from schema.
    
    Returns a dict mapping lowercase operator names to their canonical forms.
    Maps both operator symbols and operator names to canonical symbols.
    """
    operator_map: Dict[str, str] = {}
    
    # Load from main operators file
    operators = schema.get("operators", {})
    if isinstance(operators, dict):
        operator_list = operators.get("operators", [])
        if isinstance(operator_list, list):
            for op in operator_list:
                if isinstance(op, dict):
                    name = op.get("name")
                    symbols = op.get("symbols", [])
                    if isinstance(name, str) and isinstance(symbols, list):
                        # Map each symbol to itself
                        for symbol in symbols:
                            if isinstance(symbol, str):
                                operator_map[symbol.lower()] = symbol
                        
                        # Determine canonical symbol for this operator
                        # Prefer "=" for equality, otherwise use first symbol
                        canonical = None
                        if "=" in symbols:
                            canonical = "="
                        elif symbols:
                            canonical = symbols[0]
                        
                        # Map operator name to canonical symbol
                        if canonical and name:
                            operator_map[name.lower()] = canonical
    
    # Load from operator variants (type-specific operators)
    variants = schema.get("operator_variants", {})
    if isinstance(variants, dict):
        for variant_ops in variants.values():
            if isinstance(variant_ops, list):
                for op in variant_ops:
                    if isinstance(op, dict):
                        operator = op.get("operator")
                        if isinstance(operator, str):
                            operator_map[operator.lower()] = operator
    
    return operator_map


def _normalize_operator(operator: str, operator_map: Dict[str, str]) -> str:
    """
    Normalize an operator to its canonical form from the schema.

    ACCURACY FIX: Improved operator matching to prevent false failures on valid operators.
    Uses multi-stage matching strategy instead of hardcoded fallbacks.

    Args:
        operator: The operator string to normalize
        operator_map: Map from lowercase operators to canonical forms

    Returns:
        The canonical operator string

    Raises:
        ValueError: If the operator is not found in the schema after all attempts
    """
    if not operator or not isinstance(operator, str):
        raise ValueError("Operator must be a non-empty string")

    # Stage 1: Try exact lowercase match
    normalized = operator_map.get(operator.lower())
    if normalized is not None:
        return normalized

    # Stage 2: Try common operator aliases
    common_aliases = {
        "==": "=",
        "!=": "<>",
        "contains ignorecase": "contains anycase",
        "containsignorecase": "contains anycase",
        "contains_ignorecase": "contains anycase",
        "eq": "=",
        "ne": "<>",
        "neq": "<>",
        "gt": ">",
        "gte": ">=",
        "lt": "<",
        "lte": "<=",
    }

    alias_target = common_aliases.get(operator.lower())
    if alias_target:
        normalized = operator_map.get(alias_target)
        if normalized is not None:
            return normalized

    # Stage 3: Try case-insensitive search through all operator_map keys
    # The operator might already be canonical but with different casing
    for key, value in operator_map.items():
        if key.lower() == operator.lower():
            return value

    # Stage 4: Try partial/fuzzy match for operators with spaces or underscores
    operator_normalized = operator.lower().replace("_", " ").replace("-", " ")
    for key, value in operator_map.items():
        key_normalized = key.lower().replace("_", " ").replace("-", " ")
        if key_normalized == operator_normalized:
            return value

    # Stage 5: If operator looks like it's already canonical (proper casing, etc.),
    # check if it matches any of the values in operator_map
    for value in operator_map.values():
        if value.lower() == operator.lower():
            return value

    # All attempts failed - operator is truly unknown
    available_operators = sorted(set(operator_map.values()))[:10]  # Show first 10 for brevity
    raise ValueError(
        f"Unknown operator '{operator}'. Available operators include: "
        f"{', '.join(available_operators)}... "
        f"Please check the S1 operator schema."
    )


def _quote(value: str) -> str:
    """Quote a value for use in S1QL queries.
    
    S1QL uses single quotes for string literals and requires backslashes
    to be doubled (\\ becomes \\\\) to represent literal backslashes in paths.
    Single quotes within the string are escaped with a backslash.
    """
    # First, double all backslashes for S1QL
    escaped = value.replace("\\", "\\\\")
    # Then escape any single quotes
    escaped = escaped.replace("'", "\\'")
    # Wrap in single quotes
    return f"'{escaped}'"


def _format_values(
    values: Sequence[Any],
    data_type: Optional[str] = None,
) -> str:
    formatted: List[str] = []
    for value in values:
        if isinstance(value, (int, float)):
            formatted.append(str(value))
        else:
            if data_type and data_type.lower() in {"numeric", "integer"}:
                try:
                    formatted.append(str(int(value)))
                    continue
                except Exception:
                    pass
            formatted.append(_quote(str(value)))
    return ", ".join(formatted)


def _normalize_filter_string(expression: str) -> str:
    """Normalize a filter string to use S1QL-compliant single-quote syntax.
    
    If the expression contains double-quoted strings, convert them to single-quoted
    strings with properly escaped backslashes and quotes.
    """
    import re
    
    # Pattern to match double-quoted strings
    double_quote_pattern = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')
    
    def replace_double_quotes(match: re.Match) -> str:
        # Get the content between double quotes
        content = match.group(1)
        # Unescape any escaped double quotes
        content = content.replace('\\"', '"')
        # Now apply S1QL escaping (double backslashes, escape single quotes)
        content = content.replace("\\", "\\\\")
        content = content.replace("'", "\\'")
        # Return wrapped in single quotes
        return f"'{content}'"
    
    # Replace all double-quoted strings with properly escaped single-quoted strings
    normalized = double_quote_pattern.sub(replace_double_quotes, expression)
    return normalized


def _sanitise_expression(expression: str) -> str:
    if any(char in expression for char in [";", "|", "\n"]):
        raise ValueError("Unsafe characters detected in expression")
    return expression


def _build_filter_expression(
    item: Any,
    fields: Dict[str, Dict[str, Any]],
    operator_map: Dict[str, str],
) -> Tuple[str, Dict[str, Any]]:
    if isinstance(item, str):
        # Normalize double-quoted strings to single-quoted strings with proper escaping
        normalized = _normalize_filter_string(item.strip())
        return _sanitise_expression(normalized), {"source": "user"}

    if not isinstance(item, dict):
        raise TypeError("Filters must be either strings or dictionaries")

    field = item.get("field")
    if not isinstance(field, str):
        raise ValueError("Filter dictionaries must include a string 'field'")
    if field not in fields:
        raise ValueError(f"Field '{field}' is not present in the selected dataset")

    operator = item.get("operator", "=")
    if not isinstance(operator, str) or not operator:
        raise ValueError("Operator must be a non-empty string")
    
    # Normalize operator using the schema
    try:
        operator = _normalize_operator(operator, operator_map)
    except ValueError as e:
        logger.warning(f"Operator normalization failed: {e}")
        # If normalization fails, use the operator as-is (backwards compatibility)
        pass

    value = item.get("value")
    field_meta = fields.get(field, {})
    data_type = str(field_meta.get("data_type", "")).lower()

    if isinstance(value, (list, tuple)):
        formatted_values = _format_values(list(value), data_type=data_type)
        if operator.lower().startswith("in"):
            expression = f"{field} {operator} ({formatted_values})"
        else:
            expression = f"{field} {operator} ({formatted_values})"
        return _sanitise_expression(expression), {"field": field, "operator": operator, "value": value}

    if value is None:
        raise ValueError("Filter dictionaries must include a 'value'")

    if isinstance(value, (int, float)):
        expression = f"{field} {operator} {value}"
    else:
        if data_type in {"numeric", "integer"}:
            try:
                numeric_value = int(str(value))
            except ValueError:
                raise ValueError(
                    f"Field '{field}' expects a numeric value"
                ) from None
            expression = f"{field} {operator} {numeric_value}"
        else:
            expression = f"{field} {operator} {_quote(str(value))}"

    return _sanitise_expression(expression), {"field": field, "operator": operator, "value": value}


def _collect_hash_expressions(
    text: str,
    fields: Dict[str, Dict[str, Any]],
) -> List[Tuple[str, Dict[str, Any]]]:
    expressions: List[Tuple[str, Dict[str, Any]]] = []
    for label, regex in ("sha256", _SHA256_RE), ("sha1", _SHA1_RE), ("md5", _MD5_RE):
        candidates = _HASH_FIELD_CANDIDATES[label]
        for match in regex.finditer(text):
            field = _choose_field(fields, candidates)
            if not field:
                continue
            value = match.group(0)
            expression = f"{field} in:matchcase ({_quote(value)})"
            expressions.append((expression, {"type": label, "value": value, "field": field}))
    return expressions


def _collect_ip_expressions(
    text: str,
    fields: Dict[str, Dict[str, Any]],
) -> List[Tuple[str, Dict[str, Any]]]:
    expressions: List[Tuple[str, Dict[str, Any]]] = []
    for regex, label in ((_IPV4_RE, "ipv4"), (_IPV6_RE, "ipv6")):
        for match in regex.finditer(text):
            field = _choose_field(fields, _IP_FIELD_CANDIDATES)
            if not field:
                continue
            value = match.group(0)
            expression = f"{field} = {_quote(value)}"
            expressions.append((expression, {"type": label, "value": value, "field": field}))
    return expressions


def _collect_domain_expressions(
    text: str,
    fields: Dict[str, Dict[str, Any]],
) -> List[Tuple[str, Dict[str, Any]]]:
    expressions: List[Tuple[str, Dict[str, Any]]] = []
    for match in _DOMAIN_RE.finditer(text):
        field = _choose_field(fields, _DOMAIN_FIELD_CANDIDATES)
        if not field:
            continue
        value = match.group(1)
        expression = f"{field} contains:anycase {_quote(value)}"
        expressions.append((expression, {"type": "domain", "value": value, "field": field}))
    return expressions


def _collect_username_expressions(
    text: str,
    fields: Dict[str, Dict[str, Any]],
) -> List[Tuple[str, Dict[str, Any]]]:
    expressions: List[Tuple[str, Dict[str, Any]]] = []
    for match in _USERNAME_RE.finditer(text):
        field = _choose_field(fields, _USERNAME_FIELDS)
        if not field:
            continue
        value = match.group(1)
        expression = f"{field} contains ({_quote(value)})"
        expressions.append((expression, {"type": "username", "value": value, "field": field}))
    return expressions


def _collect_process_expressions(
    text: str,
    fields: Dict[str, Dict[str, Any]],
) -> List[Tuple[str, Dict[str, Any]]]:
    expressions: List[Tuple[str, Dict[str, Any]]] = []
    field = _choose_field(fields, _PROCESS_NAME_FIELDS)
    if not field:
        return expressions
    values: List[str] = []
    for match in _PROCESS_BINARY_RE.finditer(text):
        values.append(match.group(1))
    if values:
        unique_values = sorted(set(value.lower() for value in values))
        formatted = ", ".join(_quote(v) for v in unique_values)
        expressions.append((f"{field} contains ({formatted})", {"type": "process_name", "values": unique_values, "field": field}))
    return expressions


def _collect_path_expressions(
    text: str,
    fields: Dict[str, Dict[str, Any]],
) -> List[Tuple[str, Dict[str, Any]]]:
    expressions: List[Tuple[str, Dict[str, Any]]] = []
    field = _choose_field(fields, _FILE_NAME_FIELDS)
    if not field:
        return expressions
    for match in _FILE_PATH_RE.finditer(text):
        value = match.group(1)
        expression = f"{field} contains:anycase {_quote(value)}"
        expressions.append((expression, {"type": "path", "value": value, "field": field}))
    return expressions


def _collect_cmdline_expressions(
    text: str,
    fields: Dict[str, Dict[str, Any]],
) -> List[Tuple[str, Dict[str, Any]]]:
    field = _choose_field(fields, _CMDLINE_FIELDS)
    if not field:
        return []
    expressions: List[Tuple[str, Dict[str, Any]]] = []
    
    # First, try to extract quoted strings
    for match in _QUOTED_RE.finditer(text):
        value = match.group(1) or match.group(2)
        if not value:
            continue
        if value.lower() in _STOPWORDS or len(value) < 3:
            continue
        expression = f"{field} contains:anycase {_quote(value)}"
        expressions.append((expression, {"type": "cmdline", "value": value, "field": field}))
    
    # If we didn't find anything quoted, try to extract command-line flag patterns
    # Look for patterns like -flag, --flag, /flag
    if not expressions and "cmdline" in text.lower():
        cmdline_pattern = re.compile(r'[-/]([a-zA-Z][a-zA-Z0-9_]*)')
        for match in cmdline_pattern.finditer(text):
            value = match.group(0)  # Include the dash/slash
            if len(value) > 2:  # Must be at least 3 characters
                expression = f"{field} contains:anycase {_quote(value)}"
                expressions.append((expression, {"type": "cmdline", "value": value, "field": field}))
    
    return expressions


def _collect_port_expressions(
    text: str,
    fields: Dict[str, Dict[str, Any]],
) -> List[Tuple[str, Dict[str, Any]]]:
    expressions: List[Tuple[str, Dict[str, Any]]] = []
    field = _choose_field(fields, _PORT_FIELDS)
    if not field:
        return expressions
    for match in _PORT_RE.finditer(text):
        port = int(match.group(1))
        if not (0 < port <= 65535):
            continue
        expressions.append((f"{field} = {port}", {"type": "port", "value": port, "field": field}))
    return expressions


def _deduplicate(expressions: Sequence[Tuple[str, Dict[str, Any]]]) -> List[Tuple[str, Dict[str, Any]]]:
    seen: set[str] = set()
    ordered: List[Tuple[str, Dict[str, Any]]] = []
    for expression, meta in expressions:
        if expression in seen:
            continue
        seen.add(expression)
        ordered.append((expression, meta))
    return ordered


def _expressions_from_intent(
    text: str,
    fields: Dict[str, Dict[str, Any]],
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """
    Extract filter expressions from natural language intent.

    Security: Validates input length to prevent ReDoS attacks.
    """
    # Security: Validate input length to prevent ReDoS attacks
    if len(text) > MAX_INTENT_LENGTH:
        logger.error(
            "Natural language intent exceeds maximum length (%d > %d chars). "
            "Refusing to process potentially malicious input.",
            len(text),
            MAX_INTENT_LENGTH
        )
        raise ValueError(f"Intent exceeds maximum length of {MAX_INTENT_LENGTH} characters")

    candidates: List[Tuple[str, Dict[str, Any]]] = []
    lower = text.lower()
    if "port" in lower:
        candidates.extend(_collect_port_expressions(text, fields))
    candidates.extend(_collect_hash_expressions(text, fields))
    candidates.extend(_collect_ip_expressions(text, fields))
    candidates.extend(_collect_domain_expressions(text, fields))
    candidates.extend(_collect_username_expressions(text, fields))
    candidates.extend(_collect_process_expressions(text, fields))
    candidates.extend(_collect_path_expressions(text, fields))
    candidates.extend(_collect_cmdline_expressions(text, fields))
    deduped = _deduplicate(candidates)
    expressions = [expr for expr, _ in deduped]
    metadata = [meta for _, meta in deduped]
    return expressions, metadata


def build_s1_query(
schema: Dict[str, Any],
    dataset: Optional[str] = None,
    filters: Optional[Sequence[Any]] = None,
    natural_language_intent: Optional[str] = None,
    boolean_operator: str = DEFAULT_BOOLEAN_OPERATOR,
    rag_context: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[str, Dict[str, Any]]:
    """Build an S1QL query string and metadata.
    
    Args:
        schema: S1 schema dictionary
        dataset: Dataset name to query
        filters: List of filter conditions
        natural_language_intent: Natural language description
        boolean_operator: Boolean operator to combine conditions (AND/OR)
        rag_context: Optional RAG-retrieved documents for query enhancement
        
    Returns:
        Tuple of (query_string, metadata_dict)
    """

    operator = boolean_operator.strip().upper()
    if operator not in {"AND", "OR"}:
        raise ValueError("boolean_operator must be 'AND' or 'OR'")

    dataset_key = infer_dataset(dataset, natural_language_intent, schema)
    fields = _collect_fields(schema, dataset_key)
    
    # Build operator normalization map from schema
    operator_map = _build_operator_map(schema)

    expressions: List[str] = []
    expression_details: List[Dict[str, Any]] = []

    # Security Concept Expansion: Detect and expand security concepts
    if natural_language_intent:
        try:
            from queryforge.shared.security_concepts import detect_security_concepts, generate_concept_hints, get_concept_description

            detected_concepts = detect_security_concepts(natural_language_intent)
            if detected_concepts:
                concept_hints = generate_concept_hints(detected_concepts, "s1")

                # Build S1QL expressions from concept hints
                for keyword_category, keywords in concept_hints.items():
                    # Map hint category to S1 field names
                    field_mapping = {
                        "process_keywords": ["SrcProcName", "TgtProcName", "SrcProcParentName"],
                        "cmdline_keywords": ["SrcProcCmdLine"],
                        "port_keywords": ["TgtProcNetConnLocalPort", "TgtProcNetConnRemotePort"],
                        "domain_keywords": ["TgtProcNetConnRemoteDomain"],
                        "registry_keywords": ["TgtProcRegistryKeyPath"],
                    }

                    candidate_fields = field_mapping.get(keyword_category, [])
                    for field in candidate_fields:
                        if field not in fields:
                            continue

                        if keyword_category == "port_keywords":
                            # Numeric fields use 'In Contains' operator
                            if keywords:
                                # Format: field In Contains Anycase ("value1", "value2")
                                quoted_ports = ", ".join([_quote(p) for p in keywords])
                                expression = f"{field} In Contains Anycase ({quoted_ports})"
                                expressions.append(expression)
                                expression_details.append({
                                    "type": "concept_expansion",
                                    "concepts": list(detected_concepts),
                                    "field": field,
                                    "values": keywords,
                                })
                                logger.info(f"Added concept-based S1 expression: {expression}")
                        else:
                            # String fields use 'In Contains Anycase' operator for multi-value match
                            if keywords:
                                # Format: field In Contains Anycase ("value1", "value2")
                                quoted_keywords = ", ".join([_quote(k) for k in keywords])
                                expression = f"{field} In Contains Anycase ({quoted_keywords})"
                                expressions.append(expression)
                                expression_details.append({
                                    "type": "concept_expansion",
                                    "concepts": list(detected_concepts),
                                    "field": field,
                                    "values": keywords,
                                })
                                logger.info(f"Added concept-based S1 expression: {expression}")

                concept_descriptions = [get_concept_description(c) for c in detected_concepts]
                logger.info(f"Detected security concepts: {', '.join(detected_concepts)}")
                logger.info(f"Added {len([d for d in expression_details if d.get('type') == 'concept_expansion'])} concept-based S1 expressions")

        except Exception as e:
            # Concept expansion is optional - don't fail the query if it errors
            logger.warning(f"Security concept expansion failed for S1, continuing without it: {e}")

    # RAG-Enhanced Query Building: Extract additional expressions from RAG context
    if rag_context and natural_language_intent:
        try:
            from queryforge.shared.rag_context_parser import create_rag_context_parser
            
            parser = create_rag_context_parser("s1")
            parsed_context = parser.parse_context(
                rag_context,
                natural_language_intent,
                dataset_key
            )
            
            logger.info(f"RAG parsed context for S1: fields={parsed_context['fields']}, "
                       f"values={parsed_context['values']}, "
                       f"confidence={parsed_context['confidence']}")
            
            # Use RAG enhancements with low confidence threshold (RAG-first approach)
            # Goal: Comprehensive one-shot queries that cover multiple indicators
            if parsed_context["confidence"] >= 0.1:
                # Extract field:value pairs from RAG context
                for field in parsed_context["fields"][:10]:  # Top 10 fields for comprehensive coverage
                    if field not in fields:
                        logger.info(f"Field {field} not in fields for S1, skipping")
                        continue
                    
                    values = parsed_context["values"].get(field, [])
                    for value in values[:7]:  # Top 7 values per field for comprehensive coverage
                        # Format the S1QL expression (field = 'value' or field contains:anycase 'value')
                        if any(keyword in value.lower() for keyword in ['.exe', '.dll', 'http', 'www', 'domain']):
                            # Likely a filename, URL, or domain - use contains:anycase
                            expression = f"{field} contains:anycase {_quote(value)}"
                        else:
                            # Use contains for flexible matching
                            expression = f"{field} contains ({_quote(value)})"
                        
                        expressions.append(expression)
                        expression_details.append({
                            "type": "rag_enhanced",
                            "field": field,
                            "value": value,
                            "confidence": parsed_context["confidence"]
                        })
                        logger.info(f"Added RAG enhanced S1 expression: {expression}")
                
                if len([d for d in expression_details if d.get("type") == "rag_enhanced"]) > 0:
                    logger.info(f"Added {len([d for d in expression_details if d.get('type') == 'rag_enhanced'])} RAG enhanced expressions to S1 query")
            else:
                logger.info(f"RAG confidence too low for S1: {parsed_context['confidence']}")
                
        except Exception as e:
            # RAG enhancement is optional - don't fail the query if it errors
            logger.warning(f"RAG enhancement failed for S1, continuing without it: {e}")

    if filters:
        for item in filters:
            expression, meta = _build_filter_expression(item, fields, operator_map)
            expressions.append(expression)
            expression_details.append(meta)

    if natural_language_intent:
        nl_expressions, nl_meta = _expressions_from_intent(natural_language_intent, fields)
        expressions.extend(nl_expressions)
        expression_details.extend(nl_meta)

    # Validate that we have something meaningful to query BEFORE adding event filters
    has_valid_intent = natural_language_intent and natural_language_intent.strip()
    has_valid_filters = filters and len(filters) > 0
    has_extracted_expressions = len(expressions) > 0
    has_explicit_dataset = dataset is not None and dataset.strip()
    
    # Determine if dataset was inferred from intent (not just defaulted)
    inferred_from_intent = False
    if natural_language_intent and dataset_key:
        lowered = natural_language_intent.lower()
        for keyword, key in _DATASET_KEYWORDS.items():
            if keyword in lowered and key == dataset_key:
                inferred_from_intent = True
                break
    
    # If we have no filters and no valid intent, that's an error
    if not has_valid_filters and not has_valid_intent:
        raise ValueError("Must provide either natural_language_intent, filters, or both")
    
    # If we have intent but no expressions were extracted from it, and no filters provided
    if has_valid_intent and not has_extracted_expressions and not has_valid_filters:
        # Allow if an explicit dataset was provided or dataset was inferred from keywords
        if has_explicit_dataset or inferred_from_intent:
            pass  # Allow it - this is a valid general query for the dataset
        else:
            # No explicit dataset, not inferred, no extracted expressions
            raise ValueError("No valid expressions could be generated from the provided intent")
    
    # Event filters are no longer automatically added.
    # Users have full control and can add them explicitly if needed.

    query: str
    if expressions:
        combined = f" {operator} ".join(expressions)
        # Only wrap in parentheses if using OR with multiple expressions
        if operator == "OR" and len(expressions) > 1:
            combined = f"({combined})"
        query = combined
    else:
        query = ""

    # ACCURACY FIX: Final validation to prevent empty/unbounded queries
    # Even after all the logic above, ensure we never return a completely empty query
    # which would match ALL records in the dataset (potentially millions of results)
    if not query or not query.strip():
        raise ValueError(
            "Unable to construct a meaningful query. "
            "Empty queries would return all records and are not allowed. "
            "Please provide more specific filters or natural language intent."
        )

    metadata: Dict[str, Any] = {
        "dataset": dataset_key,
        "dataset_display_name": None,
        "boolean_operator": operator,
        "inferred_conditions": expression_details,
        "conditions_count": len(expression_details),
    }

    if dataset_key:
        dataset_meta = schema.get("datasets", {}).get(dataset_key, {})
        display_name = dataset_meta.get("name")
        if isinstance(display_name, str):
            metadata["dataset_display_name"] = display_name
        metadata["dataset_metadata"] = dataset_meta.get("metadata", {})

    return query, metadata
