from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from .schema_loader import normalise_search_type


DEFAULT_SEARCH_TYPE = "server_event"
DEFAULT_BOOLEAN_OPERATOR = "AND"
SUPPORTED_BOOLEAN_OPERATORS = {"AND", "OR"}
MAX_LIMIT = 5000

# Security: Input length limits to prevent ReDoS and resource exhaustion
MAX_INTENT_LENGTH = 10000  # 10KB max for natural language intent
MAX_VALUE_LENGTH = 2000  # 2KB max for individual field values

_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(
    r"(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"  # Full address
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"  # Compressed with trailing ::
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"  # Compressed with 1 group after
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"  # Compressed with 2 groups after
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"  # Compressed with 3 groups after
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"  # Compressed with 4 groups after
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"  # Compressed with 5 groups after
    r"[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|"  # Compressed with 6 groups after
    r":(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))"  # Leading :: or just ::
)
_PORT_RE = re.compile(r"\bport\s*(?:=|is)?\s*(\d{1,5})\b", re.IGNORECASE)
# SECURITY FIX: Limit quantifier to prevent ReDoS on very long quoted strings
_QUOTED_VALUE_RE = re.compile(r'"([^"]{1,2000})"|\'([^\']{1,2000})\'')

_PROCESS_NAME_RE = re.compile(
    r"(?:process(?:es)?|binary)\s+(?:name\s*(?:is|=|equals|was)?|named)\s+[\"']?([A-Za-z0-9_.-]+)[\"']?",
    re.IGNORECASE,
)
_CMDLINE_RE = re.compile(
    r"(?:cmdline|command\s+line)\s+(?:contains|includes|containing|with)?\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_PATH_RE = re.compile(
    r"(?:path|file\s+path)\s+(?:is|=|equals)?\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_USERNAME_RE = re.compile(
    r"user(?:name)?\s+(?:is|=|equals|running\s+as)?\s*[\"']?([A-Za-z0-9_@.-]+)[\"']?",
    re.IGNORECASE,
)
_DOMAIN_RE = re.compile(
    r"domain\s+(?:is|=|equals|contains|to)?\s*[\"']?([A-Za-z0-9_.-]+(?:\.[A-Za-z0-9_.-]+)*)[\"']?",
    re.IGNORECASE,
)
_PROCESS_GUID_RE = re.compile(
    r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}-[a-f0-9]{16}\b",
    re.IGNORECASE,
)

_STOPWORDS = {
    "find",
    "show",
    "me",
    "all",
    "process",
    "processes",
    "with",
    "that",
    "where",
    "which",
    "the",
    "a",
    "an",
    "for",
    "running",
    "binary",
    "alerts",
    "alert",
    "search",
    "event",
    "events",
}


class QueryBuildError(ValueError):
    """Raised when we cannot construct a valid query."""


def _quote_if_needed(value: str) -> str:
    """Quote value if it contains spaces or special characters."""
    cleaned = value.strip()
    if not cleaned:
        return cleaned
    cleaned = cleaned.replace("\"", r"\"")
    if any(ch.isspace() for ch in cleaned) or ":" in cleaned:
        return f'"{cleaned}"'
    return cleaned


def _sanitise_term(term: str) -> str:
    """Sanitize term by removing/escaping dangerous characters."""
    cleaned = term.strip()
    if not cleaned:
        return ""
    if any(ch in cleaned for ch in [";", "|", "(", ")", "{", "}"]):
        raise QueryBuildError(f"Unsafe characters detected in term '{term}'")
    # Escape backslashes for Windows paths
    cleaned = cleaned.replace("\\", "\\\\")
    return cleaned


def _field_if_available(candidates: Sequence[str], available_fields: Iterable[str]) -> str | None:
    """Return first candidate field that exists in available_fields."""
    for candidate in candidates:
        if candidate in available_fields:
            return candidate
    return None


def _collect_fields(field_map: Dict[str, Dict[str, Any]]) -> List[str]:
    """Collect all field names from field map."""
    return list(field_map.keys())


def _extract_patterns(intent: str, field_map: Dict[str, Dict[str, Any]]) -> Tuple[List[str], List[Tuple[int, int]], List[Dict[str, Any]]]:
    """
    Extract patterns from natural language intent.

    Security: Validates input length to prevent ReDoS attacks.
    """
    # Security: Validate input length to prevent ReDoS attacks
    if len(intent) > MAX_INTENT_LENGTH:
        raise ValueError(f"Intent exceeds maximum length of {MAX_INTENT_LENGTH} characters")

    expressions: List[str] = []
    spans: List[Tuple[int, int]] = []
    metadata: List[Dict[str, Any]] = []
    available_fields = _collect_fields(field_map)

    # IOC patterns adapted for CBR field names
    pattern_definitions = [
        ("md5", _MD5_RE, ["md5", "process_md5", "parent_md5"]),
        ("sha256", _SHA256_RE, ["sha256"]),  # May not be in all CBR schemas
        ("ipv4", _IPV4_RE, ["ipv4", "remote_ip", "local_ip", "proxy_ip"]),
        ("ipv6", _IPV6_RE, ["ipv6"]),  # May not be in all CBR schemas (note: likely not present)
        ("process_guid", _PROCESS_GUID_RE, ["process_guid", "parent_process_guid", "child_process_guid", "target_process_guid"]),
    ]

    for label, regex, candidates in pattern_definitions:
        for match in regex.finditer(intent):
            field = _field_if_available(candidates, available_fields)
            # For IPv6, skip if field not available (it's not in most CBR schemas)
            if not field and label == "ipv6":
                continue
            # For other patterns, if no field available, treat as keyword instead of skipping
            if not field:
                continue
            value = match.group(0)
            expressions.append(f"{field}:{_sanitise_term(value)}")
            spans.append(match.span())
            metadata.append({"type": label, "field": field, "value": value})

    # Explicit constructs
    explicit_patterns = [
        ("process_name", _PROCESS_NAME_RE, ["process_name", "observed_filename", "parent_name"]),
        ("cmdline", _CMDLINE_RE, ["cmdline", "command_line"]),
        ("path", _PATH_RE, ["path", "observed_filename", "parent_path", "target_path"]),
        ("username", _USERNAME_RE, ["username"]),
        ("domain", _DOMAIN_RE, ["domain", "proxy_domain"]),
    ]

    for label, regex, candidates in explicit_patterns:
        for match in regex.finditer(intent):
            field = _field_if_available(candidates, available_fields)
            if not field:
                continue
            value = match.group(1)
            if not value:
                continue
            formatted = _quote_if_needed(_sanitise_term(value))
            expressions.append(f"{field}:{formatted}")
            spans.append(match.span())
            metadata.append({"type": label, "field": field, "value": value})

    # Ports
    for match in _PORT_RE.finditer(intent):
        field = _field_if_available(["port", "remote_port", "local_port", "proxy_port"], available_fields)
        if not field:
            continue
        value = match.group(1)
        expressions.append(f"{field}:{value}")
        spans.append(match.span())
        metadata.append({"type": "port", "field": field, "value": value})

    return expressions, spans, metadata


def _residual_terms(intent: str, spans: List[Tuple[int, int]]) -> List[str]:
    """Extract residual keywords after removing structured patterns."""
    if not intent:
        return []

    chars = list(intent)
    for start, end in spans:
        for idx in range(start, min(end, len(chars))):
            chars[idx] = " "

    residual = re.sub(r"\s+", " ", "".join(chars)).strip()
    if not residual:
        return []

    terms: List[str] = []
    for token in re.split(r"[;,]", residual):
        token = token.strip()
        if not token:
            continue
        # Remove quoted substrings to avoid duplication
        token = _QUOTED_VALUE_RE.sub(lambda m: m.group(1) or m.group(2) or "", token)
        words = [w for w in re.split(r"[^A-Za-z0-9_.-]+", token) if w]
        filtered = [w for w in words if w.lower() not in _STOPWORDS and len(w) > 2]
        for word in filtered:
            terms.append(word)
    return terms


def _compose_query(expressions: List[str], boolean_operator: str) -> str:
    """Compose final query string from expressions."""
    if not expressions:
        raise QueryBuildError("No search terms could be derived from the provided input")
    return f" {boolean_operator} ".join(expressions)


def build_cbr_query(
    schema: Dict[str, Any],
    *,
    search_type: str | None = None,
    terms: Sequence[str] | None = None,
    natural_language_intent: str | None = None,
    boolean_operator: str = DEFAULT_BOOLEAN_OPERATOR,
    limit: int | None = None,
    rag_context: List[Dict[str, Any]] | None = None,
) -> Tuple[str, Dict[str, Any]]:
    """Build a Carbon Black Response (CBR) query string and return metadata.

    Args:
        schema: CBR schema dictionary
        search_type: Type of search (server_event, endpoint_event, or granular types)
        terms: List of structured search terms
        natural_language_intent: Natural language description of what to find
        boolean_operator: Boolean operator to combine terms (AND/OR)
        limit: Maximum number of results
        rag_context: Optional RAG-retrieved documents for query enhancement

    Returns:
        Tuple of (query_string, metadata_dict)
    """

    search_types = schema.get("search_types", {})
    chosen_search_type, normalisation_log = normalise_search_type(
        search_type or DEFAULT_SEARCH_TYPE, search_types.keys()
    )

    field_map = {}
    if hasattr(schema, "field_map_for"):
        # Support callers who pass CBResponseSchemaCache.load()
        field_map = schema.field_map_for(chosen_search_type)  # type: ignore[attr-defined]
    else:
        # schema may already be the payload
        # CBR uses merged field sets for server_event and endpoint_event
        field_map = schema.get(f"{chosen_search_type}_fields", {})

    expressions: List[str] = []
    recognised: List[Dict[str, Any]] = []

    # Security Concept Expansion: Detect and expand security concepts
    concept_hints: Dict[str, List[str]] = {}
    detected_concepts: set = set()
    if natural_language_intent:
        try:
            from queryforge.shared.security_concepts import detect_security_concepts, generate_concept_hints, get_concept_description

            detected_concepts = detect_security_concepts(natural_language_intent)
            if detected_concepts:
                concept_hints = generate_concept_hints(detected_concepts, "cbr")

                # Add concept-based expressions to the query
                available_fields = _collect_fields(field_map)
                for keyword_category, keywords in concept_hints.items():
                    # Map hint category to CBR field names
                    field_mapping = {
                        "process_keywords": ["process_name", "parent_name", "observed_filename"],
                        "cmdline_keywords": ["cmdline", "command_line"],
                        "port_keywords": ["remote_port", "local_port", "port", "proxy_port"],
                        "domain_keywords": ["domain", "proxy_domain"],
                        "registry_keywords": ["path"],  # For regmod events
                    }

                    candidate_fields = field_mapping.get(keyword_category, [])
                    field = _field_if_available(candidate_fields, available_fields)
                    if not field:
                        continue

                    # Add expressions for each keyword
                    for keyword in keywords:
                        formatted_keyword = _quote_if_needed(_sanitise_term(keyword))
                        expression = f"{field}:{formatted_keyword}"
                        expressions.append(expression)
                        recognised.append({
                            "type": "concept_expansion",
                            "concepts": list(detected_concepts),
                            "field": field,
                            "value": keyword,
                        })

                # Add metadata about concept detection
                import logging
                concept_descriptions = [get_concept_description(c) for c in detected_concepts]
                logging.info(f"Detected security concepts: {', '.join(detected_concepts)}")
                logging.info(f"Added {len([r for r in recognised if r.get('type') == 'concept_expansion'])} concept-based expressions")

        except Exception as e:
            # Concept expansion is optional - don't fail the query if it errors
            import logging
            logging.warning(f"Security concept expansion failed, continuing without it: {e}")
    
    # RAG-Enhanced Query Building: Extract additional terms from RAG context
    rag_enhanced_terms: List[str] = []
    if rag_context and natural_language_intent:
        try:
            from queryforge.shared.rag_context_parser import create_rag_context_parser
            
            parser = create_rag_context_parser("cbr")
            parsed_context = parser.parse_context(
                rag_context,
                natural_language_intent,
                chosen_search_type
            )
            
            # Debug: Print parsed context info
            import logging
            logging.info(f"RAG parsed context: fields={parsed_context['fields']}, "
                        f"values={parsed_context['values']}, "
                        f"confidence={parsed_context['confidence']}")
            
            # Use RAG enhancements with low confidence threshold (RAG-first approach)
            # Goal: Comprehensive one-shot queries that cover multiple indicators
            if parsed_context["confidence"] >= 0.1:
                # Extract field:value pairs from RAG context
                for field in parsed_context["fields"][:10]:  # Top 10 fields for comprehensive coverage
                    if field not in field_map:
                        logging.info(f"Field {field} not in field_map, skipping")
                        continue
                    
                    values = parsed_context["values"].get(field, [])
                    for value in values[:7]:  # Top 7 values per field for comprehensive coverage
                        # Format the field:value expression
                        formatted_value = _quote_if_needed(_sanitise_term(value))
                        expression = f"{field}:{formatted_value}"
                        rag_enhanced_terms.append(expression)
                        recognised.append({
                            "type": "rag_enhanced",
                            "field": field,
                            "value": value,
                            "confidence": parsed_context["confidence"]
                        })
                
                # Add metadata about RAG enhancement
                if rag_enhanced_terms:
                    recognised.append({
                        "type": "rag_metadata",
                        "enhanced_fields": parsed_context["fields"],
                        "confidence": parsed_context["confidence"],
                        "enhancement_count": len(rag_enhanced_terms)
                    })
                    logging.info(f"Added {len(rag_enhanced_terms)} RAG enhanced terms")
                else:
                    logging.info("No RAG enhanced terms added")
            else:
                logging.info(f"RAG confidence too low: {parsed_context['confidence']}")
                
        except Exception as e:
            # RAG enhancement is optional - don't fail the query if it errors
            import logging
            logging.warning(f"RAG enhancement failed, continuing without it: {e}")
    
    # Add RAG enhanced terms to expressions
    expressions.extend(rag_enhanced_terms)

    # BUG FIX: Validate terms type to prevent iteration over string characters
    if terms:
        if not isinstance(terms, (list, tuple)):
            raise TypeError(
                f"terms must be a list or tuple of strings, got {type(terms).__name__}. "
                f"If you have a single term, wrap it in a list: terms=['value']"
            )
        for term in terms:
            cleaned = _sanitise_term(term)
            if not cleaned:
                continue
            expressions.append(cleaned)
            recognised.append({"type": "structured", "value": cleaned})

    if natural_language_intent:
        nl_expressions, spans, meta = _extract_patterns(natural_language_intent, field_map)
        expressions.extend(nl_expressions)
        recognised.extend(meta)

        # ACCURACY FIX: Prevent duplicate conditions from pattern values appearing as keywords
        # Extract values from structured expressions to avoid re-adding them as keywords
        structured_values = set()
        for expr in nl_expressions:
            # Extract value from expressions like "process_name:cmd.exe" or "process_name:'cmd.exe'"
            if ":" in expr:
                value_part = expr.split(":", 1)[1]
                # Remove quotes if present
                value_clean = value_part.strip().strip("'\"")
                if value_clean:
                    structured_values.add(value_clean.lower())

        for token in _residual_terms(natural_language_intent, spans):
            sanitised = _sanitise_term(token)
            if not sanitised:
                continue

            # Skip if this token is already represented in structured expressions
            if sanitised.lower() in structured_values:
                continue

            expressions.append(sanitised)
            recognised.append({"type": "keyword", "value": sanitised})

    if not expressions:
        raise QueryBuildError("No expressions provided. Supply terms or natural language intent.")

    operator = boolean_operator.upper().strip()
    if operator not in SUPPORTED_BOOLEAN_OPERATORS:
        raise QueryBuildError(
            f"Unsupported boolean operator '{boolean_operator}'. Use one of: {', '.join(SUPPORTED_BOOLEAN_OPERATORS)}"
        )

    # Clamp limit if provided
    limit_value: int | None = None
    if limit is not None:
        if limit <= 0:
            raise QueryBuildError("Limit must be positive")
        limit_value = min(limit, MAX_LIMIT)

    query = _compose_query(expressions, operator)

    metadata = {
        "search_type": chosen_search_type,
        "normalisation": normalisation_log,
        "boolean_operator": operator,
        "recognised": recognised,
    }

    if limit_value is not None:
        metadata["limit"] = limit_value
        if limit_value != limit:
            metadata["limit_clamped"] = MAX_LIMIT

    return query, metadata
