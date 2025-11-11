from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Sequence, Tuple

try:
    from .schema_loader import CortexSchemaCache, normalise_dataset
except ImportError:  # pragma: no cover - fallback when package layout unavailable
    from schema_loader import CortexSchemaCache, normalise_dataset  # type: ignore

DEFAULT_DATASET = "xdr_data"
DEFAULT_LIMIT = 100
MAX_LIMIT = 10000

_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(
    r"\b(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r":(?:[0-9a-fA-F]{1,4}:){1,7}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|"
    r":(?::[0-9a-fA-F]{1,4}){1,7}|"
    r"::"
    r")\b"
)
_PROCESS_RE = re.compile(r"\b([A-Za-z0-9_\-]+\.exe)\b", re.IGNORECASE)
_FILE_PATH_RE = re.compile(
    r"((?:[A-Za-z]:\\\\?|\\\\)\\?(?:[^\\/:\n]+\\\\)*[^\\/:\n]+|/(?:[^/\s]+/)*[^/\s]+)"
)
_TIME_RANGE_RE = re.compile(
    r"(?:last|past)\s+(?:(\d+)\s+)?(minute|hour|day|week|month)s?",
    re.IGNORECASE,
)
_DOMAIN_RE = re.compile(
    r"\b(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,})\b"
)
_HOST_PHRASE_RE = re.compile(
    r"(?:host|hostname|server|agent)\s+(?:named\s+)?['\"]?([A-Za-z0-9_.-]{2,})['\"]?",
    re.IGNORECASE,
)

_KNOWN_PROCESS_ALIASES = {
    "powershell": "powershell.exe",
    "cmd": "cmd.exe",
    "command prompt": "cmd.exe",
    "wmic": "wmic.exe",
    "mshta": "mshta.exe",
    "cscript": "cscript.exe",
    "wscript": "wscript.exe",
}

_HOST_KEYWORDS = {"host", "hostname", "agent", "endpoint", "machine", "server"}


class QueryBuildError(ValueError):
    """Raised when a Cortex XDR XQL query cannot be constructed."""


def _collect_fields(field_map: Dict[str, Dict[str, Any]]) -> Iterable[str]:
    return field_map.keys()


def _derive_default_fields(
    field_groups: Dict[str, Any],
    field_map: Dict[str, Dict[str, Any]],
) -> List[str]:
    """Derive a sensible default field selection from schema metadata."""

    if not field_groups or not field_map:
        return []

    preferred_groups = [
        "system_fields",
        "event_fields",
        "actor_fields",
        "action_fields",
        "agent_fields",
        "auth_fields",
        "dst_fields",
    ]

    seen: set[str] = set()
    results: List[str] = []

    def append_field(name: str) -> None:
        if name in field_map and name not in seen:
            seen.add(name)
            results.append(name)

    for group in preferred_groups:
        meta = field_groups.get(group)
        if not isinstance(meta, dict):
            continue
        raw_fields = meta.get("key_fields") or meta.get("fields")
        if isinstance(raw_fields, list):
            for entry in raw_fields:
                if isinstance(entry, str):
                    append_field(entry)

    if not results:
        for name, meta in field_map.items():
            if isinstance(meta, dict) and meta.get("default_field"):
                append_field(name)

    if not results:
        for candidate in ["_time", "agent_hostname", "actor_process_image_name", "action_process_image_name"]:
            append_field(candidate)

    return results[:6]


def _field_if_available(candidates: Sequence[str], available_fields: Iterable[str]) -> str | None:
    available = set(available_fields)
    for candidate in candidates:
        if candidate in available:
            return candidate
    return None


def _format_literal(value: str) -> str:
    if value.startswith("'") and value.endswith("'"):
        return value
    escaped = value.replace("'", "\\'")
    return f"'{escaped}'"


def _format_value(value: Any) -> str:
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, str):
        trimmed = value.strip()
        if not trimmed:
            return "''"
        if trimmed.startswith("ENUM."):
            return trimmed
        if trimmed.startswith("interval "):
            return trimmed
        if "(" in trimmed or trimmed.endswith("()") or "current_time()" in trimmed:
            return trimmed
        if trimmed[0] in {"'", '"'} and trimmed[-1] == trimmed[0]:
            if trimmed[0] == '"':
                trimmed = trimmed[1:-1].replace("'", "\\'")
                return f"'{trimmed}'"
            return trimmed
        return _format_literal(trimmed)
    return _format_literal(str(value))


def _format_filter(field: str, operator: str, value: Any) -> str:
    """
    Format a filter expression for Cortex XQL queries.

    ACCURACY FIX: Validate that field is not None to prevent malformed queries.

    Args:
        field: Field name (must not be None or empty)
        operator: Comparison operator
        value: Value to compare

    Returns:
        Formatted filter expression

    Raises:
        ValueError: If field is None or empty
    """
    if not field or field is None:
        raise ValueError(
            "Field name cannot be None or empty. "
            "This likely means the requested field is not available for the selected dataset."
        )

    op = operator.strip()
    if op.lower() == "in" and isinstance(value, (list, tuple, set)):
        formatted = ", ".join(_format_value(v) for v in value)
        return f"{field} in ({formatted})"
    formatted_value = _format_value(value)
    return f"{field} {op} {formatted_value}"


def _get_time_filter_from_schema(
    time_range_input: str,
    time_filter_schema: Dict[str, Any],
) -> str | None:
    """
    Map a time range input to the correct XQL syntax from schema.
    
    Args:
        time_range_input: User input like "7 days", "24 hours", "last_7_days"
        time_filter_schema: Time filter configuration from schema
        
    Returns:
        XQL time filter expression or None if not found
    """
    if not time_filter_schema:
        return None
    
    # Normalize input
    normalized = time_range_input.strip().lower().replace(" ", "_")
    
    # Check presets
    presets = time_filter_schema.get("presets", {})
    if isinstance(presets, dict):
        # Direct preset match (e.g., "last_7_days")
        if normalized in presets:
            preset = presets[normalized]
            if isinstance(preset, dict):
                return preset.get("syntax")
        
        # Try with "last_" prefix added
        with_last = f"last_{normalized}"
        if with_last in presets:
            preset = presets[with_last]
            if isinstance(preset, dict):
                return preset.get("syntax")
        
        # Try without "last_" prefix
        if normalized.startswith("last_"):
            alt_key = normalized[5:]  # Remove "last_"
            if alt_key in presets:
                preset = presets[alt_key]
                if isinstance(preset, dict):
                    return preset.get("syntax")
    
    # Parse quantity + unit pattern (e.g., "7 days", "24 hours")
    # Handle both with and without spaces
    input_for_parsing = time_range_input.strip().lower()
    match = re.match(r"(\d+)\s*(second|minute|hour|day|week|month)s?", input_for_parsing)
    if match:
        quantity = match.group(1)
        unit = match.group(2)
        
        # Validate unit against schema
        custom = time_filter_schema.get("custom", {})
        relative = custom.get("relative", {})
        if isinstance(relative, dict):
            valid_units = relative.get("units", [])
            if unit in valid_units:
                return f"_time > current_time() - interval '{quantity} {unit}'"
    
    return None


def _extract_time_filters(
    intent: str,
    time_filter_schema: Dict[str, Any],
) -> Tuple[List[str], List[Tuple[int, int]], List[Dict[str, Any]]]:
    """
    Extract time filters from natural language intent using schema definitions.
    
    Args:
        intent: Natural language query intent
        time_filter_schema: Time filter configuration from schema
        
    Returns:
        Tuple of (filter expressions, span positions, metadata)
    """
    filters: List[str] = []
    spans: List[Tuple[int, int]] = []
    metadata: List[Dict[str, Any]] = []
    
    for match in _TIME_RANGE_RE.finditer(intent):
        quantity = match.group(1) or "1"
        unit = match.group(2).lower()
        
        # Try to get syntax from schema
        time_input = f"{quantity} {unit}"
        expression = _get_time_filter_from_schema(time_input, time_filter_schema)
        
        if not expression:
            # Fallback to constructed syntax
            expression = f"_time > current_time() - interval '{quantity} {unit}'"
        
        filters.append(expression)
        spans.append(match.span())
        metadata.append({"type": "time_range", "value": f"last {quantity} {unit}"})
    
    return filters, spans, metadata


def _extract_natural_language_filters(
    intent: str,
    field_map: Dict[str, Dict[str, Any]],
) -> Tuple[List[str], List[Tuple[int, int]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    expressions: List[str] = []
    spans: List[Tuple[int, int]] = []
    metadata: List[Dict[str, Any]] = []
    unmatched: List[Dict[str, Any]] = []
    available_fields = list(_collect_fields(field_map))

    pattern_definitions = [
        ("md5", _MD5_RE, ["action_file_md5", "action_process_image_md5"]),
        ("sha256", _SHA256_RE, ["action_file_sha256", "action_process_image_sha256"]),
        (
            "ipv4",
            _IPV4_RE,
            ["action_local_ip", "action_remote_ip", "src_ip", "dst_ip"],
        ),
        (
            "ipv6",
            _IPV6_RE,
            ["action_local_ip", "action_remote_ip", "src_ip", "dst_ip"],
        ),
        (
            "domain",
            _DOMAIN_RE,
            [
                "action_domain",
                "remote_domain",
                "dns_query_name",
                "domain",
                "agent_hostname",
            ],
        ),
    ]

    for label, regex, candidates in pattern_definitions:
        for match in regex.finditer(intent):
            field = _field_if_available(candidates, available_fields)
            if not field:
                spans.append(match.span())
                unmatched.append({"type": label, "field": None, "value": match.group(0)})
                continue
            value = match.group(0)
            operator = "contains" if label == "domain" else "="
            expression = _format_filter(field, operator, value)
            expressions.append(expression)
            spans.append(match.span())
            metadata.append({"type": label, "field": field, "value": value})

    # Process names
    for match in _PROCESS_RE.finditer(intent):
        field = _field_if_available(["actor_process_image_name", "action_file_name"], available_fields)
        if not field:
            continue
        value = match.group(1)
        expression = _format_filter(field, "=", value.lower())
        expressions.append(expression)
        spans.append(match.span())
        metadata.append({"type": "process_name", "field": field, "value": value.lower()})

    # File paths
    for match in _FILE_PATH_RE.finditer(intent):
        field = _field_if_available(["action_file_path", "actor_process_image_path"], available_fields)
        if not field:
            continue
        value = match.group(1)
        expression = _format_filter(field, "=", value)
        expressions.append(expression)
        spans.append(match.span())
        metadata.append({"type": "file_path", "field": field, "value": value})

    # Hostname phrases
    for match in _HOST_PHRASE_RE.finditer(intent):
        field = _field_if_available(
            ["agent_hostname", "dest_agent_hostname", "src_agent_hostname"],
            available_fields,
        )
        if not field:
            continue
        value = match.group(1)
        expression = _format_filter(field, "contains", value.lower())
        expressions.append(expression)
        spans.append(match.span())
        metadata.append({"type": "hostname", "field": field, "value": value})

    return expressions, spans, metadata, unmatched


def _extract_keywords(intent: str, spans: List[Tuple[int, int]]) -> List[str]:
    if not intent:
        return []
    chars = list(intent)
    for start, end in spans:
        for idx in range(start, min(end, len(chars))):
            chars[idx] = " "
    residual = re.sub(r"\s+", " ", "".join(chars)).strip()
    if not residual:
        return []
    keywords: List[str] = []
    for token in re.split(r"[;,]", residual):
        token = token.strip()
        if not token:
            continue
        if token.lower() in _HOST_KEYWORDS:
            continue
        keywords.extend(re.findall(r"[A-Za-z0-9_.-]+", token))
    return keywords


def _resolve_process_aliases(keywords: Iterable[str]) -> List[str]:
    resolved: List[str] = []
    for keyword in keywords:
        lowered = keyword.lower()
        if lowered in _KNOWN_PROCESS_ALIASES:
            resolved.append(_KNOWN_PROCESS_ALIASES[lowered])
        elif lowered.endswith(".exe"):
            resolved.append(lowered)
    return resolved


def build_cortex_query(
schema: Dict[str, Any] | CortexSchemaCache,
    dataset: str = DEFAULT_DATASET,
    filters: Sequence[Dict[str, Any]] | Dict[str, Any] | None = None,
    fields: Sequence[str] | None = None,
    natural_language_intent: str | None = None,
    time_range: str | Dict[str, Any] | None = None,
    limit: int | None = None,
    rag_context: List[Dict[str, Any]] | None = None,
) -> Tuple[str, Dict[str, Any]]:
    """Construct an XQL query using the provided parameters and heuristics.
    
    Args:
        schema: Cortex schema dictionary or CortexSchemaCache instance
        dataset: Dataset name to query
        filters: Filter conditions (dict or list of dicts)
        fields: List of fields to select
        natural_language_intent: Natural language description
        time_range: Time range filter
        limit: Maximum number of results
        rag_context: Optional RAG-retrieved documents for query enhancement
        
    Returns:
        Tuple of (query_string, metadata_dict)
    """

    payload: Dict[str, Any]
    field_map: Dict[str, Dict[str, Any]]

    if not isinstance(schema, (dict, CortexSchemaCache)):
        raise TypeError("schema must be a mapping or CortexSchemaCache instance")

    cleaned_intent: str | None = None
    if natural_language_intent is not None:
        if not isinstance(natural_language_intent, str):
            raise TypeError("natural_language_intent must be a string if provided")
        cleaned_intent = natural_language_intent.strip()
        if not cleaned_intent:
            raise ValueError("natural_language_intent must not be empty")

    has_structured_inputs = filters is not None or bool(time_range)
    if cleaned_intent is None and natural_language_intent is None and not has_structured_inputs:
        raise ValueError("Either natural_language_intent or structured parameters must be provided")

    dataset_meta: Dict[str, Any] | None = None

    field_groups: Dict[str, Any] = {}

    # Load time filter schema
    time_filter_schema: Dict[str, Any] = {}
    if isinstance(schema, CortexSchemaCache):
        payload = schema.load()
        available_datasets = schema.datasets()
        field_map = schema.field_map_for(dataset)
        dataset_meta = available_datasets.get(dataset) if isinstance(available_datasets, dict) else None
        field_groups = schema.field_groups()
        time_filter_schema = schema.time_filters()
    else:
        payload = schema
        available_datasets = payload.get("datasets", {}) if isinstance(payload, dict) else {}
        field_map = {}
        mapping = CortexSchemaCache.DATASET_FIELD_MAP
        if isinstance(payload, dict) and dataset in mapping:
            raw_fields = payload.get(mapping[dataset], {})
            if isinstance(raw_fields, dict):
                field_map = raw_fields
        if isinstance(available_datasets, dict):
            dataset_meta = available_datasets.get(dataset)
        if isinstance(payload, dict):
            raw_groups = payload.get("field_groups", {})
            field_groups = raw_groups if isinstance(raw_groups, dict) else {}
            time_filter_schema = payload.get("time_filters", {})
            if not isinstance(time_filter_schema, dict):
                time_filter_schema = {}

    available_names: List[str] = []
    if isinstance(available_datasets, dict):
        available_names.extend(available_datasets.keys())

    dataset_mapping_keys: Iterable[str]
    if isinstance(schema, CortexSchemaCache):
        dataset_mapping_keys = schema.DATASET_FIELD_MAP.keys()
    else:
        dataset_mapping_keys = CortexSchemaCache.DATASET_FIELD_MAP.keys()

    for name in dataset_mapping_keys:
        if name not in available_names:
            available_names.append(name)

    chosen_dataset, normalisation_log = normalise_dataset(dataset, available_names)
    if isinstance(schema, CortexSchemaCache):
        field_map = schema.field_map_for(chosen_dataset)
        datasets_info = schema.datasets()
        if isinstance(datasets_info, dict):
            dataset_meta = datasets_info.get(chosen_dataset)
        field_groups = schema.field_groups()
    else:
        mapping = CortexSchemaCache.DATASET_FIELD_MAP
        field_map = {}
        if isinstance(payload, dict):
            mapped_key = mapping.get(chosen_dataset)
            raw_fields = payload.get(mapped_key, {}) if mapped_key else {}
            if isinstance(raw_fields, dict):
                field_map = raw_fields
        if isinstance(available_datasets, dict):
            dataset_meta = available_datasets.get(chosen_dataset)
        if isinstance(payload, dict):
            raw_groups = payload.get("field_groups", {})
            field_groups = raw_groups if isinstance(raw_groups, dict) else {}

    stages: List[str] = [f"dataset = {chosen_dataset}"]
    recognised: List[Dict[str, Any]] = []
    selected_fields: List[str] = []
    has_time_filter = False

    def add_filter_stage(expression: str, meta: Dict[str, Any]) -> None:
        stages.append(f"| filter {expression}")
        recognised.append(meta)

    # Security Concept Expansion: Detect and expand security concepts
    if cleaned_intent:
        try:
            import logging
            from shared.security_concepts import detect_security_concepts, generate_concept_hints, get_concept_description

            logger = logging.getLogger(__name__)
            detected_concepts = detect_security_concepts(cleaned_intent)
            if detected_concepts:
                concept_hints = generate_concept_hints(detected_concepts, "cortex")
                available_fields = list(_collect_fields(field_map))

                # Build OR-combined filter expressions for each concept category
                for keyword_category, keywords in concept_hints.items():
                    # Map hint category to Cortex field names
                    field_mapping = {
                        "process_keywords": ["actor_process_image_name", "causality_actor_process_image_name", "action_process_image_name"],
                        "cmdline_keywords": ["actor_process_command_line"],
                        "port_keywords": ["action_local_port", "action_remote_port"],
                        "domain_keywords": ["dst_action_external_hostname"],
                        "registry_keywords": ["action_registry_key_name"],
                    }

                    candidate_fields = field_mapping.get(keyword_category, [])
                    field = _field_if_available(candidate_fields, available_fields)
                    if not field:
                        continue

                    # Create OR-combined expressions for multiple values
                    if keyword_category in ["process_keywords", "cmdline_keywords", "domain_keywords", "registry_keywords"]:
                        # String fields use 'in' operator for multiple values
                        if keywords:
                            filter_expr = _format_filter(field, "in", keywords)
                            add_filter_stage(filter_expr, {
                                "type": "concept_expansion",
                                "concepts": list(detected_concepts),
                                "field": field,
                                "values": keywords,
                            })
                    elif keyword_category == "port_keywords":
                        # Numeric fields use 'in' operator
                        if keywords:
                            port_values = [int(p) for p in keywords if p.isdigit()]
                            if port_values:
                                filter_expr = _format_filter(field, "in", port_values)
                                add_filter_stage(filter_expr, {
                                    "type": "concept_expansion",
                                    "concepts": list(detected_concepts),
                                    "field": field,
                                    "values": port_values,
                                })

                concept_descriptions = [get_concept_description(c) for c in detected_concepts]
                logger.info(f"Detected security concepts: {', '.join(detected_concepts)}")
                logger.info(f"Added {len([r for r in recognised if r.get('type') == 'concept_expansion'])} concept-based filter stages")

        except Exception as e:
            # Concept expansion is optional - don't fail the query if it errors
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Security concept expansion failed, continuing without it: {e}")

    # RAG-Enhanced Query Building: Extract additional filters from RAG context
    if rag_context and cleaned_intent:
        try:
            import logging
            from shared.rag_context_parser import create_rag_context_parser
            
            logger = logging.getLogger(__name__)
            parser = create_rag_context_parser("cortex")
            parsed_context = parser.parse_context(
                rag_context,
                cleaned_intent,
                chosen_dataset
            )
            
            logger.info(f"RAG parsed context for Cortex: fields={parsed_context['fields']}, "
                       f"values={parsed_context['values']}, "
                       f"confidence={parsed_context['confidence']}")
            
            # Use RAG enhancements with low confidence threshold (RAG-first approach)
            # Goal: Comprehensive one-shot queries that cover multiple indicators
            if parsed_context["confidence"] >= 0.1:
                # Extract field:value pairs from RAG context
                for field in parsed_context["fields"][:10]:  # Top 10 fields for comprehensive coverage
                    if field not in field_map:
                        logger.info(f"Field {field} not in field_map for Cortex, skipping")
                        continue
                    
                    values = parsed_context["values"].get(field, [])
                    for value in values[:7]:  # Top 7 values per field for comprehensive coverage
                        # Format the Cortex filter expression (field = 'value' or field contains 'value')
                        if any(keyword in value.lower() for keyword in ['.exe', '.dll', 'http', 'www', 'domain']):
                            # Likely a filename, URL, or domain - use contains
                            expression = _format_filter(field, "contains", value)
                        else:
                            # Use equality
                            expression = _format_filter(field, "=", value)
                        
                        add_filter_stage(expression, {
                            "type": "rag_enhanced",
                            "field": field,
                            "value": value,
                            "confidence": parsed_context["confidence"]
                        })
                        logger.info(f"Added RAG enhanced Cortex filter: {expression}")
                
                if len([r for r in recognised if r.get("type") == "rag_enhanced"]) > 0:
                    logger.info(f"Added {len([r for r in recognised if r.get('type') == 'rag_enhanced'])} RAG enhanced filters to Cortex query")
            else:
                logger.info(f"RAG confidence too low for Cortex: {parsed_context['confidence']}")
                
        except Exception as e:
            # RAG enhancement is optional - don't fail the query if it errors
            import logging
            logging.getLogger(__name__).warning(f"RAG enhancement failed for Cortex, continuing without it: {e}")

    structured_filters: Sequence[Dict[str, Any]] = []
    if filters:
        if isinstance(filters, dict):
            structured_filters = [filters]
        else:
            structured_filters = list(filters)

    for item in structured_filters:
        field = item.get("field") if isinstance(item, dict) else None
        operator = item.get("operator", "=") if isinstance(item, dict) else "="
        value = item.get("value") if isinstance(item, dict) else None
        if not field:
            continue
        if field_map and field not in field_map:
            raise KeyError(f"Field '{field}' is not available for dataset '{chosen_dataset}'")
        expression = _format_filter(field, operator, value)
        add_filter_stage(expression, {"type": "structured", "field": field, "operator": operator, "value": value})

    if cleaned_intent:
        nl_filters, spans, meta, unmatched_meta = _extract_natural_language_filters(cleaned_intent, field_map)
        for expression, entry in zip(nl_filters, meta):
            add_filter_stage(expression, entry)

        if unmatched_meta:
            recognised.extend(unmatched_meta)

        keyword_candidates = _extract_keywords(cleaned_intent, spans)
        process_names = _resolve_process_aliases(keyword_candidates)
        if process_names:
            field = _field_if_available(["actor_process_image_name", "action_file_name"], field_map)
            if field:
                expression = _format_filter(field, "in", sorted(set(process_names)))
                add_filter_stage(
                    expression,
                    {"type": "process_keyword", "field": field, "value": process_names},
                )
        if re.search(r"process|execution", cleaned_intent, re.IGNORECASE):
            field = _field_if_available(["event_type"], field_map)
            if field:
                add_filter_stage(
                    _format_filter(field, "=", "ENUM.PROCESS"),
                    {"type": "event_type", "field": field, "value": "ENUM.PROCESS"},
                )
        time_filters, time_spans, time_meta = _extract_time_filters(cleaned_intent, time_filter_schema)
        for expression, meta_entry in zip(time_filters, time_meta):
            add_filter_stage(expression, meta_entry)
            has_time_filter = True
        spans.extend(time_spans)

    if time_range:
        if isinstance(time_range, str):
            # Try to map string time_range to schema syntax
            schema_expression = _get_time_filter_from_schema(time_range, time_filter_schema)
            expression = schema_expression if schema_expression else time_range
            add_filter_stage(expression, {"type": "time_range", "value": time_range})
            has_time_filter = True
        elif isinstance(time_range, dict):
            field = time_range.get("field", "_time")
            operator = time_range.get("operator", ">")
            value = time_range.get("value", "current_time() - interval '1 hour'")
            expression = _format_filter(field, operator, value)
            add_filter_stage(
                expression,
                {"type": "time_range", "field": field, "operator": operator, "value": value},
            )
            has_time_filter = True

    # Add default 7-day time filter if no time filter was specified
    if not has_time_filter:
        default_time_filter = "_time > current_time() - interval '7 days'"
        add_filter_stage(
            default_time_filter,
            {"type": "time_range", "value": "default 7 days", "default": True}
        )
        has_time_filter = True

    if fields:
        cleaned_fields = [field.strip() for field in fields if field]
        if cleaned_fields:
            stages.append(f"| fields {', '.join(cleaned_fields)}")
            selected_fields = cleaned_fields
    else:
        default_fields: Sequence[str] | None = None
        if dataset_meta and isinstance(dataset_meta, dict):
            raw_default = dataset_meta.get("default_fields")
            if isinstance(raw_default, list) and raw_default:
                default_fields = [str(field).strip() for field in raw_default if field]
        if not default_fields and field_groups:
            default_fields = _derive_default_fields(field_groups, field_map)
        if default_fields:
            formatted_fields = [field for field in default_fields if field]
            if formatted_fields:
                stages.append(f"| fields {', '.join(formatted_fields)}")
                selected_fields = list(formatted_fields)

    if limit is None:
        effective_limit = DEFAULT_LIMIT
    else:
        try:
            numeric_limit = int(limit)
        except (TypeError, ValueError) as exc:
            raise ValueError("limit must be an integer") from exc
        if numeric_limit <= 0:
            raise ValueError("limit must be a positive integer")
        effective_limit = min(numeric_limit, MAX_LIMIT)
    stages.append(f"| limit {effective_limit}")

    metadata = {
        "dataset": chosen_dataset,
        "normalisation": normalisation_log,
        "recognised": recognised,
        "limit": effective_limit,
        "has_time_filter": has_time_filter,
    }

    if selected_fields:
        metadata["fields"] = selected_fields

    return "\n".join(stages), metadata
