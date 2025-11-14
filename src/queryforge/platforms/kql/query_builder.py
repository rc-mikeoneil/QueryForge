from __future__ import annotations
from typing import Dict, Any, List, Tuple, Optional
import re
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_TIME_WINDOW = "7d"

# Security: Input length limits to prevent ReDoS and resource exhaustion
MAX_INTENT_LENGTH = 10000  # 10KB max for natural language intent
MAX_WHERE_CLAUSE_LENGTH = 2000  # 2KB max for individual where clauses
MAX_FIELD_NAME_LENGTH = 255  # Standard field name limit

# Precompiled regexes reused across validation/parsing helpers.
# SECURITY FIX: Replaced vulnerable .*? pattern with simpler non-backtracking pattern
_WHERE_DANGEROUS_PATTERNS = (
    re.compile(r';\s*(?:drop|delete|update|insert|alter|create|truncate)', re.IGNORECASE),
    re.compile(r';\s*(?:exec|execute)\s+', re.IGNORECASE),
    re.compile(r'union\s+select', re.IGNORECASE),
    # IMPROVED: Only match SQL-style comments (-- followed by space/non-word), not command flags
    # Matches: "-- comment" or "--\n" but NOT "--retry" or "--max-time"
    re.compile(r'--\s*(?:[^-\w]|$)'),
    # SECURITY FIX: Use atomic pattern instead of .*? to prevent ReDoS
    # Changed from: r'/\*.*?\*/' which can cause catastrophic backtracking
    # To: Simpler pattern that doesn't use nested quantifiers
    re.compile(r'/\*[^*]*\*+(?:[^/*][^*]*\*+)*/', re.IGNORECASE),
)

# Allowlist patterns for legitimate command-line syntax in threat hunting queries
# These patterns are common in security detections and should not trigger validation errors
_ALLOWED_COMMAND_PATTERNS = (
    re.compile(r'--[a-z]+-[a-z]+'),  # Command flags like --retry-delay, --max-time
    re.compile(r'--[a-z]+'),          # Single-word flags like --retry, --force
    re.compile(r'\|\|'),              # Shell OR operator
    re.compile(r'&&'),                # Shell AND operator
    re.compile(r'>>'),                # Shell redirect append
    re.compile(r'<<'),                # Shell here-document
)

_ORDER_BY_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*\s+(?:asc|desc)$')
_TIME_WINDOW_VALID_PATTERN = re.compile(r'\d+[dhm]')
_TIME_WINDOW_UNIT_PATTERN = re.compile(r'(\d+)([dhm])')
_NL_TIME_WINDOW_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"(?:last|past|previous)\s+(\d+)\s*(day|days|d|hour|hours|h|minute|minutes|min|m)",
        r"(\d+)\s*(day|days|d|hour|hours|h|minute|minutes|min|m)\s+(?:ago|back|earlier)",
        r"since\s+(\d+)\s*(day|days|d|hour|hours|h|minute|minutes|min|m)\s+ago",
        r"within\s+(?:the\s+)?(?:last|past)\s+(\d+)\s*(day|days|d|hour|hours|h|minute|minutes|min|m)",
    )
)

_TOP_PATTERN = re.compile(r"(?:top|most)\s+(\d+|\w+)\s+(?:by|per|grouped\s+by)\s+(\w+)", re.IGNORECASE)
_GROUP_BY_PATTERN = re.compile(r"(?:by|per|grouped\s+by)\s+(\w+)", re.IGNORECASE)
_LIMIT_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"(?:limit|top|first)\s+(\d+)",
        r"(\d+)\s+(?:results?|records?|entries?|items?)",
        r"show\s+(?:me\s+)?(\d+)",
    )
)

_SELECT_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"project\s+(.+?)(?:\s+(?:where|when|with|from)|\s*$)",
        r"return\s+(.+?)(?:\s+(?:where|when|with|from)|\s*$)",
        r"show\s+(?:me\s+)?(.+?)(?:\s+(?:where|when|with|from)|\s*$)",
        r"display\s+(.+?)(?:\s+(?:where|when|with|from)|\s*$)",
        r"select\s+(.+?)(?:\s+(?:where|when|with|from)|\s*$)",
    )
)

_SELECT_SPLIT_PATTERN = re.compile(r'[,&\s]+(?:and\s+)?')

_COLUMN_CACHE: Dict[int, Tuple[Tuple[str, ...], Tuple[str, ...]]] = {}

def _quote(val: str) -> str:
    """Safely quote a string value for KQL."""
    if not isinstance(val, str):
        val = str(val)
    return "'" + val.replace("\\", "\\\\").replace("'", "\\'") + "'"

_CONDITION_PATTERNS = (
    # Action types
    (re.compile(r"action\s+(?:type\s+)?(?:is|=|equals?)\s+['\"]?([A-Za-z0-9_]+)['\"]?", re.IGNORECASE),
     lambda m: f"ActionType == {_quote(m.group(1))}"),
    (re.compile(r"action\s+['\"]?([A-Za-z0-9_]+)['\"]?", re.IGNORECASE),
     lambda m: f"ActionType == {_quote(m.group(1))}"),

    # Process/File names (FileName is used for process executables in DeviceProcessEvents)
    (re.compile(r"process\s+(?:name\s+)?(?:is|=|equals?|contains|like)\s+['\"]?([A-Za-z0-9._\\-]+)['\"]?", re.IGNORECASE),
     lambda m: f"FileName =~ {_quote(m.group(1))}"),
    (re.compile(r"(?:running|executing)\s+['\"]?([A-Za-z0-9._\\-]+)['\"]?", re.IGNORECASE),
     lambda m: f"FileName =~ {_quote(m.group(1))}"),
    (re.compile(r"['\"]?([A-Za-z0-9._\\-]+\.exe)['\"]?\s+process(?:es)?", re.IGNORECASE),
     lambda m: f"FileName =~ {_quote(m.group(1))}"),
    (re.compile(r"file\s+(?:name\s+)?(?:is|=|equals?|contains|like)\s+['\"]?([A-Za-z0-9._\\-]+)['\"]?", re.IGNORECASE),
     lambda m: f"FileName =~ {_quote(m.group(1))}"),
    (re.compile(r"(?:accessing|opening|creating|deleting)\s+(?:file\s+)?['\"]?([A-Za-z0-9._\\-]+)['\"]?", re.IGNORECASE),
     lambda m: f"FileName =~ {_quote(m.group(1))}"),

    # Initiating process names
    (re.compile(r"initiating\s+process\s+(?:is|=|equals?|contains|like)\s+['\"]?([A-Za-z0-9._\\-]+)['\"]?", re.IGNORECASE),
     lambda m: f"InitiatingProcessFileName =~ {_quote(m.group(1))}"),

    # Device names
    (re.compile(r"device\s+(?:name\s+)?(?:is|=|equals?|on)\s+['\"]?([A-Za-z0-9._\\-]+)['\"]?", re.IGNORECASE),
     lambda m: f"DeviceName =~ {_quote(m.group(1))}"),
    (re.compile(r"(?:on|from)\s+(?:device|machine|computer)\s+['\"]?([A-Za-z0-9._\\-]+)['\"]?", re.IGNORECASE),
     lambda m: f"DeviceName =~ {_quote(m.group(1))}"),

    # IP addresses
    (re.compile(r"remote\s+ip\s+(?:is|=|equals?)\s+['\"]?([0-9a-fA-F\.:]+)['\"]?", re.IGNORECASE),
     lambda m: f"RemoteIP == {_quote(m.group(1))}"),
    (re.compile(r"(?:sender|source)\s+ip\s+(?:is|=|equals?)\s+['\"]?([0-9a-fA-F\.:]+)['\"]?", re.IGNORECASE),
     lambda m: f"SenderIPv4 == {_quote(m.group(1))} or SenderIPv6 == {_quote(m.group(1))}"),
    (re.compile(r"local\s+ip\s+(?:is|=|equals?)\s+['\"]?([0-9a-fA-F\.:]+)['\"]?", re.IGNORECASE),
     lambda m: f"LocalIP == {_quote(m.group(1))}"),
    (re.compile(r"ip\s+(?:address\s+)?(?:is|=|equals?)\s+['\"]?([0-9a-fA-F\.:]+)['\"]?", re.IGNORECASE),
     lambda m: f"RemoteIP == {_quote(m.group(1))}"),
    (re.compile(r"(?:connecting\s+to|from\s+ip)\s+['\"]?([0-9a-fA-F\.:]+)['\"]?", re.IGNORECASE),
     lambda m: f"RemoteIP == {_quote(m.group(1))}"),

    # User accounts
    (re.compile(r"(?:user|account)\s+(?:name\s+)?(?:is|=|equals?|by)\s+['\"]?([A-Za-z0-9._\\@-]+)['\"]?", re.IGNORECASE),
     lambda m: f"AccountName =~ {_quote(m.group(1))}"),
    (re.compile(r"(?:logged\s+in\s+as|running\s+as)\s+['\"]?([A-Za-z0-9._\\@-]+)['\"]?", re.IGNORECASE),
     lambda m: f"AccountName =~ {_quote(m.group(1))} or InitiatingProcessAccountName =~ {_quote(m.group(1))}"),

    # Email sender patterns
    (re.compile(r"(?:from|sender)\s+(?:is|=|equals?|address)\s+['\"]?([A-Za-z0-9@._+-]+)['\"]?", re.IGNORECASE),
     lambda m: f"SenderFromAddress =~ {_quote(m.group(1))}"),
    (re.compile(r"sender\s+domain\s+(?:is|=|equals?|contains)\s+['\"]?([A-Za-z0-9._-]+)['\"]?", re.IGNORECASE),
     lambda m: f"SenderFromDomain =~ {_quote(m.group(1))}"),

    # Email recipient patterns
    (re.compile(r"(?:recipient|to)\s+(?:is|=|equals?|address)\s+['\"]?([A-Za-z0-9@._+-]+)['\"]?", re.IGNORECASE),
     lambda m: f"RecipientEmailAddress =~ {_quote(m.group(1))}"),

    # Email subject patterns
    (re.compile(r"subject\s+(?:is|=|equals?)\s+['\"](.+?)['\"]", re.IGNORECASE),
     lambda m: f"Subject == {_quote(m.group(1))}"),
    (re.compile(r"subject\s+contains\s+['\"]?(.+?)['\"]?(?:\s+(?:where|when|with|from|and|or)|\s*$)", re.IGNORECASE),
     lambda m: f"Subject contains {_quote(m.group(1).strip())}"),

    # Domains/URLs
    (re.compile(r"domain\s+(?:is|=|equals?|contains)\s+['\"]?([A-Za-z0-9._-]+)['\"]?", re.IGNORECASE),
     lambda m: f"RemoteUrl endswith {_quote(m.group(1))} or RemoteUrl contains {_quote(m.group(1))}"),
    (re.compile(r"(?:visiting|accessing)\s+(?:url\s+)?['\"]?([A-Za-z0-9._-]+)['\"]?", re.IGNORECASE),
     lambda m: f"RemoteUrl contains {_quote(m.group(1))}"),
    (re.compile(r"(?:connections?|traffic|requests?)\s+(?:to|from)\s+['\"]?([A-Za-z0-9._-]+)['\"]?", re.IGNORECASE),
     lambda m: f"RemoteUrl contains {_quote(m.group(1))}"),
)

def _validate_table_name(table: str, schema: Dict[str, Any]) -> str:
    """Validate and normalize table name."""
    if not table or not isinstance(table, str):
        raise ValueError("Table name must be a non-empty string")

    table = table.strip()
    if not table:
        raise ValueError("Table name cannot be empty or whitespace")

    # Check for potentially dangerous characters
    if any(char in table for char in [';', '|', '\n', '\r', '\t']):
        raise ValueError("Table name contains invalid characters")

    return table


def _get_cached_columns(schema: Dict[str, Any], table: str) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    """Return canonical and lowercased column names for a table using an LRU-like cache."""
    table_info = schema.get(table)
    if not isinstance(table_info, dict):
        return tuple(), tuple()

    columns_data = table_info.get("columns", [])
    if not isinstance(columns_data, list):
        return tuple(), tuple()

    cache_key = id(columns_data)
    cached = _COLUMN_CACHE.get(cache_key)
    if cached is not None:
        return cached

    names: List[str] = []
    for column in columns_data:
        if isinstance(column, dict):
            name = column.get("name")
            if isinstance(name, str):
                stripped = name.strip()
                if stripped:
                    names.append(stripped)

    canonical = tuple(names)
    lowered = tuple(name.lower() for name in canonical)
    _COLUMN_CACHE[cache_key] = (canonical, lowered)
    return _COLUMN_CACHE[cache_key]

def _validate_column_names(columns: List[str], schema: Dict[str, Any], table: str) -> List[str]:
    """Validate column names against schema."""
    if not columns:
        return columns

    if not isinstance(columns, list):
        raise ValueError("Columns must be a list")

    column_names, _ = _get_cached_columns(schema, table)
    available_columns = set(column_names)

    validated_columns = []
    for col in columns:
        if not isinstance(col, str):
            raise ValueError(f"Column name must be a string, got {type(col)}")

        col = col.strip()
        if not col:
            continue

        # Check for dangerous characters
        if any(char in col for char in [';', '|', '\n', '\r', '\t', "'", '"']):
            raise ValueError(f"Column name '{col}' contains invalid characters")

        # Check if column exists in schema (warning only, don't fail)
        if available_columns and col not in available_columns:
            logger.warning(f"Column '{col}' not found in schema for table '{table}'")

        validated_columns.append(col)

    return validated_columns

def _validate_where_conditions(conditions: List[str]) -> List[str]:
    """Validate WHERE conditions for safety with allowlist for legitimate command-line patterns."""
    if not conditions:
        return conditions

    if not isinstance(conditions, list):
        raise ValueError("WHERE conditions must be a list")

    validated_conditions = []
    for condition in conditions:
        if not isinstance(condition, str):
            raise ValueError(f"WHERE condition must be a string, got {type(condition)}")

        condition = condition.strip()
        if not condition:
            continue

        # Check dangerous patterns, but skip validation if allowlisted patterns are present
        for pattern in _WHERE_DANGEROUS_PATTERNS:
            if pattern.search(condition):
                # Before failing, check if this is actually an allowlisted pattern
                is_safe = any(allow_pattern.search(condition) for allow_pattern in _ALLOWED_COMMAND_PATTERNS)
                if not is_safe:
                    raise ValueError(f"WHERE condition contains potentially dangerous pattern: {condition}")
                # Pattern matched but it's allowlisted, so continue validation
                break

        # Check for balanced quotes
        single_quotes = condition.count("'")
        if single_quotes % 2 != 0:
            raise ValueError(f"Unbalanced quotes in WHERE condition: {condition}")

        validated_conditions.append(condition)

    return validated_conditions

def _validate_time_window(time_window: str) -> str:
    """Validate time window format."""
    if not time_window or not isinstance(time_window, str):
        return DEFAULT_TIME_WINDOW

    time_window = time_window.strip()
    if not time_window:
        return DEFAULT_TIME_WINDOW

    # Check format: number followed by d/h/m
    if not _TIME_WINDOW_VALID_PATTERN.fullmatch(time_window):
        logger.warning(f"Invalid time window format '{time_window}', using default")
        return DEFAULT_TIME_WINDOW

    # Reasonable bounds check
    match = _TIME_WINDOW_UNIT_PATTERN.match(time_window)
    if match:
        num = int(match.group(1))
        unit = match.group(2)

        max_values = {'d': 365, 'h': 8760, 'm': 525600}  # 1 year in each unit
        if num > max_values.get(unit, 365):
            logger.warning(f"Time window '{time_window}' is very large, consider using a smaller window")
        elif num < 1:
            logger.warning(f"Time window '{time_window}' is invalid, using default")
            return DEFAULT_TIME_WINDOW

    return time_window

def _validate_limit(limit: Optional[int]) -> int:
    """Validate and normalize limit value."""
    if limit is None:
        # No limit was specified; use the safe default.
        return 100

    if not isinstance(limit, int):
        try:
            limit = int(limit)
        except (ValueError, TypeError):
            raise ValueError("limit must be an integer value") from None

    if limit < 1:
        raise ValueError("limit must be a positive integer")

    if limit > 10000:
        logger.warning(f"Limit is very large ({limit}), consider using a smaller value")
        return min(limit, 50000)  # Allow up to 50k but warn

    return limit

def _validate_summarize_expression(summarize: Optional[str]) -> Optional[str]:
    """Validate summarize expression for safety."""
    if not summarize or not isinstance(summarize, str):
        return summarize

    summarize = summarize.strip()
    if not summarize:
        return None

    # Basic safety checks
    for pattern in _WHERE_DANGEROUS_PATTERNS:
        if pattern.search(summarize):
            raise ValueError(f"Summarize expression contains potentially dangerous pattern: {summarize}")

    return summarize

def _validate_order_by_expression(order_by: Optional[str]) -> Optional[str]:
    """Validate order by expression for safety."""
    if not order_by or not isinstance(order_by, str):
        return order_by

    order_by = order_by.strip()
    if not order_by:
        return None

    # Check for valid order by patterns
    if not _ORDER_BY_PATTERN.match(order_by):
        logger.warning(f"Order by expression may be invalid: {order_by}")

    return order_by

def _parse_time_window(s: Optional[str]) -> str:
    """Parse and validate time window string."""
    if not s:
        return DEFAULT_TIME_WINDOW

    s = s.strip()
    if not s:
        return DEFAULT_TIME_WINDOW

    # Check format: number followed by d/h/m
    if not _TIME_WINDOW_VALID_PATTERN.fullmatch(s):
        logger.warning(f"Invalid time window format '{s}', using default")
        return DEFAULT_TIME_WINDOW

    return s

def list_columns(schema: Dict[str, Any], table: str) -> List[str]:
    """List all columns for a given table with input validation."""
    if not isinstance(schema, dict):
        logger.error("Schema must be a dictionary")
        return []

    if not isinstance(table, str) or not table.strip():
        logger.error("Table name must be a non-empty string")
        return []

    table = table.strip()
    if table not in schema:
        logger.warning(f"Table '{table}' not found in schema")
        return []

    try:
        column_names, _ = _get_cached_columns(schema, table)
        return list(column_names)
    except (KeyError, TypeError) as e:
        logger.error(f"Error accessing columns for table '{table}': {e}")
        return []

def suggest_columns(schema: Dict[str, Any], table: str, keyword: Optional[str]=None) -> List[str]:
    """Suggest columns for a table, optionally filtered by keyword, with input validation."""
    if not isinstance(schema, dict):
        logger.error("Schema must be a dictionary")
        return []

    if not isinstance(table, str) or not table.strip():
        logger.error("Table name must be a non-empty string")
        return []

    if keyword is not None and not isinstance(keyword, str):
        logger.error("Keyword must be a string or None")
        return []

    cols, lower_cols = _get_cached_columns(schema, table)
    if not cols:
        return []

    if not keyword or not keyword.strip():
        return list(cols[:50])

    kw = keyword.lower().strip()
    if not kw:
        return list(cols[:50])

    try:
        filtered_cols = [name for name, lowered in zip(cols, lower_cols) if kw in lowered]
        return filtered_cols[:50]
    except Exception as e:
        logger.error(f"Error filtering columns with keyword '{keyword}': {e}")
        return list(cols[:50])

def _best_table(schema: Dict[str, Any], name: str) -> str:
    """Find the best matching table name with improved error handling."""
    if not isinstance(schema, dict):
        logger.error("Schema must be a dictionary")
        return name

    if not isinstance(name, str) or not name.strip():
        logger.error("Table name must be a non-empty string")
        return name

    name = name.strip()
    if name in schema:
        return name

    try:
        from rapidfuzz import process
        if not schema:
            logger.warning("Schema is empty, cannot find best match")
            return name

        choice, score, _ = process.extractOne(name, list(schema.keys()))
        if score >= 80:  # Only use fuzzy match if confidence is high
            logger.info(f"Using fuzzy match for table '{name}' -> '{choice}' (score: {score})")
            return choice
        else:
            logger.warning(f"No good fuzzy match found for table '{name}' (best score: {score})")
            return name
    except ImportError:
        logger.error("rapidfuzz not available for fuzzy matching")
        return name
    except Exception as e:
        logger.error(f"Error in fuzzy table matching for '{name}': {e}")
        return name

def _nl_to_structured(schema: Dict[str, Any], intent: str) -> Dict[str, Any]:
    """
    Enhanced natural language to structured query parsing with better pattern matching.

    Security: Validates input length to prevent ReDoS and resource exhaustion attacks.
    """
    if not intent or not intent.strip():
        logger.warning("Empty or None natural language intent provided")
        return _get_default_query_params()

    # Security: Validate input length to prevent ReDoS attacks
    if len(intent) > MAX_INTENT_LENGTH:
        logger.error(
            "Natural language intent exceeds maximum length (%d > %d chars). "
            "Refusing to process potentially malicious input.",
            len(intent),
            MAX_INTENT_LENGTH
        )
        raise ValueError(f"Intent exceeds maximum length of {MAX_INTENT_LENGTH} characters")

    stripped_intent = intent.strip()
    logger.info("Parsing natural language intent: %s", stripped_intent[:100] + ("..." if len(stripped_intent) > 100 else ""))

    lowered = stripped_intent.lower()

    # Initialize query parameters
    params = _get_default_query_params()

    # Determine table from keywords
    params["table"] = _infer_table_from_text(lowered, schema)

    # Parse time window
    params["time_window"] = _parse_time_window_from_text(stripped_intent)

    # Parse conditions and filters
    params["where"] = _parse_conditions_from_text(stripped_intent)

    # Parse aggregation and ordering
    agg_result = _parse_aggregation_from_text(stripped_intent)
    params.update(agg_result)

    # Parse limit
    params["limit"] = _parse_limit_from_text(stripped_intent)

    # Parse select columns if specified
    params["select"] = _parse_select_from_text(stripped_intent)

    logger.info("Parsed query parameters: %s", params)
    return params

def _get_default_query_params() -> Dict[str, Any]:
    """Get default query parameters."""
    return {
        "table": None,
        "select": None,
        "where": None,
        "time_window": DEFAULT_TIME_WINDOW,
        "summarize": None,
        "order_by": None,
        "limit": None
    }

def _infer_table_from_text(text: str, schema: Dict[str, Any]) -> Optional[str]:
    """Infer table from text using comprehensive keyword mapping."""
    # Expanded table hints with more keywords
    table_hints = {
        "DeviceProcessEvents": [
            "process", "processes", "exe", "executable", "cmd", "command", "powershell",
            "script", "batch", "ps1", "vbs", "wscript", "cscript", "rundll32", "regsvr32"
        ],
        "DeviceNetworkEvents": [
            "network", "net", "connection", "connect", "dns", "domain", "url", "http",
            "https", "tcp", "udp", "port", "firewall", "traffic", "web", "browser"
        ],
        "DeviceFileEvents": [
            "file", "files", "document", "doc", "pdf", "txt", "log", "config", "ini",
            "registry", "reg", "disk", "drive", "folder", "directory"
        ],
        "EmailEvents": [
            "email", "mail", "smtp", "outlook", "exchange", "message", "attachment",
            "sender", "recipient", "subject", "phishing", "spam"
        ],
        "AlertInfo": [
            "alert", "alerts", "threat", "security", "incident", "detection", "malware",
            "attack", "breach", "compromise", "suspicious"
        ],
        "IdentityLogonEvents": [
            "logon", "login", "sign-in", "authentication", "auth", "user", "account",
            "credential", "password", "session", "interactive"
        ],
        "DeviceInfo": [
            "device", "machine", "computer", "host", "endpoint", "system", "os",
            "windows", "linux", "mac", "version", "build"
        ]
    }

    # Check for explicit table mentions first
    for table_name in schema.keys():
        if table_name.lower() in text:
            return table_name

    # Check keyword hints
    for table_name, keywords in table_hints.items():
        if table_name in schema and any(kw in text for kw in keywords):
            return table_name

    return None

def _parse_time_window_from_text(text: str) -> str:
    """Parse time window from natural language text with safe regex operations."""
    if not isinstance(text, str):
        logger.error("Text must be a string for time window parsing")
        return DEFAULT_TIME_WINDOW

    # Multiple time pattern formats
    for pattern in _NL_TIME_WINDOW_PATTERNS:
        try:
            match = pattern.search(text)
            if match and len(match.groups()) >= 2:
                n = match.group(1)
                unit = match.group(2)

                if n and unit:
                    unit = unit.lower()

                    # Normalize unit
                    if unit in ['day', 'days', 'd']:
                        return f"{n}d"
                    elif unit in ['hour', 'hours', 'h']:
                        return f"{n}h"
                    elif unit in ['minute', 'minutes', 'min', 'm']:
                        return f"{n}m"
        except (IndexError, AttributeError) as e:
            logger.warning(f"Error parsing time pattern {pattern}: {e}")
            continue

    return DEFAULT_TIME_WINDOW

def _parse_conditions_from_text(text: str) -> Optional[List[str]]:
    """Parse WHERE conditions from natural language text."""
    conditions = []

    for pattern, condition_func in _CONDITION_PATTERNS:
        for match in pattern.finditer(text):
            try:
                condition = condition_func(match)
                if condition and condition not in conditions:
                    conditions.append(condition)
            except Exception as e:
                logger.warning(f"Failed to parse condition from pattern {pattern}: {e}")

    return conditions if conditions else None

def _parse_aggregation_from_text(text: str) -> Dict[str, Any]:
    """Parse aggregation and ordering from text with safe regex operations."""
    if not isinstance(text, str):
        logger.error("Text must be a string for aggregation parsing")
        return {"summarize": None, "order_by": None}

    result = {"summarize": None, "order_by": None}
    lowered = text.lower()

    # Top/bottom patterns
    try:
        top_match = _TOP_PATTERN.search(text)
        if top_match and len(top_match.groups()) >= 2:
            count = top_match.group(1)
            group_by = top_match.group(2)

            if count and group_by:
                if count.isdigit():
                    result["limit"] = int(count)
                elif count.lower() in ['all', 'every', 'each']:
                    result["limit"] = None

                result["summarize"] = f"count() by {group_by}"
                result["order_by"] = "count_ desc"
    except (IndexError, AttributeError) as e:
        logger.warning(f"Error parsing top/bottom pattern: {e}")

    # Count patterns
    if any(keyword in lowered for keyword in ("count", "number of", "how many")):
        pass

    if any(keyword in lowered for keyword in ("count", "number of", "how many")):
        if "by" in lowered:
            try:
                by_match = _GROUP_BY_PATTERN.search(text)
                if by_match and len(by_match.groups()) >= 1:
                    group_by = by_match.group(1)
                    if group_by:
                        result["summarize"] = f"count() by {group_by}"
                        result["order_by"] = "count_ desc"
            except (IndexError, AttributeError) as e:
                logger.warning(f"Error parsing count pattern: {e}")

    return result

def _parse_limit_from_text(text: str) -> Optional[int]:
    """Parse limit from text."""
    for pattern in _LIMIT_PATTERNS:
        match = pattern.search(text)
        if match:
            try:
                limit = int(match.group(1))
                if 1 <= limit <= 10000:  # Reasonable bounds
                    return limit
            except ValueError:
                continue

    return None

def _parse_select_from_text(text: str) -> Optional[List[str]]:
    """Parse select columns from text."""
    if "show" not in text and "display" not in text and "select" not in text:
        return None

    for pattern in _SELECT_PATTERNS:
        match = pattern.search(text)
        if match:
            columns_text = match.group(1).strip()
            # Split by common separators
            columns = _SELECT_SPLIT_PATTERN.split(columns_text)
            # Clean up column names
            clean_columns = []
            for col in columns:
                col = col.strip()
                if col and not any(word in col.lower() for word in ['where', 'when', 'with', 'from', 'the', 'only']):
                    clean_columns.append(col)

            if clean_columns:
                return clean_columns

    return None

def _deduplicate_where_conditions(conditions: List[str]) -> List[str]:
    """
    Deduplicate WHERE conditions, handling semantically equivalent variations.

    ACCURACY FIX: Prevents duplicate conditions from appearing in final query.
    Handles cases like:
    - Exact duplicates: "DeviceName == 'SERVER'" and "DeviceName == 'SERVER'"
    - Operator variations: "DeviceName == 'SERVER'" and "DeviceName =~ 'SERVER'"
    - Whitespace variations: "FileName=='cmd.exe'" and "FileName == 'cmd.exe'"

    Args:
        conditions: List of WHERE condition strings

    Returns:
        Deduplicated list of conditions, preserving order
    """
    if not conditions:
        return []

    def normalize_condition(cond: str) -> str:
        """Normalize a condition for comparison."""
        # Remove extra whitespace
        normalized = " ".join(cond.split())
        # Make comparison operators consistent for deduplication
        # Note: We keep the original condition, just use this for comparison
        return normalized.lower()

    seen = set()
    deduplicated = []

    for condition in conditions:
        if not condition or not isinstance(condition, str):
            continue

        # Normalize for comparison
        normalized = normalize_condition(condition)

        # Check for exact match (case-insensitive, whitespace-normalized)
        if normalized in seen:
            logger.debug(f"Skipping duplicate condition: {condition}")
            continue

        # Check for semantic equivalence (same field and value, different operators)
        # Extract field name (everything before the operator)
        is_duplicate = False
        for existing_norm in seen:
            # Check if conditions are semantically equivalent
            # e.g., "DeviceName == 'SERVER'" vs "DeviceName =~ 'SERVER'"
            # Extract parts: field, operator, value
            if _conditions_are_equivalent(normalized, existing_norm):
                logger.debug(
                    f"Skipping semantically equivalent condition: {condition} "
                    f"(already have similar condition)"
                )
                is_duplicate = True
                break

        if not is_duplicate:
            seen.add(normalized)
            deduplicated.append(condition)

    return deduplicated


def _conditions_are_equivalent(cond1: str, cond2: str) -> bool:
    """
    Check if two normalized conditions are semantically equivalent.

    Returns True if they operate on the same field with the same value,
    even if using different operators (==, =~, contains, etc.)
    """
    # Simple heuristic: if they share the same field name and value (in quotes)
    # they're likely equivalent
    import re

    # Extract field name (word characters before operator)
    field_pattern = r'^([a-z0-9_]+)\s*(?:==|=~|!=|contains|startswith|endswith)'

    match1 = re.match(field_pattern, cond1, re.IGNORECASE)
    match2 = re.match(field_pattern, cond2, re.IGNORECASE)

    if not match1 or not match2:
        return False

    field1 = match1.group(1)
    field2 = match2.group(1)

    if field1 != field2:
        return False

    # Extract quoted values
    value_pattern = r'["\']([^"\']+)["\']'
    values1 = re.findall(value_pattern, cond1)
    values2 = re.findall(value_pattern, cond2)

    # If same field and same values (in quotes), consider equivalent
    if values1 and values2 and values1 == values2:
        return True

    return False


def build_kql_query(
    schema: Dict[str, Any],
    table: Optional[str] = None,
    select: Optional[List[str]] = None,
    where: Optional[List[str]] = None,
    time_window: Optional[str] = None,
    summarize: Optional[str] = None,
    order_by: Optional[str] = None,
    limit: Optional[int] = None,
    natural_language_intent: Optional[str] = None,
    rag_context: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[str, Dict[str, Any]]:
    """Build a KQL query with comprehensive input validation.
    
    Args:
        schema: KQL schema dictionary
        table: Table name to query
        select: List of columns to select
        where: List of WHERE conditions
        time_window: Time window (e.g., '7d', '24h')
        summarize: Summarization expression
        order_by: ORDER BY expression
        limit: Maximum number of results
        natural_language_intent: Natural language description
        rag_context: Optional RAG-retrieved documents for query enhancement
        
    Returns:
        Tuple of (query_string, metadata_dict)
    """
    try:
        if not isinstance(schema, dict):
            raise TypeError("schema must be a dictionary of table metadata")

        logger.info("Building KQL query with parameters: table=%s, select=%s, where=%s, time_window=%s, summarize=%s, order_by=%s, limit=%s, natural_language_intent=%s",
                   table, select, where, time_window, summarize, order_by, limit, bool(natural_language_intent))

        cleaned_intent: Optional[str] = None
        if natural_language_intent is not None:
            if not isinstance(natural_language_intent, str):
                raise TypeError("natural_language_intent must be a string if provided")
            cleaned_intent = natural_language_intent.strip()
            if not cleaned_intent:
                raise ValueError("natural_language_intent must not be empty")

        # Security Concept Expansion: Detect and expand security concepts
        concept_enhanced_conditions: List[str] = []
        if cleaned_intent:
            try:
                from queryforge.shared.security_concepts import detect_security_concepts, generate_concept_hints, get_concept_description

                detected_concepts = detect_security_concepts(cleaned_intent)
                if detected_concepts:
                    concept_hints = generate_concept_hints(detected_concepts, "kql")

                    # Build KQL WHERE conditions from concept hints
                    for keyword_category, keywords in concept_hints.items():
                        # Map hint category to KQL field names
                        field_mapping = {
                            "process_keywords": "FileName",
                            "cmdline_keywords": "ProcessCommandLine",
                            "port_keywords": ["LocalPort", "RemotePort"],
                            "domain_keywords": "RemoteUrl",
                            "registry_keywords": "RegistryKey",
                        }

                        field_candidates = field_mapping.get(keyword_category, [])
                        if not isinstance(field_candidates, list):
                            field_candidates = [field_candidates]

                        for field in field_candidates:
                            if keyword_category == "port_keywords":
                                # Numeric fields use 'in' operator
                                if keywords:
                                    port_values = [p for p in keywords if p.isdigit()]
                                    if port_values:
                                        ports_str = ", ".join(port_values)
                                        condition = f"{field} in ({ports_str})"
                                        concept_enhanced_conditions.append(condition)
                                        logger.info(f"Added concept-based KQL condition: {condition}")
                            else:
                                # String fields use 'in~' operator for case-insensitive multi-value match
                                if keywords:
                                    quoted_keywords = [_quote(k) for k in keywords]
                                    keywords_str = ", ".join(quoted_keywords)
                                    condition = f"{field} in~ ({keywords_str})"
                                    concept_enhanced_conditions.append(condition)
                                    logger.info(f"Added concept-based KQL condition: {condition}")

                    concept_descriptions = [get_concept_description(c) for c in detected_concepts]
                    logger.info(f"Detected security concepts: {', '.join(detected_concepts)}")
                    logger.info(f"Added {len(concept_enhanced_conditions)} concept-based KQL conditions")

            except Exception as e:
                # Concept expansion is optional - don't fail the query if it errors
                logger.warning(f"Security concept expansion failed for KQL, continuing without it: {e}")

        # RAG-Enhanced Query Building: Extract additional WHERE conditions from RAG context
        rag_enhanced_conditions: List[str] = []
        if rag_context and cleaned_intent:
            try:
                from queryforge.shared.rag_context_parser import create_rag_context_parser
                
                parser = create_rag_context_parser("kql")
                parsed_context = parser.parse_context(
                    rag_context,
                    cleaned_intent,
                    table
                )
                
                logger.info(f"RAG parsed context for KQL: fields={parsed_context['fields']}, "
                           f"values={parsed_context['values']}, "
                           f"confidence={parsed_context['confidence']}")
                
                # Use RAG enhancements with low confidence threshold (RAG-first approach)
                # Goal: Comprehensive one-shot queries that cover multiple indicators
                if parsed_context["confidence"] >= 0.1:
                    # Extract column:value pairs from RAG context
                    for field in parsed_context["fields"][:10]:  # Top 10 fields for comprehensive coverage
                        values = parsed_context["values"].get(field, [])
                        for value in values[:7]:  # Top 7 values per field for comprehensive coverage
                            # Format the KQL condition (Column == 'value' or Column contains 'value')
                            # Use contains for string fields, == for exact matches
                            if any(keyword in value.lower() for keyword in ['.exe', '.dll', 'http', 'www', 'domain']):
                                # Likely a filename, URL, or domain - use case-insensitive contains
                                condition = f"{field} contains {_quote(value)}"
                            else:
                                # Use case-insensitive equality
                                condition = f"{field} =~ {_quote(value)}"
                            
                            rag_enhanced_conditions.append(condition)
                            logger.info(f"Added RAG enhanced KQL condition: {condition}")
                    
                    if rag_enhanced_conditions:
                        logger.info(f"Added {len(rag_enhanced_conditions)} RAG enhanced conditions to KQL query")
                else:
                    logger.info(f"RAG confidence too low for KQL: {parsed_context['confidence']}")
                    
            except Exception as e:
                # RAG enhancement is optional - don't fail the query if it errors
                logger.warning(f"RAG enhancement failed for KQL, continuing without it: {e}")
        
        # Parse natural language intent if provided
        if cleaned_intent:
            derived = _nl_to_structured(schema, cleaned_intent)
            table = table or derived["table"]
            select = select or derived["select"]

            # ACCURACY FIX: Merge where conditions with deduplication
            # Combine explicit where conditions with derived conditions from natural language, concepts, and RAG
            explicit_where = where or []
            derived_where = derived["where"] or []
            all_where = explicit_where + derived_where + concept_enhanced_conditions + rag_enhanced_conditions
            where = _deduplicate_where_conditions(all_where)

            time_window = time_window or derived["time_window"]
            summarize = summarize or derived["summarize"]
            order_by = order_by or derived["order_by"]
            if limit is None:
                limit = derived["limit"]

        # Validate table
        if not table:
            raise ValueError("Table is required (pass 'table' or provide 'natural_language_intent' that implies a table).")
        table = _validate_table_name(table, schema)
        table = _best_table(schema, table)

        # Validate and get available columns
        cols = [c["name"] for c in schema.get(table, {}).get("columns", [])]

        # Validate inputs
        if select:
            select = _validate_column_names(select, schema, table)
        if where:
            where = _validate_where_conditions(where)
        time_window = _validate_time_window(time_window)
        limit = _validate_limit(limit)
        if summarize:
            summarize = _validate_summarize_expression(summarize)
        if order_by:
            order_by = _validate_order_by_expression(order_by)

        # Build query
        q = [table]

        # Add time window filter if Timestamp column exists
        if "Timestamp" in cols:
            tw = _parse_time_window(time_window)
            q.append(f"| where Timestamp > ago({tw})")

        # Add WHERE conditions
        if where:
            for cond in where:
                q.append(f"| where {cond}")

        # Add SELECT projection
        if select:
            q.append("| project " + ", ".join(select))

        # Add summarization
        if summarize:
            q.append("| summarize " + summarize)

        # Add ordering
        if order_by:
            q.append("| order by " + order_by)

        # Add limit
        if limit:
            q.append("| limit " + str(limit))

        kql_query = "\n".join(q)
        logger.info("Successfully built KQL query for table '%s'", table)

        return kql_query, {
            "table": table,
            "time_window": time_window,
            "has_timestamp": "Timestamp" in cols,
            "column_count": len(cols),
            "conditions_count": len(where) if where else 0,
            "selected_columns": len(select) if select else None
        }

    except Exception as e:
        logger.error("Failed to build KQL query: %s", str(e))
        raise

def _load_example_queries_from_directory() -> Dict[str, List[str]]:
    """Load example queries from the kql_example_queries directory."""
    queries_dir = Path(__file__).parent / "kql_example_queries"
    if not queries_dir.exists():
        logger.warning(f"Example queries directory not found: {queries_dir}")
        return {}

    table_queries = {}

    # Walk through all .md files in the directory
    for md_file in queries_dir.rglob("*.md"):
        try:
            content = md_file.read_text(encoding='utf-8')
            queries = _parse_kql_from_markdown(content, str(md_file))
            for table_name, query_list in queries.items():
                if table_name not in table_queries:
                    table_queries[table_name] = []
                table_queries[table_name].extend(query_list)
        except Exception as e:
            logger.warning(f"Failed to parse example file {md_file}: {e}")

    logger.info(f"Loaded {sum(len(queries) for queries in table_queries.values())} example queries for {len(table_queries)} tables")
    return table_queries

def _parse_kql_from_markdown(content: str, filename: str) -> Dict[str, List[str]]:
    """Parse KQL queries from markdown content, focusing on Defender XDR sections."""
    table_queries = {}

    # Split by sections (## headers)
    sections = re.split(r'\n##\s+', content)

    for section in sections:
        section = section.strip()
        if not section:
            continue

        # Look for Defender XDR code blocks
        defender_pattern = r'## Defender XDR\s*```KQL\s*(.+?)\s*```'
        matches = re.findall(defender_pattern, section, re.DOTALL)

        for match in matches:
            query = match.strip()
            if not query:
                continue

            # Extract table name from first line
            lines = query.split('\n')
            first_line = lines[0].strip() if lines else ""

            # Skip if first line is empty or doesn't look like a table name
            if not first_line or '|' in first_line or first_line.startswith('//'):
                continue

            table_name = first_line

            # Clean up the query
            clean_query = '\n'.join(lines[1:]).strip()
            if clean_query:
                full_query = f"{table_name}\n{clean_query}"
                if table_name not in table_queries:
                    table_queries[table_name] = []
                table_queries[table_name].append(full_query)

    return table_queries

def example_queries_for_table(schema: Dict[str, Any], table: str) -> List[str]:
    """Return example KQL queries for a given table, loaded from the example queries directory."""
    t = _best_table(schema, table)

    # Try to load from the example queries directory first
    try:
        all_queries = _load_example_queries_from_directory()
        if t in all_queries:
            return all_queries[t][:5]  # Return up to 5 examples
    except Exception as e:
        logger.warning(f"Failed to load example queries from directory: {e}")

    # Fallback to hardcoded examples if directory loading fails
    cols = [c["name"] for c in schema.get(t, {}).get("columns", [])]
    ex = []

    if t == "DeviceProcessEvents":
        ex.append(
            "DeviceProcessEvents\n"
            "| where Timestamp > ago(7d)\n"
            "| where ActionType == 'ProcessCreated'\n"
            "| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName\n"
            "| limit 200"
        )
    elif t == "DeviceNetworkEvents":
        ex.append(
            "DeviceNetworkEvents\n"
            "| where Timestamp > ago(24h)\n"
            "| where RemoteUrl contains 'example.com' or RemoteIP == '1.2.3.4'\n"
            "| summarize count() by DeviceName, RemoteUrl\n"
            "| order by count_ desc\n"
            "| limit 100"
        )
    else:
        ex.append(
            f"{t}\n"
            "| where Timestamp > ago(7d)\n"
            "| limit 100"
        )

    return ex
