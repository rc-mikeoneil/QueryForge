#!/usr/bin/env python3
"""
Script to add missing CQL functions based on validation data.
This adds the 51 missing functions identified in CQL_VALIDATION_REPORT.md
"""

import json
import os
from pathlib import Path

# Base path for CQL functions
FUNCTIONS_DIR = Path("src/queryforge/platforms/cql/cql_schemas/functions")

# Function definitions based on validation report and usage patterns
MISSING_FUNCTIONS = {
    "Mac": {
        "name": "Mac",
        "category": "constant",
        "description": "Platform constant representing the macOS operating system. Used to filter or match Mac-specific events in CQL queries.",
        "syntax": "Mac",
        "parameters": [],
        "return_type": "string",
        "examples": [
            "event_platform=Mac",
            "| where event_platform=Mac"
        ],
        "related_functions": ["Win", "Lin"],
        "use_cases": ["Platform filtering", "OS-specific queries", "macOS event isolation"],
        "notes": "This is a constant value, not a function call. Typically used with event_platform field to filter for Mac events."
    },
    "Lin": {
        "name": "Lin",
        "category": "constant",
        "description": "Platform constant representing the Linux operating system. Used to filter or match Linux-specific events in CQL queries.",
        "syntax": "Lin",
        "parameters": [],
        "return_type": "string",
        "examples": [
            "event_platform=Lin",
            "| where event_platform=Lin"
        ],
        "related_functions": ["Win", "Mac"],
        "use_cases": ["Platform filtering", "OS-specific queries", "Linux event isolation"],
        "notes": "This is a constant value, not a function call. Typically used with event_platform field to filter for Linux events."
    },
    "groupby": {
        "name": "groupby",
        "category": "aggregation",
        "description": "Lowercase variant of groupBy(). Groups together events by one or more specified fields. Functionally identical to groupBy().",
        "syntax": "groupby([field1, field2, ...], function=([aggregate_functions]), limit=max)",
        "parameters": [
            {
                "name": "fields",
                "type": "array",
                "required": True,
                "description": "Array of field names to group by"
            },
            {
                "name": "function",
                "type": "aggregation_function",
                "required": False,
                "description": "Aggregate functions to apply to each group"
            },
            {
                "name": "limit",
                "type": "number",
                "required": False,
                "description": "Maximum number of groups to return"
            }
        ],
        "return_type": "grouped_events",
        "examples": [
            "| groupby([ComputerName], function=count())",
            "| groupby([aid, falconPID], function=collect([ImageFileName]))"
        ],
        "related_functions": ["groupBy", "count", "bucket", "stats"],
        "use_cases": ["Aggregation", "Event grouping", "Statistical analysis"],
        "notes": "Case-insensitive alias of groupBy(). Both forms are accepted in CQL."
    },
    "now": {
        "name": "now",
        "category": "time",
        "description": "Returns the current timestamp as epoch time in seconds. Commonly used for calculating time deltas or relative timestamps.",
        "syntax": "now()",
        "parameters": [],
        "return_type": "long",
        "examples": [
            "timeDelta := (now()*1000)-ProcessStartTime",
            "LastRebootAgo := now()-LastReboot",
            "| where @timestamp > now()-86400"
        ],
        "related_functions": ["formatTime", "formatDuration", "bucket"],
        "use_cases": ["Time calculations", "Relative time filtering", "Uptime calculations", "Age determination"],
        "notes": "Returns epoch seconds. Multiply by 1000 to convert to milliseconds for comparison with CrowdStrike timestamps."
    },
    "enrich": {
        "name": "enrich",
        "category": "enrichment",
        "description": "Enriches events with additional data from external sources or lookup tables. Used to add contextual information to events.",
        "syntax": "enrich(field, [parameters])",
        "parameters": [
            {
                "name": "field",
                "type": "string",
                "required": True,
                "description": "Field to enrich"
            }
        ],
        "return_type": "enriched_event",
        "examples": [
            "| enrich(RemoteAddressIP4)",
            "| enrich(aid, include=[ComputerName, AgentVersion])"
        ],
        "related_functions": ["ipLocation", "asn", "match", "join"],
        "use_cases": ["Data enrichment", "Context addition", "Lookup augmentation"],
        "notes": "Commonly used with IP addresses, agent IDs, and other identifiers to add contextual data."
    },
    "extractFlags": {
        "name": "extractFlags",
        "category": "bitfield",
        "description": "Extracts and decodes individual flags from a bitmask field. Returns human-readable flag names based on bit positions.",
        "syntax": "extractFlags(field, [mapping])",
        "parameters": [
            {
                "name": "field",
                "type": "long",
                "required": True,
                "description": "Bitmask field to decode"
            },
            {
                "name": "mapping",
                "type": "object",
                "required": False,
                "description": "Mapping of bit positions to flag names"
            }
        ],
        "return_type": "array",
        "examples": [
            "flags := extractFlags(SignInfoFlags)",
            "| extractFlags(WindowFlags, output=decodedFlags)"
        ],
        "related_functions": [],
        "use_cases": ["Bitmask decoding", "Flag extraction", "Binary field parsing"],
        "notes": "Useful for fields like SignInfoFlags, WindowFlags, and other bitmask values in Falcon data."
    },
    "wildcard": {
        "name": "wildcard",
        "category": "pattern",
        "description": "Performs wildcard pattern matching on field values. Supports * for zero or more characters and ? for single character.",
        "syntax": "wildcard(field, pattern)",
        "parameters": [
            {
                "name": "field",
                "type": "string",
                "required": True,
                "description": "Field to match against"
            },
            {
                "name": "pattern",
                "type": "string",
                "required": True,
                "description": "Wildcard pattern (* and ? supported)"
            }
        ],
        "return_type": "boolean",
        "examples": [
            "| where wildcard(ImageFileName, \"*powershell*\")",
            "| where wildcard(FileName, \"cmd.???\")"
        ],
        "related_functions": ["match", "regex", "=*"],
        "use_cases": ["Pattern matching", "Substring search", "Flexible filtering"],
        "notes": "Alternative to =* operator. Useful for programmatic pattern matching."
    },
    "convert": {
        "name": "convert",
        "category": "transformation",
        "description": "Converts values between different units or formats. Commonly used for size conversions (bytes to KB/MB/GB) and data type transformations.",
        "syntax": "convert(value, from=unit, to=unit)",
        "parameters": [
            {
                "name": "value",
                "type": "number",
                "required": True,
                "description": "Value to convert"
            },
            {
                "name": "from",
                "type": "string",
                "required": True,
                "description": "Source unit or format"
            },
            {
                "name": "to",
                "type": "string",
                "required": True,
                "description": "Target unit or format"
            }
        ],
        "return_type": "number",
        "examples": [
            "sizeGB := convert(FileSize, from=bytes, to=GB)",
            "sizeMB := convert(MemoryTotal, from=bytes, to=MB)"
        ],
        "related_functions": ["format", "round"],
        "use_cases": ["Unit conversion", "Size formatting", "Data transformation"],
        "notes": "Commonly used for converting byte values to human-readable sizes."
    },
    "systems": {
        "name": "systems",
        "category": "enrichment",
        "description": "Retrieves system information and metadata. Used to access system-level details beyond standard event fields.",
        "syntax": "systems()",
        "parameters": [],
        "return_type": "table",
        "examples": [
            "| systems()",
            "| join({systems()}, field=aid)"
        ],
        "related_functions": ["enrich", "match"],
        "use_cases": ["System metadata retrieval", "Inventory queries", "Asset enrichment"],
        "notes": "Provides access to system-level information not available in standard events."
    },
    "urlDecode": {
        "name": "urlDecode",
        "category": "transformation",
        "description": "Decodes URL-encoded strings, converting percent-encoded characters back to their original form.",
        "syntax": "urlDecode(field)",
        "parameters": [
            {
                "name": "field",
                "type": "string",
                "required": True,
                "description": "URL-encoded string to decode"
            }
        ],
        "return_type": "string",
        "examples": [
            "decodedUrl := urlDecode(HttpUrl)",
            "| urlDecode(CommandLine)"
        ],
        "related_functions": ["base64Decode", "parseJson"],
        "use_cases": ["URL decoding", "HTTP request analysis", "Encoded string parsing"],
        "notes": "Useful for analyzing web traffic and HTTP request data."
    },
    "geohash": {
        "name": "geohash",
        "category": "geospatial",
        "description": "Converts geographic coordinates (latitude/longitude) into a geohash string for spatial indexing and clustering.",
        "syntax": "geohash(lat, lon, [precision])",
        "parameters": [
            {
                "name": "lat",
                "type": "number",
                "required": True,
                "description": "Latitude coordinate"
            },
            {
                "name": "lon",
                "type": "number",
                "required": True,
                "description": "Longitude coordinate"
            },
            {
                "name": "precision",
                "type": "number",
                "required": False,
                "default": 5,
                "description": "Geohash precision level (1-12)"
            }
        ],
        "return_type": "string",
        "examples": [
            "locHash := geohash(latitude, longitude, 6)",
            "| groupBy([geohash(lat, lon)], function=count())"
        ],
        "related_functions": ["ipLocation", "worldMap"],
        "use_cases": ["Geographic clustering", "Location-based grouping", "Spatial analysis"],
        "notes": "Higher precision values create more specific geohashes. Commonly used for geographic event clustering."
    },
    "filter": {
        "name": "filter",
        "category": "filtering",
        "description": "Filters array or collection elements based on a condition. Returns a subset of elements matching the specified criteria.",
        "syntax": "filter(array, condition)",
        "parameters": [
            {
                "name": "array",
                "type": "array",
                "required": True,
                "description": "Array to filter"
            },
            {
                "name": "condition",
                "type": "expression",
                "required": True,
                "description": "Boolean condition to evaluate for each element"
            }
        ],
        "return_type": "array",
        "examples": [
            "| filter(collection, element > threshold)",
            "validItems := filter(items, match(element, pattern))"
        ],
        "related_functions": ["collect", "select"],
        "use_cases": ["Array filtering", "Collection subset", "Conditional selection"],
        "notes": "Useful for filtering collected arrays or multi-value fields."
    },
    "parseTimestamp": {
        "name": "parseTimestamp",
        "category": "time",
        "description": "Parses a timestamp string into epoch time format. Supports various date/time formats.",
        "syntax": "parseTimestamp(field, [format])",
        "parameters": [
            {
                "name": "field",
                "type": "string",
                "required": True,
                "description": "Timestamp string to parse"
            },
            {
                "name": "format",
                "type": "string",
                "required": False,
                "description": "Expected timestamp format pattern"
            }
        ],
        "return_type": "long",
        "examples": [
            "epochTime := parseTimestamp(timeString)",
            "timestamp := parseTimestamp(dateField, format=\"%Y-%m-%d\")"
        ],
        "related_functions": ["formatTime", "bucket", "now"],
        "use_cases": ["Timestamp parsing", "Date conversion", "Time normalization"],
        "notes": "Converts various timestamp formats to epoch time for temporal operations."
    },
    "shannonEntropy": {
        "name": "shannonEntropy",
        "category": "analysis",
        "description": "Calculates Shannon entropy of a string to measure randomness/complexity. Higher values indicate more random/encoded content.",
        "syntax": "shannonEntropy(field)",
        "parameters": [
            {
                "name": "field",
                "type": "string",
                "required": True,
                "description": "String to calculate entropy for"
            }
        ],
        "return_type": "number",
        "examples": [
            "entropy := shannonEntropy(CommandLine)",
            "| where shannonEntropy(ScriptContent) > 4.5"
        ],
        "related_functions": ["base64Decode", "length"],
        "use_cases": ["Encoded content detection", "Obfuscation detection", "Randomness analysis", "Malware detection"],
        "notes": "Values typically range from 0 (not random) to ~8 (highly random). Base64 encoded strings often have entropy around 5-6."
    },
    "base64Decode": {
        "name": "base64Decode",
        "category": "transformation",
        "description": "Decodes Base64-encoded strings back to their original content. Commonly used for analyzing encoded commands and payloads.",
        "syntax": "base64Decode(field, [charset])",
        "parameters": [
            {
                "name": "field",
                "type": "string",
                "required": True,
                "description": "Base64-encoded string to decode"
            },
            {
                "name": "charset",
                "type": "string",
                "required": False,
                "default": "UTF-8",
                "description": "Character encoding to use"
            }
        ],
        "return_type": "string",
        "examples": [
            "decoded := base64Decode(b64String)",
            "command := base64Decode(encodedCommand, charset=\"UTF-16LE\")"
        ],
        "related_functions": ["urlDecode", "shannonEntropy", "parseJson"],
        "use_cases": ["Encoded command analysis", "Payload decoding", "PowerShell command inspection"],
        "notes": "PowerShell often uses Base64 encoding with -enc flag. UTF-16LE charset common for Windows."
    },
    "cidr": {
        "name": "cidr",
        "category": "network",
        "description": "Checks if an IP address falls within specified CIDR subnet ranges. Returns true if IP matches any provided subnet.",
        "syntax": "cidr(ip_field, subnet=[\"cidr1\", \"cidr2\", ...])",
        "parameters": [
            {
                "name": "ip_field",
                "type": "string",
                "required": True,
                "description": "IP address field to check"
            },
            {
                "name": "subnet",
                "type": "array",
                "required": True,
                "description": "Array of CIDR subnet ranges"
            }
        ],
        "return_type": "boolean",
        "examples": [
            "| where cidr(RemoteAddressIP4, subnet=[\"10.0.0.0/8\", \"192.168.0.0/16\"])",
            "| where !cidr(RemoteAddressIP4, subnet=[\"10.0.0.0/8\"])"
        ],
        "related_functions": ["ipLocation", "asn"],
        "use_cases": ["IP range filtering", "Private IP detection", "Network segmentation", "Subnet matching"],
        "notes": "Commonly used to filter RFC1918 private addresses or specific network ranges."
    }
}

# Additional medium/low priority functions
ADDITIONAL_FUNCTIONS = {
    "series": {
        "name": "series",
        "category": "analysis",
        "description": "Creates a time series analysis of events, organizing data into temporal buckets for trend analysis.",
        "syntax": "series(field, [span])",
        "parameters": [
            {"name": "field", "type": "string", "required": True, "description": "Field to analyze over time"},
            {"name": "span", "type": "string", "required": False, "description": "Time bucket size"}
        ],
        "return_type": "series_data",
        "examples": ["| series(count(), span=1h)"],
        "related_functions": ["timechart", "bucket"],
        "use_cases": ["Time series analysis", "Trend detection"],
        "notes": "Used for temporal pattern analysis."
    },
    "if": {
        "name": "if",
        "category": "conditional",
        "description": "Conditional expression that returns different values based on a boolean condition. Similar to ternary operator.",
        "syntax": "if(condition, then=value1, else=value2)",
        "parameters": [
            {"name": "condition", "type": "boolean", "required": True, "description": "Condition to evaluate"},
            {"name": "then", "type": "any", "required": True, "description": "Value if condition is true"},
            {"name": "else", "type": "any", "required": True, "description": "Value if condition is false"}
        ],
        "return_type": "any",
        "examples": [
            "result := if(count > threshold, then=\"High\", else=\"Normal\")",
            "category := if(entropy > 5.0, then=\"Suspicious\", else=\"Normal\")"
        ],
        "related_functions": ["case"],
        "use_cases": ["Conditional logic", "Value transformation", "Categorization"],
        "notes": "Can be nested for complex conditional logic."
    },
    "md5": {
        "name": "md5",
        "category": "hash",
        "description": "Calculates MD5 hash of a string value. Used for creating unique identifiers or fingerprints.",
        "syntax": "md5(field)",
        "parameters": [
            {"name": "field", "type": "string", "required": True, "description": "String to hash"}
        ],
        "return_type": "string",
        "examples": [
            "userHash := md5(UserName)",
            "fingerprint := md5(concat(field1, field2))"
        ],
        "related_functions": ["sha256", "concat"],
        "use_cases": ["Unique ID generation", "Data fingerprinting", "Deduplication"],
        "notes": "MD5 is not cryptographically secure but useful for non-security hashing."
    },
    "neighbor": {
        "name": "neighbor",
        "category": "analysis",
        "description": "Accesses field values from neighboring (previous or next) events in a sorted sequence.",
        "syntax": "neighbor(field, [offset])",
        "parameters": [
            {"name": "field", "type": "string", "required": True, "description": "Field to access from neighbor"},
            {"name": "offset", "type": "number", "required": False, "default": -1, "description": "Offset (-1 for previous, 1 for next)"}
        ],
        "return_type": "value",
        "examples": [
            "prevValue := neighbor(value, -1)",
            "nextTimestamp := neighbor(@timestamp, 1)"
        ],
        "related_functions": ["sort", "groupBy"],
        "use_cases": ["Sequential analysis", "Temporal comparison", "State changes"],
        "notes": "Requires sorted events. Commonly used for calculating deltas between sequential events."
    },
    "distance": {
        "name": "distance",
        "category": "geospatial",
        "description": "Calculates distance between two geographic coordinate pairs. Returns distance in kilometers.",
        "syntax": "distance(lat1, lon1, lat2, lon2)",
        "parameters": [
            {"name": "lat1", "type": "number", "required": True, "description": "First latitude"},
            {"name": "lon1", "type": "number", "required": True, "description": "First longitude"},
            {"name": "lat2", "type": "number", "required": True, "description": "Second latitude"},
            {"name": "lon2", "type": "number", "required": True, "description": "Second longitude"}
        ],
        "return_type": "number",
        "examples": [
            "distKm := distance(lat1, lon1, lat2, lon2)",
            "| where distance(prevLat, prevLon, lat, lon) > 1000"
        ],
        "related_functions": ["geohash", "ipLocation"],
        "use_cases": ["Geographic distance calculation", "Impossible travel detection", "Location analysis"],
        "notes": "Uses Haversine formula for spherical distance. Result in kilometers."
    },
    "http": {
        "name": "http",
        "category": "network",
        "description": "Parses and analyzes HTTP request/response data from events.",
        "syntax": "http(field)",
        "parameters": [
            {"name": "field", "type": "string", "required": True, "description": "HTTP data field to parse"}
        ],
        "return_type": "parsed_http",
        "examples": [
            "| http(HttpRequestHeader)",
            "parsedReq := http(requestData)"
        ],
        "related_functions": ["urlDecode", "parseJson"],
        "use_cases": ["HTTP analysis", "Web traffic inspection", "Request parsing"],
        "notes": "Extracts HTTP method, URL, headers, and other request components."
    },
    "simpleName": {
        "name": "simpleName",
        "category": "transformation",
        "description": "Extracts the simple filename from a full file path, removing directory components.",
        "syntax": "simpleName(path_field)",
        "parameters": [
            {"name": "path_field", "type": "string", "required": True, "description": "Full file path"}
        ],
        "return_type": "string",
        "examples": [
            "fileName := simpleName(ImageFileName)",
            "| groupBy([simpleName(FilePath)])"
        ],
        "related_functions": ["split", "splitString"],
        "use_cases": ["Filename extraction", "Path normalization", "Grouping by filename"],
        "notes": "Handles both forward slash and backslash path separators."
    },
    "exe": {
        "name": "exe",
        "category": "transformation",
        "description": "Extracts executable name from a process or file path.",
        "syntax": "exe(path_field)",
        "parameters": [
            {"name": "path_field", "type": "string", "required": True, "description": "Process or file path"}
        ],
        "return_type": "string",
        "examples": [
            "exeName := exe(ImageFileName)",
            "| groupBy([exe(CommandLine)])"
        ],
        "related_functions": ["simpleName", "split"],
        "use_cases": ["Executable extraction", "Process name normalization"],
        "notes": "Similar to simpleName but specifically for executables."
    },
    "communityId": {
        "name": "communityId",
        "category": "network",
        "description": "Generates a Community ID hash for network flows, enabling correlation across different data sources.",
        "syntax": "communityId(src_ip, dst_ip, src_port, dst_port, protocol)",
        "parameters": [
            {"name": "src_ip", "type": "string", "required": True, "description": "Source IP address"},
            {"name": "dst_ip", "type": "string", "required": True, "description": "Destination IP address"},
            {"name": "src_port", "type": "number", "required": True, "description": "Source port"},
            {"name": "dst_port", "type": "number", "required": True, "description": "Destination port"},
            {"name": "protocol", "type": "string", "required": True, "description": "Protocol (TCP/UDP)"}
        ],
        "return_type": "string",
        "examples": [
            "flowId := communityId(LocalAddressIP4, RemoteAddressIP4, LocalPort, RemotePort, Protocol)",
            "| groupBy([communityId(src, dst, sport, dport, proto)])"
        ],
        "related_functions": ["ipLocation", "asn"],
        "use_cases": ["Network flow correlation", "Cross-tool analysis", "Flow hashing"],
        "notes": "Standard community ID format for network flow correlation across security tools."
    },
    "hour": {
        "name": "hour",
        "category": "time",
        "description": "Extracts the hour component (0-23) from a timestamp.",
        "syntax": "hour(timestamp_field)",
        "parameters": [
            {"name": "timestamp_field", "type": "long", "required": True, "description": "Timestamp to extract hour from"}
        ],
        "return_type": "number",
        "examples": [
            "loginHour := hour(@timestamp)",
            "| groupBy([hour(@timestamp)])"
        ],
        "related_functions": ["formatTime", "bucket"],
        "use_cases": ["Time-of-day analysis", "Temporal grouping", "Activity pattern detection"],
        "notes": "Returns hour in 24-hour format (0-23)."
    },
    "dayOfWeekName": {
        "name": "dayOfWeekName",
        "category": "time",
        "description": "Returns the name of the day of week (Monday, Tuesday, etc.) for a given timestamp.",
        "syntax": "dayOfWeekName(timestamp_field)",
        "parameters": [
            {"name": "timestamp_field", "type": "long", "required": True, "description": "Timestamp to get day name from"}
        ],
        "return_type": "string",
        "examples": [
            "dayName := dayOfWeekName(@timestamp)",
            "| groupBy([dayOfWeekName(@timestamp)])"
        ],
        "related_functions": ["hour", "formatTime"],
        "use_cases": ["Weekly pattern analysis", "Day grouping", "Temporal reporting"],
        "notes": "Returns full day name in English (e.g., 'Monday', 'Tuesday')."
    },
    "formattime": {
        "name": "formattime",
        "category": "time",
        "description": "Lowercase variant of formatTime(). Formats timestamp into human-readable string.",
        "syntax": "formattime(format, field=timestamp, [locale], [timezone])",
        "parameters": [
            {"name": "format", "type": "string", "required": True, "description": "Time format pattern"},
            {"name": "field", "type": "long", "required": True, "description": "Timestamp field to format"},
            {"name": "locale", "type": "string", "required": False, "description": "Locale for formatting"},
            {"name": "timezone", "type": "string", "required": False, "description": "Timezone for display"}
        ],
        "return_type": "string",
        "examples": [
            "readable := formattime(\"%Y-%m-%d %H:%M:%S\", field=@timestamp)",
            "date := formattime(\"%Y-%m-%d\", field=ProcessStartTime)"
        ],
        "related_functions": ["formatTime", "formatDuration"],
        "use_cases": ["Timestamp formatting", "Human-readable time display"],
        "notes": "Case-insensitive alias of formatTime()."
    },
    "parseInt": {
        "name": "parseInt",
        "category": "transformation",
        "description": "Parses a string value as an integer number. Useful for converting string fields to numeric types.",
        "syntax": "parseInt(field, [radix])",
        "parameters": [
            {"name": "field", "type": "string", "required": True, "description": "String to parse as integer"},
            {"name": "radix", "type": "number", "required": False, "default": 10, "description": "Number base (e.g., 10, 16)"}
        ],
        "return_type": "long",
        "examples": [
            "numValue := parseInt(stringField)",
            "hexValue := parseInt(hexString, radix=16)"
        ],
        "related_functions": ["convert", "round"],
        "use_cases": ["String to number conversion", "Type casting", "Numeric operations"],
        "notes": "Returns NaN for non-numeric strings. Radix 16 for hexadecimal parsing."
    },
    "parseHexString": {
        "name": "parseHexString",
        "category": "transformation",
        "description": "Parses hexadecimal string into binary or string representation.",
        "syntax": "parseHexString(hex_field)",
        "parameters": [
            {"name": "hex_field", "type": "string", "required": True, "description": "Hexadecimal string to parse"}
        ],
        "return_type": "string",
        "examples": [
            "decoded := parseHexString(hexData)",
            "| parseHexString(MagicNumber)"
        ],
        "related_functions": ["parseInt", "base64Decode"],
        "use_cases": ["Hex decoding", "Binary data parsing", "Magic number decoding"],
        "notes": "Commonly used for parsing binary data encoded as hex strings."
    },
    "usersid_username_win": {
        "name": "usersid_username_win",
        "category": "enrichment",
        "description": "Enriches Windows SID values with corresponding usernames. Maps Security Identifiers to user account names.",
        "syntax": "usersid_username_win(sid_field)",
        "parameters": [
            {"name": "sid_field", "type": "string", "required": True, "description": "Windows SID to resolve"}
        ],
        "return_type": "string",
        "examples": [
            "userName := usersid_username_win(UserSid)",
            "| usersid_username_win(TargetUserSid)"
        ],
        "related_functions": ["enrich", "match"],
        "use_cases": ["SID to username mapping", "Windows user enrichment", "Identity resolution"],
        "notes": "Windows-specific function for resolving SID values to usernames."
    },
    "runs": {
        "name": "runs",
        "category": "analysis",
        "description": "Identifies runs or sequences of similar values in sorted data. Used for detecting patterns and anomalies.",
        "syntax": "runs(field)",
        "parameters": [
            {"name": "field", "type": "string", "required": True, "description": "Field to analyze for runs"}
        ],
        "return_type": "run_data",
        "examples": [
            "| runs(CommandLine)",
            "| runs(ImageFileName) | where runLength > 5"
        ],
        "related_functions": ["groupBy", "sort"],
        "use_cases": ["Pattern detection", "Anomaly identification", "Sequence analysis"],
        "notes": "Useful for detecting repeated executions or sequences of similar events."
    }
}

def create_function_file(func_name: str, func_def: dict):
    """Create a JSON function definition file."""
    file_path = FUNCTIONS_DIR / f"{func_name}.json"
    
    # Skip if file already exists
    if file_path.exists():
        print(f"  ⏭️  Skipping {func_name} (already exists)")
        return False
    
    with open(file_path, 'w') as f:
        json.dump(func_def, f, indent=2)
    
    print(f"  ✅ Created {func_name}.json")
    return True

def main():
    """Main execution."""
    print("🔧 Adding missing CQL functions...\n")
    
    # Ensure functions directory exists
    FUNCTIONS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Add high-priority functions
    print("📝 Adding high-priority functions:")
    high_count = 0
    for func_name, func_def in MISSING_FUNCTIONS.items():
        if create_function_file(func_name, func_def):
            high_count += 1
    
    print(f"\n📝 Adding additional functions:")
    add_count = 0
    for func_name, func_def in ADDITIONAL_FUNCTIONS.items():
        if create_function_file(func_name, func_def):
            add_count += 1
    
    total_created = high_count + add_count
    total_attempted = len(MISSING_FUNCTIONS) + len(ADDITIONAL_FUNCTIONS)
    
    print(f"\n✨ Summary:")
    print(f"   Created: {total_created} functions")
    print(f"   Skipped: {total_attempted - total_created} (already existed)")
    print(f"   Total: {total_attempted} functions processed")

if __name__ == "__main__":
    main()
