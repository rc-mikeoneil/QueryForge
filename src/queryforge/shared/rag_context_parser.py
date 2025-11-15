"""RAG Context Parser - Extract query-relevant information from RAG documents.

This module provides base and platform-specific parsers to extract actionable
query components from RAG retrieval results.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set, Tuple

# Pattern for extracting field names from different formats
# CBC: field_name:value or field_name (type)
# KQL: ColumnName == value or | where ColumnName
# Cortex: filter field_name = value
# S1: field.path = 'value'
FIELD_PATTERNS = {
    "cbc": re.compile(r'\b([a-z_][a-z0-9_]*)\s*[:(]', re.IGNORECASE),
    "kql": re.compile(r'\b([A-Z][A-Za-z0-9]*)\b'),
    "cortex": re.compile(r'\b([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*)\b'),
    "s1": re.compile(r'\b([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*)\b'),
}

# Pattern for extracting field:value pairs
VALUE_PATTERNS = {
    "cbc": re.compile(r'([a-z_][a-z0-9_]*)\s*:\s*(["\']?)([^"\'\s]+)\2', re.IGNORECASE),
    "kql": re.compile(r'([A-Z][A-Za-z0-9]*)\s*(?:==|:)\s*["\']?([^"\'\s]+)["\']?'),
    "cortex": re.compile(r'([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*)\s*(?:=|:|is)\s*["\']?([^"\'\s\,\;]+)["\']?'),
    "s1": re.compile(r'([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*)\s*(?:=|:|is)\s*["\']?([^"\'\s\,\;]+)["\']?'),
}


class RAGContextParser:
    """Base class for extracting query components from RAG documents."""

    # Class-level cache for parsed contexts
    _cache: Dict[str, Tuple[Dict[str, Any], float]] = {}
    _cache_ttl: int = 300  # 5 minutes TTL
    _max_cache_size: int = 100  # Maximum cache entries

    def __init__(self, platform: str):
        """Initialize parser for specific platform.
        
        Args:
            platform: Platform identifier (cbc, kql, cortex, s1)
        """
        self.platform = platform
        self.field_pattern = FIELD_PATTERNS.get(platform)
        self.value_pattern = VALUE_PATTERNS.get(platform)
        self.max_fields = 10  # Limit fields extracted per query
        self.max_values_per_field = 5  # Limit values per field
        self.parsing_timeout = 5.0  # 5 second timeout for parsing

    def parse_context(
        self,
        documents: List[Dict[str, Any]],
        intent: str,
        dataset: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Parse RAG documents to extract actionable query components.
        
        Args:
            documents: List of retrieved RAG documents
            intent: User's natural language intent
            dataset: Optional dataset/table name for context
            
        Returns:
            Dictionary containing:
            - fields: List of relevant field names
            - values: Dict mapping fields to suggested values
            - patterns: List of query patterns from examples
            - operators: Dict mapping fields to appropriate operators
            - relationships: List of related fields
            - confidence: Confidence score (0-1)
        """
        if not documents:
            return self._empty_result()

        # Check cache first
        cache_key = self._generate_cache_key(documents, intent, dataset)
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            return cached_result

        # Set timeout for parsing
        start_time = time.time()
        
        try:
            # Extract components with timeout awareness
            fields = self.extract_fields(documents, intent)
            if time.time() - start_time > self.parsing_timeout:
                return self._empty_result()
            
            values = self.extract_values(documents, fields, intent)
            if time.time() - start_time > self.parsing_timeout:
                return self._empty_result()
            
            patterns = self.parse_examples(documents, intent)
            if time.time() - start_time > self.parsing_timeout:
                return self._empty_result()
            
            operators = self.identify_operators(documents, fields)
            if time.time() - start_time > self.parsing_timeout:
                return self._empty_result()
            
            relationships = self.identify_relationships(documents, fields)
            
            # Calculate confidence based on quality of extraction
            confidence = self._calculate_confidence(
                documents, fields, values, patterns
            )

            result = {
                "fields": fields[:self.max_fields],  # Enforce field limit
                "values": values,
                "patterns": patterns,
                "operators": operators,
                "relationships": relationships,
                "confidence": confidence,
                "platform": self.platform,
                "dataset": dataset,
            }
            
            # Cache the result
            self._add_to_cache(cache_key, result)
            
            return result
            
        except Exception as e:
            # Circuit breaker: If parsing fails, return empty result
            # This ensures graceful degradation
            print(f"RAG parsing error (falling back to basic query): {e}")
            return self._empty_result()

    def extract_fields(
        self, documents: List[Dict[str, Any]], intent: str
    ) -> List[str]:
        """Extract relevant field names from RAG documents.
        
        Args:
            documents: Retrieved RAG documents
            intent: User's natural language intent
            
        Returns:
            List of field names sorted by relevance
        """
        field_counts: Dict[str, int] = {}
        intent_lower = intent.lower()

        for doc in documents:
            text = doc.get("text", "")
            score = doc.get("score", 0)
            
            # Higher-scored documents contribute more weight
            weight = int(score * 10) if score > 0 else 1
            
            # Extract field names using platform-specific pattern
            if self.field_pattern:
                for match in self.field_pattern.finditer(text):
                    field = match.group(1)
                    if field and len(field) > 1:  # Skip single-char matches
                        field_counts[field] = field_counts.get(field, 0) + weight
            
            # Boost fields mentioned in intent
            for field in field_counts.keys():
                if field.lower() in intent_lower:
                    field_counts[field] += 5

        # Sort by count (relevance) and return top fields
        sorted_fields = sorted(
            field_counts.items(), key=lambda x: x[1], reverse=True
        )
        
        # Return top N most relevant fields (limited by max_fields)
        return [field for field, _ in sorted_fields[:self.max_fields]]

    def extract_values(
        self,
        documents: List[Dict[str, Any]],
        fields: List[str],
        intent: str,
    ) -> Dict[str, List[str]]:
        """Extract suggested values for fields from RAG documents.
        
        Args:
            documents: Retrieved RAG documents
            fields: List of relevant fields
            intent: User's natural language intent
            
        Returns:
            Dictionary mapping field names to lists of suggested values
        """
        field_values: Dict[str, Set[str]] = {field: set() for field in fields}
        intent_lower = intent.lower()

        for doc in documents:
            text = doc.get("text", "")
            
            # Extract field:value pairs using platform-specific pattern
            if self.value_pattern:
                for match in self.value_pattern.finditer(text):
                    field = match.group(1)
                    # Handle different group patterns
                    if len(match.groups()) >= 3:
                        value = match.group(2) or match.group(3)
                    elif len(match.groups()) >= 2:
                        value = match.group(2)
                    else:
                        continue
                    
                    if field in field_values and value:
                        # Limit to reasonable values (not too long)
                        if len(value) < 100:
                            field_values[field].add(value)
            
            # Check for common formats like "examples" sections
            examples_pattern = re.compile(r'examples?:?\s*([^\.]+)', re.IGNORECASE)
            examples_match = examples_pattern.search(text)
            if examples_match:
                examples_text = examples_match.group(1)
                
                # Look for field-specific examples in this section
                for field in fields:
                    field_pattern = rf'{re.escape(field)}[=:]?\s*([^,\s\.;]+)'
                    for match in re.finditer(field_pattern, examples_text, re.IGNORECASE):
                        value = match.group(1).strip('"\'')
                        if value and len(value) < 100:
                            field_values[field].add(value)
                
                # Look for mentions of specific values in examples
                for word in re.findall(r'[\w\.-]+\.(?:exe|dll)', examples_text, re.IGNORECASE):
                    # For process-related fields, add executable names
                    for field in fields:
                        if any(name in field.lower() for name in ["process", "image", "file"]):
                            if len(word) < 100:
                                field_values[field].add(word.strip())
                
                # Look for port numbers in examples
                for port in re.findall(r'(?:port|:)\s*(\d{1,5})', examples_text, re.IGNORECASE):
                    port_num = int(port)
                    if 0 < port_num < 65536:  # Valid port range
                        for field in fields:
                            if "port" in field.lower():
                                field_values[field].add(port)
            
            # Look for field-specific value patterns
            for field in fields:
                # Pattern 1: "field_name ... Values: val1, val2, val3"
                values_match = re.search(
                    rf'{re.escape(field)}[^\n]*?Values?:\s*([^\n]+)',
                    text,
                    re.IGNORECASE
                )
                if values_match:
                    values_text = values_match.group(1)
                    # Extract comma-separated values
                    for val in re.split(r'[,;]', values_text):
                        val = val.strip().strip('"\'')
                        if val and len(val) < 100 and not val.isspace():
                            field_values[field].add(val)
                
                # Pattern 2: "Examples: field_name:value1, field_name:value2"
                example_pattern = rf'Examples?:[^\n]*?{re.escape(field)}:([^,\s\n]+)'
                for match in re.finditer(example_pattern, text, re.IGNORECASE):
                    value = match.group(1).strip().strip('"\'')
                    if value and len(value) < 100:
                        field_values[field].add(value)
                
                # Pattern 3: Look for any mention of field with colon
                field_colon_pattern = rf'{re.escape(field)}:([A-Za-z0-9._-]+)'
                for match in re.finditer(field_colon_pattern, text, re.IGNORECASE):
                    value = match.group(1).strip().strip('"\'')
                    if value and len(value) < 100:
                        field_values[field].add(value)

        # Convert sets to lists, limit values per field
        return {
            field: list(values)[:self.max_values_per_field]
            for field, values in field_values.items()
            if values
        }

    def parse_examples(
        self, documents: List[Dict[str, Any]], intent: str
    ) -> List[str]:
        """Parse example queries from RAG documents.
        
        Args:
            documents: Retrieved RAG documents
            intent: User's natural language intent
            
        Returns:
            List of relevant query patterns/examples
        """
        patterns: List[Tuple[str, float]] = []
        intent_lower = intent.lower()

        for doc in documents:
            text = doc.get("text", "")
            score = doc.get("score", 0.5)
            
            # Look for example query sections
            example_matches = re.finditer(
                r'(?:Query|Example|Pattern):\s*([^\n]+)',
                text,
                re.IGNORECASE
            )
            
            for match in example_matches:
                query = match.group(1).strip()
                if query and len(query) > 5:  # Skip trivial examples
                    # Boost relevance if query contains intent keywords
                    relevance = score
                    for word in intent_lower.split():
                        if len(word) > 3 and word in query.lower():
                            relevance += 0.1
                    patterns.append((query, min(relevance, 1.0)))

        # Sort by relevance and return top 5
        patterns.sort(key=lambda x: x[1], reverse=True)
        return [pattern for pattern, _ in patterns[:5]]

    def identify_operators(
        self, documents: List[Dict[str, Any]], fields: List[str]
    ) -> Dict[str, List[str]]:
        """Identify appropriate operators for fields.
        
        Args:
            documents: Retrieved RAG documents
            fields: List of relevant fields
            
        Returns:
            Dictionary mapping field names to suggested operators
        """
        field_operators: Dict[str, Set[str]] = {field: set() for field in fields}

        for doc in documents:
            text = doc.get("text", "")
            
            # Look for operator information
            for field in fields:
                # Common operators
                operator_patterns = [
                    (r'==|equals?', '=='),
                    (r'!=|not\s+equals?', '!='),
                    (r'contains?', 'contains'),
                    (r'[><]=?', 'comparison'),
                    (r'in\b', 'in'),
                    (r'like', 'like'),
                ]
                
                for pattern, op_type in operator_patterns:
                    if re.search(
                        rf'{re.escape(field)}[^\n]*?{pattern}',
                        text,
                        re.IGNORECASE
                    ):
                        field_operators[field].add(op_type)

        return {
            field: list(ops)
            for field, ops in field_operators.items()
            if ops
        }

    def identify_relationships(
        self, documents: List[Dict[str, Any]], fields: List[str]
    ) -> List[List[str]]:
        """Identify related fields that should be queried together.
        
        Args:
            documents: Retrieved RAG documents
            fields: List of relevant fields
            
        Returns:
            List of field groups (lists of related field names)
        """
        # Track co-occurrence of fields in documents
        co_occurrence: Dict[Tuple[str, str], int] = {}
        
        for doc in documents:
            text = doc.get("text", "")
            fields_in_doc = [f for f in fields if f in text]
            
            # Count co-occurrences
            for i, field1 in enumerate(fields_in_doc):
                for field2 in fields_in_doc[i+1:]:
                    key = tuple(sorted([field1, field2]))
                    co_occurrence[key] = co_occurrence.get(key, 0) + 1

        # Build relationship groups
        relationships: List[List[str]] = []
        used_fields: Set[str] = set()
        
        # Sort by co-occurrence count
        sorted_pairs = sorted(
            co_occurrence.items(), key=lambda x: x[1], reverse=True
        )
        
        for (field1, field2), count in sorted_pairs:
            if count < 2:  # Require at least 2 co-occurrences
                break
            
            # Find or create group
            group_found = False
            for group in relationships:
                if field1 in group or field2 in group:
                    if field1 not in group:
                        group.append(field1)
                    if field2 not in group:
                        group.append(field2)
                    group_found = True
                    break
            
            if not group_found:
                relationships.append([field1, field2])

        return relationships

    def _calculate_confidence(
        self,
        documents: List[Dict[str, Any]],
        fields: List[str],
        values: Dict[str, List[str]],
        patterns: List[str],
    ) -> float:
        """Calculate confidence score for parsed context.
        
        Args:
            documents: Retrieved RAG documents
            fields: Extracted fields
            values: Extracted values
            patterns: Extracted patterns
            
        Returns:
            Confidence score between 0 and 1
        """
        if not documents:
            return 0.0

        # Start with average document score
        avg_score = sum(doc.get("score", 0) for doc in documents) / len(documents)
        confidence = avg_score * 0.5  # 50% weight on retrieval quality
        
        # Boost confidence based on extraction results
        if fields:
            confidence += 0.15  # Found relevant fields
        if values:
            confidence += 0.15  # Found example values
        if patterns:
            confidence += 0.20  # Found example patterns
        
        # Cap at 1.0
        return min(confidence, 1.0)

    def _generate_cache_key(
        self,
        documents: List[Dict[str, Any]],
        intent: str,
        dataset: Optional[str],
    ) -> str:
        """Generate a cache key from input parameters.
        
        Args:
            documents: RAG documents
            intent: User intent
            dataset: Dataset name
            
        Returns:
            SHA256 hash of the inputs
        """
        # Create a deterministic string representation
        doc_strings = [
            f"{doc.get('text', '')}:{doc.get('score', 0)}"
            for doc in documents[:5]  # Only use top 5 for cache key
        ]
        cache_input = f"{self.platform}|{intent}|{dataset}|{'|'.join(doc_strings)}"
        
        return hashlib.sha256(cache_input.encode()).hexdigest()

    def _get_from_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve result from cache if valid.
        
        Args:
            cache_key: Cache key to lookup
            
        Returns:
            Cached result if valid, None otherwise
        """
        if cache_key in self._cache:
            result, timestamp = self._cache[cache_key]
            # Check if cache entry is still valid
            if time.time() - timestamp < self._cache_ttl:
                return result
            else:
                # Remove expired entry
                del self._cache[cache_key]
        
        return None

    def _add_to_cache(self, cache_key: str, result: Dict[str, Any]) -> None:
        """Add result to cache with timestamp.
        
        Args:
            cache_key: Cache key
            result: Result to cache
        """
        # Enforce max cache size
        if len(self._cache) >= self._max_cache_size:
            # Remove oldest entry
            oldest_key = min(self._cache.items(), key=lambda x: x[1][1])[0]
            del self._cache[oldest_key]
        
        self._cache[cache_key] = (result, time.time())

    @classmethod
    def clear_cache(cls) -> None:
        """Clear the entire cache."""
        cls._cache.clear()

    @classmethod
    def get_cache_stats(cls) -> Dict[str, Any]:
        """Get cache statistics.
        
        Returns:
            Dictionary with cache stats
        """
        return {
            "size": len(cls._cache),
            "max_size": cls._max_cache_size,
            "ttl_seconds": cls._cache_ttl,
        }

    def _empty_result(self) -> Dict[str, Any]:
        """Return empty result structure."""
        return {
            "fields": [],
            "values": {},
            "patterns": [],
            "operators": {},
            "relationships": [],
            "confidence": 0.0,
            "platform": self.platform,
            "dataset": None,
        }


class CBCRAGContextParser(RAGContextParser):
    """CBC-specific RAG context parser."""

    def __init__(self):
        super().__init__("cbc")

    def extract_fields(
        self, documents: List[Dict[str, Any]], intent: str
    ) -> List[str]:
        """Extract CBC field names with special handling."""
        fields = super().extract_fields(documents, intent)
        
        # CBC-specific field prioritization
        # Common security fields should be prioritized
        priority_fields = {
            "process_name": 10,
            "process_cmdline": 8,
            "netconn_domain": 7,
            "netconn_port": 7,
            "parent_name": 6,
            "filemod_name": 5,
        }
        
        # Adjust field rankings
        field_scores = {f: 0 for f in fields}
        for field in fields:
            if field in priority_fields:
                field_scores[field] += priority_fields[field]
        
        # Re-sort with priorities
        return sorted(field_scores.keys(), key=lambda f: field_scores[f], reverse=True)


class KQLRAGContextParser(RAGContextParser):
    """KQL-specific RAG context parser."""

    def __init__(self):
        super().__init__("kql")

    def extract_fields(
        self, documents: List[Dict[str, Any]], intent: str
    ) -> List[str]:
        """Extract KQL column names with special handling."""
        fields = super().extract_fields(documents, intent)
        
        # KQL uses PascalCase for column names
        # Filter to keep only properly formatted column names
        return [f for f in fields if f and f[0].isupper()]


class CortexRAGContextParser(RAGContextParser):
    """Cortex XDR-specific RAG context parser."""

    def __init__(self):
        super().__init__("cortex")

    def extract_fields(
        self, documents: List[Dict[str, Any]], intent: str
    ) -> List[str]:
        """Extract Cortex field names with special handling."""
        fields = super().extract_fields(documents, intent)
        
        # Cortex uses prefixed field groups (actor_, causality_, etc.)
        # Prioritize complete field paths
        priority_prefixes = [
            "actor_process_",
            "causality_actor_",
            "action_",
            "dst_action_",
        ]
        
        prioritized = []
        standard = []
        
        for field in fields:
            if any(field.startswith(prefix) for prefix in priority_prefixes):
                prioritized.append(field)
            else:
                standard.append(field)
        
        return prioritized + standard


class S1RAGContextParser(RAGContextParser):
    """SentinelOne-specific RAG context parser."""

    def __init__(self):
        super().__init__("s1")

    def extract_fields(
        self, documents: List[Dict[str, Any]], intent: str
    ) -> List[str]:
        """Extract S1 field names with special handling."""
        fields = super().extract_fields(documents, intent)
        
        # S1 uses dotted paths (src.process.name, dst.port.number)
        # Prioritize complete paths over partial matches
        complete_paths = [f for f in fields if '.' in f]
        partial_paths = [f for f in fields if '.' not in f]
        
        return complete_paths + partial_paths


class CQLRAGContextParser(RAGContextParser):
    """CrowdStrike Query Language-specific RAG context parser."""

    def __init__(self):
        super().__init__("cql")
        # CQL uses similar patterns to other query languages
        # Field names are typically lowercase with underscores
        self.field_pattern = re.compile(r'\b([a-z_][a-z0-9_]*)\b', re.IGNORECASE)
        self.value_pattern = re.compile(
            r'([a-z_][a-z0-9_]*)\s*(?:=|:|is)\s*["\']?([^"\'\s\,\;]+)["\']?',
            re.IGNORECASE
        )

    def extract_fields(
        self, documents: List[Dict[str, Any]], intent: str
    ) -> List[str]:
        """Extract CQL field names with special handling."""
        fields = super().extract_fields(documents, intent)
        
        # CQL-specific field prioritization
        # Common security fields should be prioritized
        priority_fields = {
            "process_name": 10,
            "command_line": 8,
            "file_path": 7,
            "file_hash": 7,
            "destination_ip": 7,
            "destination_port": 6,
            "source_ip": 6,
            "user_name": 6,
        }
        
        # Adjust field rankings
        field_scores = {f: 0 for f in fields}
        for field in fields:
            if field in priority_fields:
                field_scores[field] += priority_fields[field]
        
        # Re-sort with priorities
        return sorted(field_scores.keys(), key=lambda f: field_scores[f], reverse=True)


def create_rag_context_parser(platform: str) -> RAGContextParser:
    """Factory function to create appropriate parser for platform.
    
    Args:
        platform: Platform identifier (cbc, kql, cortex, s1, cql)
        
    Returns:
        Platform-specific RAG context parser
        
    Raises:
        ValueError: If platform is not supported
    """
    parsers = {
        "cbc": CBCRAGContextParser,
        "kql": KQLRAGContextParser,
        "cortex": CortexRAGContextParser,
        "s1": S1RAGContextParser,
        "cql": CQLRAGContextParser,
    }
    
    parser_class = parsers.get(platform.lower())
    if not parser_class:
        raise ValueError(
            f"Unsupported platform: {platform}. "
            f"Supported platforms: {', '.join(parsers.keys())}"
        )
    
    return parser_class()
