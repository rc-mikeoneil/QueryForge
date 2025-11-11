# RAG Enhancement Developer Guide

**Version:** 1.0  
**Last Updated:** 2025-11-05  
**Status:** Production Ready

## Overview

The RAG (Retrieval-Augmented Generation) Enhancement system bridges the gap between semantic search results and query construction. When a user requests "RDP activity", the system:

1. **Retrieves** relevant schema documents via RAG (e.g., documents about netconn_port, process names)
2. **Parses** those documents to extract actionable query components
3. **Enhances** the generated query with multiple indicators instead of just one
4. **Validates** the comprehensive query before presenting to the user

**Result:** Queries go from simplistic (`netconn_port:3389`) to comprehensive (`(netconn_port:3389 OR process_name:mstsc.exe OR process_name:rdpclip.exe)`)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     User Request                                 │
│              "Show me RDP activity in last 3 days"               │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    RAG Retrieval                                 │
│  • Semantic search finds relevant docs about RDP                 │
│  • Returns: netconn_port info, process names, examples           │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│               RAG Context Parser (NEW)                           │
│  • Extracts fields: [netconn_port, process_name]                │
│  • Extracts values: {process_name: [mstsc.exe, rdpclip.exe]}    │
│  • Parses example patterns                                       │
│  • Identifies field relationships                                │
│  • Calculates confidence score                                   │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              Query Builder (ENHANCED)                            │
│  • Combines user intent + RAG insights                           │
│  • Generates: (netconn_port:3389 OR                             │
│                process_name:mstsc.exe OR                         │
│                process_name:rdpclip.exe)                         │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Validator                                     │
│  • Validates comprehensive query                                 │
│  • Ensures all fields exist in schema                            │
│  • Checks syntax correctness                                     │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                 Enhanced Query Result                            │
│  User receives validated, comprehensive query                    │
└─────────────────────────────────────────────────────────────────┘
```

## Key Components

### 1. RAG Context Parser (`src/src/queryforge/shared/rag_context_parser.py`)

The parser extracts actionable query components from RAG retrieval results.

#### Base Class: `RAGContextParser`

```python
class RAGContextParser:
    """Base class for extracting query components from RAG documents."""
    
    def parse_context(
        self,
        documents: List[Dict[str, Any]],
        intent: str,
        dataset: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Returns:
            {
                "fields": [...],          # Relevant field names
                "values": {...},          # field -> suggested values
                "patterns": [...],        # Query patterns from examples
                "operators": {...},       # field -> appropriate operators
                "relationships": [...],   # Related fields
                "confidence": float       # Confidence score (0-1)
            }
        """
```

#### Platform-Specific Parsers

- **`CBCRAGContextParser`**: Handles CBC syntax (field:value)
- **`KQLRAGContextParser`**: Handles KQL syntax (Table | where Column == value)
- **`CortexRAGContextParser`**: Handles XQL syntax (filter field = value)
- **`S1RAGContextParser`**: Handles S1QL syntax (field = 'value')

### 2. Query Builder Integration

Each platform's query builder now accepts an optional `rag_context` parameter:

```python
def build_xxx_query(
    schema: Dict[str, Any],
    *,
    natural_language_intent: Optional[str] = None,
    # ... other parameters ...
    rag_context: Optional[List[Dict[str, Any]]] = None,  # NEW
) -> Tuple[str, Dict[str, Any]]:
```

### 3. Server Tool Updates

MCP server tools pass RAG context to query builders:

```python
def xxx_build_query(...):
    # RAG context is retrieved
    rag_context = rag_service.search(...)
    
    # Pass to query builder
    query, metadata = build_xxx_query(
        schema,
        natural_language_intent=intent,
        rag_context=rag_context  # NEW
    )
```

## Performance Optimizations

### Caching

The parser implements intelligent caching to minimize overhead:

```python
# Class-level cache with TTL
_cache: Dict[str, Tuple[Dict[str, Any], float]] = {}
_cache_ttl: int = 300  # 5 minutes
_max_cache_size: int = 100  # Max entries
```

**Cache Key Generation:**
- Based on platform, intent, dataset, and top 5 RAG documents
- SHA256 hash for deterministic keys
- Automatic expiration after TTL

**Cache Management:**
```python
# Clear cache if needed
RAGContextParser.clear_cache()

# Get cache statistics
stats = RAGContextParser.get_cache_stats()
# Returns: {"size": 45, "max_size": 100, "ttl_seconds": 300}
```

### Limits & Timeouts

To ensure performance:

```python
self.max_fields = 10              # Max fields per query
self.max_values_per_field = 5     # Max values per field
self.parsing_timeout = 5.0        # 5 second timeout
```

### Circuit Breaker

Graceful degradation on parsing failures:

```python
try:
    # Parse RAG context
    result = parse_context(...)
except Exception as e:
    # Fall back to basic query building
    return empty_result()
```

## Usage Examples

### Example 1: Basic Usage

```python
from queryforge.shared.rag_context_parser import create_rag_context_parser
from queryforge.platforms.cbc.query_builder import build_cbc_query

# RAG retrieval results
rag_context = [
    {
        "text": "RDP uses port 3389. Processes: mstsc.exe, rdpclip.exe",
        "score": 0.95,
        "source": "best_practices"
    }
]

# Build query with RAG enhancement
query, metadata = build_cbc_query(
    schema,
    natural_language_intent="RDP connections",
    search_type="process_search",
    rag_context=rag_context  # Enable RAG enhancement
)

# Result: (netconn_port:3389 OR process_name:mstsc.exe OR ...)
```

### Example 2: Direct Parser Usage

```python
from queryforge.shared.rag_context_parser import create_rag_context_parser

# Create parser
parser = create_rag_context_parser("cbc")

# Parse RAG context
parsed = parser.parse_context(
    documents=rag_context,
    intent="RDP connections",
    dataset="process_search"
)

print(f"Fields: {parsed['fields']}")
# Output: ['netconn_port', 'process_name']

print(f"Values: {parsed['values']}")
# Output: {'process_name': ['mstsc.exe', 'rdpclip.exe'], ...}

print(f"Confidence: {parsed['confidence']}")
# Output: 0.85
```

### Example 3: Low Confidence Handling

```python
# Low quality RAG context
poor_rag = [
    {
        "text": "Unrelated content",
        "score": 0.1,
        "source": "irrelevant"
    }
]

# Parser returns low confidence
parsed = parser.parse_context(poor_rag, "test query")
print(parsed['confidence'])  # Output: < 0.3

# Query builder falls back to basic behavior
query, metadata = build_cbc_query(
    schema,
    natural_language_intent="test query",
    rag_context=poor_rag
)
# Result: Basic query without RAG enhancement
```

## Extending the System

### Adding a New Platform

1. **Create Platform-Specific Parser:**

```python
class NewPlatformRAGContextParser(RAGContextParser):
    """New platform-specific parser."""
    
    def __init__(self):
        super().__init__("new_platform")
    
    def extract_fields(self, documents, intent):
        """Platform-specific field extraction."""
        fields = super().extract_fields(documents, intent)
        # Add platform-specific logic
        return filtered_fields
```

2. **Register in Factory:**

```python
def create_rag_context_parser(platform: str):
    parsers = {
        "cbc": CBCRAGContextParser,
        "kql": KQLRAGContextParser,
        "cortex": CortexRAGContextParser,
        "s1": S1RAGContextParser,
        "new_platform": NewPlatformRAGContextParser,  # ADD
    }
    # ...
```

3. **Update Query Builder:**

```python
def build_new_platform_query(..., rag_context=None):
    if rag_context:
        parser = create_rag_context_parser("new_platform")
        parsed = parser.parse_context(rag_context, intent)
        # Use parsed data to enhance query
```

### Customizing Field Extraction

Override `extract_fields()` for custom logic:

```python
class CustomParser(RAGContextParser):
    def extract_fields(self, documents, intent):
        fields = super().extract_fields(documents, intent)
        
        # Custom prioritization
        priority_map = {"custom_field": 20}
        
        return sorted(
            fields,
            key=lambda f: priority_map.get(f, 0),
            reverse=True
        )
```

## Testing

### Unit Tests

Test individual parser methods:

```python
def test_field_extraction():
    parser = CBCRAGContextParser()
    docs = [{"text": "process_name:cmd.exe", "score": 0.9}]
    
    fields = parser.extract_fields(docs, "cmd")
    assert "process_name" in fields
```

### Integration Tests

Test end-to-end query enhancement:

```python
def test_rdp_query_enhancement():
    rag_context = get_rdp_rag_context()
    
    query, metadata = build_cbc_query(
        schema,
        natural_language_intent="RDP",
        rag_context=rag_context
    )
    
    assert "3389" in query
    assert "mstsc.exe" in query.lower()
```

### Performance Tests

Verify overhead limits:

```python
def test_performance():
    # Without RAG
    start = time.time()
    build_query(schema, intent="test")
    time_no_rag = time.time() - start
    
    # With RAG
    start = time.time()
    build_query(schema, intent="test", rag_context=docs)
    time_with_rag = time.time() - start
    
    overhead = (time_with_rag - time_no_rag) * 1000
    assert overhead < 100  # < 100ms
```

## Troubleshooting

### Issue: RAG Enhancement Not Applied

**Symptoms:** Queries remain simple despite RAG context

**Possible Causes:**
1. Low confidence score (< 0.5)
2. No fields extracted from RAG context
3. RAG parsing timeout exceeded

**Solutions:**
```python
# Check confidence
parsed = parser.parse_context(rag_context, intent)
print(f"Confidence: {parsed['confidence']}")

# Check extracted data
print(f"Fields: {parsed['fields']}")
print(f"Values: {parsed['values']}")

# If empty, improve RAG document quality
```

### Issue: Performance Degradation

**Symptoms:** Query building takes > 100ms

**Possible Causes:**
1. Large RAG context (> 20 documents)
2. Cache not working
3. Parsing timeout not set

**Solutions:**
```python
# Check cache stats
stats = RAGContextParser.get_cache_stats()
print(f"Cache size: {stats['size']}/{stats['max_size']}")

# Limit RAG documents
rag_context = rag_context[:10]  # Top 10 only

# Adjust timeout
parser.parsing_timeout = 3.0  # Faster timeout
```

### Issue: Incorrect Fields Extracted

**Symptoms:** Wrong fields appear in query

**Possible Causes:**
1. Platform-specific patterns not matching
2. Field names in RAG docs don't match schema

**Solutions:**
```python
# Debug field extraction
parser = create_rag_context_parser("cbc")
parser.field_pattern = re.compile(r'...')  # Custom pattern

# Verify schema field names
schema_fields = schema['process_search_fields'].keys()
extracted_fields = parser.extract_fields(rag_context, intent)
valid_fields = [f for f in extracted_fields if f in schema_fields]
```

## Best Practices

### 1. Always Validate Queries

RAG enhancement can produce complex queries. Always validate:

```python
query, metadata = build_query(..., rag_context=rag_context)

# MANDATORY: Validate before presenting
validation = validate_query(query, metadata)
if not validation['valid']:
    # Fix and retry
```

### 2. Monitor Confidence Scores

Track confidence to improve RAG quality:

```python
if parsed['confidence'] < 0.5:
    # Log for analysis
    logger.info(f"Low RAG confidence: {parsed['confidence']}")
    # Consider improving RAG documents
```

### 3. Use Appropriate Limits

Balance comprehensiveness with performance:

```python
parser.max_fields = 7           # 7 fields usually sufficient
parser.max_values_per_field = 3 # 3 values per field
parser.parsing_timeout = 3.0    # 3 seconds max
```

### 4. Cache Warming

For frequently-used queries, warm the cache:

```python
# Warm cache at startup
common_intents = ["RDP", "SMB", "PowerShell"]
for intent in common_intents:
    parser.parse_context(rag_context, intent)
```

### 5. Graceful Degradation

Always handle RAG failures:

```python
try:
    query = build_query(..., rag_context=rag_context)
except Exception:
    # Fall back to basic query
    query = build_query(...)  # No RAG context
```

## Metrics & Monitoring

### Key Metrics to Track

1. **RAG Enhancement Rate**: % of queries using RAG enhancement
2. **Average Confidence Score**: Quality of RAG context
3. **Cache Hit Rate**: Cache effectiveness
4. **Average Overhead**: Performance impact
5. **Query Comprehensiveness**: Indicators per query (1 → 3-5)

### Example Monitoring

```python
# Track metrics
metrics = {
    "total_queries": 0,
    "rag_enhanced": 0,
    "avg_confidence": [],
    "cache_hits": 0,
    "overhead_ms": [],
}

# Update on each query
if rag_context:
    metrics["total_queries"] += 1
    if parsed['confidence'] > 0.5:
        metrics["rag_enhanced"] += 1
    metrics["avg_confidence"].append(parsed['confidence'])
```

## FAQ

**Q: Is RAG enhancement always beneficial?**

A: No. If RAG context quality is low (confidence < 0.5), the system falls back to basic query building. This ensures we don't add noise.

**Q: Can I disable RAG enhancement?**

A: Yes. Simply don't pass `rag_context` parameter to query builders. The system is fully backward compatible.

**Q: How do I improve RAG context quality?**

A: 
1. Ensure schema documentation is comprehensive
2. Include more example queries in RAG documents
3. Use consistent field naming across documents
4. Provide clear field descriptions and value examples

**Q: What's the performance impact?**

A: Typically < 50ms per query when cached, < 100ms for first parse. Performance tests verify this.

**Q: Can I use custom parsers?**

A: Yes. Extend `RAGContextParser` and override methods as needed. See "Extending the System" section.

## References

- **Implementation Plan**: `docs/RAG_ENHANCED_QUERY_BUILDING.md`
- **RAG Internals**: `docs/RAG_INTERNALS.md`
- **API Reference**: `docs/API_REFERENCE.md`
- **Testing Guide**: `docs/TESTING.md`

---

**Document Version:** 1.0  
**Author:** Cline  
**Status:** Production Ready
