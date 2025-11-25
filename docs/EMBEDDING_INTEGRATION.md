# OpenAI Embedding Integration Guide

## Overview

This document describes the **technical integration** of OpenAI embeddings via LiteLLM proxy for semantic search capabilities in QueryForge.

> **📚 Also See:** [PREBUILT_EMBEDDINGS.md](PREBUILT_EMBEDDINGS.md) for **operational deployment** guide with pre-generated embeddings for faster startup.

## Architecture

### Components

1. **Configuration (`src/src/queryforge/shared/config.py`)**: Manages LiteLLM credentials and settings
2. **Embedding Service (`src/src/queryforge/shared/embeddings.py`)**: Handles embedding generation and similarity calculation
3. **RAG Service (`shared/rag.py`)**: Unified retrieval with semantic search and RapidFuzz fallback

### Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     RAG Initialization                      │
│                                                             │
│  1. Load LiteLLM Config from Environment                    │
│  2. Try to create Embedding Service                         │
│     ├─ Success: Use semantic embeddings                     │
│     └─ Failure: Fall back to RapidFuzz                      │
│  3. Build documents from schemas                            │
│  4. Generate embeddings (if service available)              │
│  5. Cache documents + embeddings                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Query Processing                       │
│                                                             │
│  User Query → Embed Query → Cosine Similarity → Top-K       │
│                    │                                        │
│                    └─ Failure → RapidFuzz Fallback          │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

### Environment Variables

Set these environment variables to enable embeddings:

```bash
# Required
export LITELLM_API_KEY="your-api-key-here"

# Optional (with defaults)
export LITELLM_BASE_URL="https://your-litellm-proxy-url"  # Your LiteLLM proxy URL
export LITELLM_EMBEDDING_MODEL="text-embedding-3-large"  # Model name
```

> **⚡ Fast Deployment:** For production deployments with pre-generated embeddings (< 2 second startup), see [PREBUILT_EMBEDDINGS.md](PREBUILT_EMBEDDINGS.md).

### Docker Compose

The `docker-compose.yml` includes environment variable configuration:

```yaml
environment:
  - LITELLM_API_KEY=${LITELLM_API_KEY:-}
  - LITELLM_BASE_URL=${LITELLM_BASE_URL:-}
  - LITELLM_EMBEDDING_MODEL=${LITELLM_EMBEDDING_MODEL:-text-embedding-3-large}
```

### Development vs Production Setup

#### Development (Runtime Generation)
```bash
# Set your API key
export LITELLM_API_KEY="your-key"

# Start the service (10-120 second startup)
docker-compose up
```

#### Production (Pre-generated Embeddings)
```bash
# Generate embeddings locally first
python -c "from queryforge.server.server import rag_service; rag_service.ensure_index(force=True)"

# Build and deploy with embeddings included (< 2 second startup)
docker-compose build queryforge
docker-compose up -d queryforge
```

> **📖 Full Production Guide:** See [PREBUILT_EMBEDDINGS.md](PREBUILT_EMBEDDINGS.md) for complete instructions.

## Features

### Semantic Search

When embeddings are enabled, the system uses semantic similarity instead of string matching:

**Example:**
- Query: "find suspicious processes"
- Matches documents about: "malicious activity", "threat detection", "process monitoring"
- RapidFuzz would miss these semantic connections

### Automatic Fallback

The system gracefully falls back to RapidFuzz if:
- LiteLLM credentials are missing
- Embedding service is unreachable
- API calls fail during indexing
- API calls fail during search

### Cache Management

**Embeddings are regenerated when:**
1. Schema versions change
2. Embedding model changes
3. Document content changes
4. Cache is manually cleared

**Embeddings are reused when:**
- Schema versions are unchanged
- Cache signature matches
- All embeddings are present

> **📋 Cache Details:** See `.cache/rag_metadata.json` format and management details in [RAG_INTERNALS.md](RAG_INTERNALS.md#caching-strategy).

### Performance

#### Runtime Generation (Development)
- **Indexing**: One-time cost at startup (~2-5 seconds for 1000 documents)
- **Query**: Fast vector comparison (milliseconds)
- **Storage**: 3072-dimensional vectors (~12KB per document)

#### Pre-generated Embeddings (Production)
- **Startup**: < 2 seconds (embeddings pre-cached)
- **Query**: Same performance as runtime generation
- **Storage**: 15-50MB Docker image increase

> **⚡ Performance Details:** See [PREBUILT_EMBEDDINGS.md](PREBUILT_EMBEDDINGS.md#file-sizes) for complete performance comparison.

## Usage Examples

### Basic Query with Embeddings

```python
# The RAG service automatically uses embeddings if available
results = rag_service.search(
    query="network connections from processes",
    k=5,
    source_filter="kql"  # Optional: filter by schema
)

# Results include retrieval method
for result in results:
    print(f"Score: {result['score']:.3f}")
    print(f"Method: {result['retrieval_method']}")  # 'semantic' or 'fuzzy'
    print(f"Text: {result['text'][:100]}...")
```

### Integration in Query Builders

The integration is transparent in the existing query builder tools:

```python
# CBC Query Builder
response = cbc_build_query(
    natural_language_intent="find processes making DNS queries",
    search_type="process_search"
)

# metadata includes rag_context with semantic matches
rag_context = response['metadata'].get('rag_context', [])
```

### Manual Health Check

```python
from queryforge.shared.embeddings import create_embedding_service

service = create_embedding_service()
if service:
    is_healthy, error = service.health_check()
    print(f"Embedding service: {'✓ healthy' if is_healthy else f'✗ {error}'}")
else:
    print("Embedding service not available")
```

## Logging

The system provides clear logging about retrieval method:

```
INFO - Initializing unified RAG service...
INFO - Generating embeddings for 847 documents using model=text-embedding-3-large
INFO - Successfully generated 847 embeddings
INFO - ✓ Unified RAG service initialized with semantic embeddings (model=text-embedding-3-large)
```

Or when falling back:

```
WARNING - LiteLLM API key not found. Falling back to RapidFuzz-based retrieval.
INFO - ✓ Unified RAG service initialized with RapidFuzz fallback
```

## Troubleshooting

### Embeddings Not Being Used

**Check logs for:**
```
WARNING - LiteLLM API key not found. Set LITELLM_API_KEY environment variable.
```

**Solution:**
```bash
export LITELLM_API_KEY="your-key"
# Restart the service
```

### Connection Errors

**Check logs for:**
```
WARNING - Embedding service health check failed: Connection refused
```

**Solution:**
- Verify LiteLLM proxy is running at the configured URL
- Check network connectivity
- Verify the URL in `LITELLM_BASE_URL`

### Model Not Found

**Check logs for:**
```
ERROR - Failed to generate embeddings: Model 'text-embedding-3-large' not found
```

**Solution:**
- Verify the model is configured in your LiteLLM proxy
- Check `LITELLM_EMBEDDING_MODEL` environment variable
- Consult LiteLLM documentation for supported models

### Cache Issues

**To force regeneration of embeddings:**

```python
# Clear the cache
rag_service.clear_cache()

# Force re-indexing
rag_service.ensure_index(force=True)
```

Or delete the cache file:
```bash
rm .cache/rag_metadata.json
# Restart the service
```

> **🔧 More Troubleshooting:** See [PREBUILT_EMBEDDINGS.md](PREBUILT_EMBEDDINGS.md#troubleshooting) for deployment-specific issues and [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for general RAG problems.

## Comparison: Semantic vs Fuzzy Search

### Query: "parent process information"

**Semantic Search Results:**
1. `parent_name` (score: 0.89) - "Name of the parent process"
2. `parent_pid` (score: 0.87) - "Process ID of parent"
3. `parent_cmdline` (score: 0.85) - "Command line of parent process"
4. `process_ancestry` (score: 0.82) - "Chain of parent processes"

**RapidFuzz Results:**
1. `process_info` (score: 72.3) - Contains substring "process"
2. `parent_hash` (score: 65.1) - Contains substring "parent"
3. `information_field` (score: 58.7) - Contains substring "information"

### Query: "malicious activity"

**Semantic Search Results:**
1. "Detection: IOA events" (score: 0.91)
2. "Threat report search" (score: 0.88)
3. "Alert search fields" (score: 0.85)
4. "Suspicious behavior patterns" (score: 0.83)

**RapidFuzz Results:**
- No good matches (low scores, irrelevant results)

## Performance Metrics

### Indexing Performance (Runtime Generation)

| Documents | Embedding Time | Cache Size |
|-----------|----------------|------------|
| 100       | ~0.5s          | ~1.2 MB    |
| 500       | ~2.0s          | ~6.0 MB    |
| 1000      | ~4.0s          | ~12.0 MB   |
| 2000      | ~8.0s          | ~24.0 MB   |

*Note: Times are approximate and depend on network latency to LiteLLM proxy*

### Startup Performance Comparison

| Method | Startup Time | Use Case |
|--------|-------------|----------|
| Runtime Generation | 10-120 seconds | Development, schema changes |
| Pre-generated Embeddings | < 2 seconds | Production, stable schemas |

### Query Performance

Both semantic and fuzzy search have similar query performance:
- Single query: 1-5ms
- Batch (5 queries): 5-20ms

The main difference is **quality** of results, not speed.

> **📊 Detailed Benchmarks:** See [PREBUILT_EMBEDDINGS.md](PREBUILT_EMBEDDINGS.md#benefits-summary) for comprehensive performance comparison.

## API Reference

### EmbeddingService

```python
class EmbeddingService:
    def __init__(self, config: LiteLLMConfig)
    def generate_embeddings(self, texts: List[str], show_progress: bool = False) -> List[List[float]]
    def embed_query(self, query: str) -> List[float]
    def health_check(self) -> Tuple[bool, Optional[str]]
```

### UnifiedRAGService

```python
class UnifiedRAGService:
    def ensure_index(self, force: bool = False) -> None
    def search(self, query: str, k: int = 5, source_filter: Optional[str] = None) -> List[Dict[str, Any]]
    def clear_cache(self) -> None
```

### Helper Functions

```python
def cosine_similarity(vec1: List[float], vec2: List[float]) -> float
def create_embedding_service(config: Optional[LiteLLMConfig] = None) -> Optional[EmbeddingService]
```

## Related Documentation

### User Guides
- **[PREBUILT_EMBEDDINGS.md](PREBUILT_EMBEDDINGS.md)** - Production deployment with pre-generated embeddings
- **[RAG_ENHANCEMENT_GUIDE.md](RAG_ENHANCEMENT_GUIDE.md)** - Complete RAG feature guide for developers

### Technical References
- **[RAG_INTERNALS.md](RAG_INTERNALS.md)** - Deep technical dive into RAG system architecture
- **[API_REFERENCE.md](API_REFERENCE.md)** - Complete MCP tool documentation
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Common issues and solutions

### System Documentation
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Overall system architecture
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - General deployment guide

## Future Enhancements

Potential improvements for future versions:

1. **Hybrid Search**: Combine semantic and fuzzy scores
2. **Reranking**: Use a separate reranking model for better precision
3. **Caching**: Cache query embeddings for common queries
4. **Metrics**: Track retrieval quality and performance
5. **Fine-tuning**: Fine-tune embeddings on domain-specific data

## Contributing

When modifying the embedding integration:

1. Maintain backward compatibility with RapidFuzz fallback
2. Add appropriate logging for debugging
3. Update this documentation and [PREBUILT_EMBEDDINGS.md](PREBUILT_EMBEDDINGS.md) if deployment changes
4. Test both embedding and fallback paths
5. Consider cache invalidation logic

---

**Last Updated:** 2025-11-25  
**Version:** 2.0 - Added cross-references and deployment guidance
