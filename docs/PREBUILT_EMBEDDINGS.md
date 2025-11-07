# Pre-Generated Embeddings Guide

This document explains how to use pre-generated embeddings to achieve instant MCP server startup (< 2 seconds) instead of waiting 10-120 seconds for runtime initialization.

## Overview

By generating embeddings ahead of time and including them in the Docker image, the server can:
- Start in 1-2 seconds instead of 10-120 seconds
- Work without dependency on LiteLLM proxy at runtime
- Provide consistent, predictable startup times
- Reduce operational costs (no embedding generation at runtime)

## Prerequisites

- Access to your LiteLLM proxy for initial embedding generation
- Local development environment with Python 3.12+

## Step 1: Generate Embeddings Locally

### Set Environment Variables
```bash
export LITELLM_API_KEY="your-api-key-here"
export LITELLM_BASE_URL="https://your-litellm-proxy-url"
export LITELLM_EMBEDDING_MODEL="text-embedding-3-large"
```

### Navigate to Project Directory
```bash
cd queryforge
```

### Generate Embeddings
```bash
python -c "
from server import rag_service
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
print('🔄 Generating embeddings for all schemas...')
rag_service.ensure_index(force=True, timeout=300.0)
print('✅ Done! Cache saved to .cache/rag_metadata.json')
"
```

Expected output:
```
2025-10-31 00:45:00 - INFO - 🔄 Starting RAG index initialization (timeout=300s)...
2025-10-31 00:45:00 - INFO - 🔄 Creating embedding service...
2025-10-31 00:45:01 - INFO - ✅ Embedding service created with model=text-embedding-3-large
2025-10-31 00:45:01 - INFO - 🔄 Loading schemas from 4 sources...
2025-10-31 00:45:02 - INFO - ✅ Loaded 1234 documents from source 'cbc'
2025-10-31 00:45:02 - INFO - ✅ Loaded 856 documents from source 'kql'
2025-10-31 00:45:03 - INFO - ✅ Loaded 2145 documents from source 'cortex'
2025-10-31 00:45:03 - INFO - ✅ Loaded 999 documents from source 's1'
2025-10-31 00:45:04 - INFO - 🔄 Generating embeddings for 5234 documents using model=text-embedding-3-large (296s remaining)...
2025-10-31 00:45:07 - INFO - ✅ Batch 1/3 completed in 2.8s
2025-10-31 00:45:10 - INFO - ✅ Batch 2/3 completed in 2.9s
2025-10-31 00:45:13 - INFO - ✅ Batch 3/3 completed in 2.7s
2025-10-31 00:45:13 - INFO - ✅ Successfully generated 5234 embeddings
2025-10-31 00:45:13 - INFO - ✅ Persisted retrieval cache to .cache
2025-10-31 00:45:13 - INFO - ✅ RAG index initialization complete (13.2s)
✅ Done! Cache saved to .cache/rag_metadata.json
```

### Verify Cache Generated
```bash
ls -lh .cache/rag_metadata.json
# Should show file several MB in size

# Optional: Inspect cache contents
python -c "
import json
with open('.cache/rag_metadata.json') as f:
    data = json.load(f)
    print(f'📊 Documents: {len(data.get(\"documents\", []))}')
    print(f'🤖 Model: {data.get(\"embedding_model\")}')
    has_embeddings = all('embedding' in doc for doc in data.get('documents', []))
    print(f'✅ Has embeddings: {has_embeddings}')
    if has_embeddings:
        print('🎉 Cache is ready for use!')
"
```

## Step 2: Rebuild Docker Image

The Dockerfile has been updated to automatically include the `.cache` directory. Simply rebuild:

```bash
# Rebuild the image with pre-generated embeddings
docker-compose build unified-mcp

# Deploy the updated container
docker-compose up -d unified-mcp
```

## Step 3: Verify Instant Startup

Check the logs to confirm fast startup:

```bash
docker logs -f unified-query-builder
```

Expected logs with pre-generated embeddings:
```
2025-10-31 00:46:00,123 - root - INFO - 🚀 Starting unified query builder MCP server
2025-10-31 00:46:00,124 - root - INFO - 🔄 RAG initialization started in background thread
2025-10-31 00:46:00,125 - root - INFO - 🌐 Running MCP server on http://0.0.0.0:8080/sse
2025-10-31 00:46:00,456 - root - INFO - 🚀 Starting background RAG initialization...
2025-10-31 00:46:00,457 - root - INFO - 🔍 Verifying schema files...
2025-10-31 00:46:00,458 - root - INFO - ✅ CBC schema found
2025-10-31 00:46:00,459 - root - INFO - ✅ Cortex schema found
2025-10-31 00:46:00,460 - root - INFO - ✅ KQL schema found
2025-10-31 00:46:00,461 - root - INFO - ✅ S1 schema found
2025-10-31 00:46:00,462 - root - INFO - ✅ Cache directory ready: /app/.cache
2025-10-31 00:46:00,789 - root - INFO - ✅ Reusing cached embeddings for 5234 documents (0.32s)
2025-10-31 00:46:00,790 - root - INFO - ✅ RAG service initialized with semantic embeddings (model=text-embedding-3-large) in 0.89s
```

Notice the total time: **< 1 second** vs 10-120 seconds!

## Maintenance

### When to Regenerate Embeddings

Regenerate embeddings when:
- ✅ Schema files are updated (new fields, operators, examples)
- ✅ You switch embedding models (e.g., different model in `LITELLM_EMBEDDING_MODEL`)
- ✅ You update LiteLLM configuration
- ❌ **NOT needed** for code changes that don't affect schemas

### Updating Embeddings

1. **Pull latest schema updates**:
```bash
git pull origin main
```

2. **Regenerate embeddings** (repeat Step 1 above)

3. **Rebuild and deploy**:
```bash
docker-compose build unified-mcp
docker-compose up -d unified-mcp
```

### Fallback Behavior

If the pre-generated cache becomes corrupted or incompatible:
- Server will still start successfully
- RAG will initialize at runtime (slower but functional)
- Or fall back to RapidFuzz-based retrieval
- Check logs for warnings about cache issues

## File Sizes

Typical cache file sizes:
- **`rag_metadata.json`**: 15-50 MB (includes embeddings)
- **Docker image increase**: +15-50 MB
- **Memory usage**: +100-200 MB at runtime

These are small costs for eliminating 10-120 second startup delays.

## Troubleshooting

### Cache Not Found
```
⚠️ No documents available for RAG indexing.
```
**Solution**: Ensure `.cache/rag_metadata.json` exists and was copied into image.

### Cache Corruption
```
⚠️ Failed to read RAG metadata cache: Invalid JSON
```
**Solution**: Regenerate embeddings from Step 1.

### Embedding Model Mismatch
```
ℹ️ Cached embeddings are out of date; rebuilding.
```
**Solution**: This is normal if you changed `LITELLM_EMBEDDING_MODEL`. Wait for rebuild or regenerate cache.

### LiteLLM Unreachable During Generation
```
❌ Health check failed after 5.01s: Connection timeout
```
**Solution**: Check your `LITELLM_BASE_URL` and network connectivity.

## Benefits Summary

✅ **Instant startup**: < 2 seconds vs 10-120 seconds  
✅ **No runtime dependencies**: Works without LiteLLM proxy  
✅ **Predictable performance**: Consistent initialization time  
✅ **Cost effective**: No runtime embedding generation costs  
✅ **Offline capable**: Can run without external API access  
✅ **Production ready**: Eliminates startup timeout issues  

🎉 **Perfect for production deployments with infrequent schema changes!**
