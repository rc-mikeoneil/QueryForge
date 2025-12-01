# RAG Internals Documentation

Deep dive into the Retrieval-Augmented Generation (RAG) system used in the MCP Security Query Builders.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Document Processing](#document-processing)
- [Search Algorithm](#search-algorithm)
- [Caching Strategy](#caching-strategy)
- [Performance Optimization](#performance-optimization)

## Overview

The RAG service provides fuzzy text search across platform schemas, documentation, and example queries to enhance natural language query building.

### Key Features

- **Unified Search**: Single search interface across all platforms
- **Rapidfuzz-based**: Fast fuzzy string matching without ML dependencies
- **Persistent Cache**: Pre-computed document metadata
- **Source Filtering**: Platform-specific search capability
- **Version Tracking**: Automatic cache invalidation on schema updates

### Why RAG?

When users provide natural language intent, the RAG service:
1. Finds relevant schema documentation
2. Retrieves similar example queries
3. Provides context to improve query accuracy
4. Reduces hallucination in query building

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────┐
│                  UnifiedRAGService                      │
│                                                         │
│  ┌────────────────────────────────────────────────┐     │
│  │          Document Store                        │     │
│  │  - Platform schemas                            │     │
│  │  - Field definitions                           │     │
│  │  - Example queries                             │     │
│  │  - Best practices                              │     │
│  └────────────┬───────────────────────────────────┘     │
│               │                                         │
│  ┌────────────▼───────────────────────────────────┐     │
│  │        Rapidfuzz Search Engine                 │     │
│  │  - Fuzzy string matching                       │     │
│  │  - Score calculation                           │     │
│  │  - Result ranking                              │     │
│  └────────────┬───────────────────────────────────┘     │
│               │                                         │
│  ┌────────────▼───────────────────────────────────┐     │
│  │          Cache Layer                           │     │
│  │  - Persistent storage (JSON)                   │     │
│  │  - Version tracking                            │     │
│  │  - Auto-invalidation                           │     │
│  └────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────┘
```

### Class Structure

```python
class UnifiedRAGService:
    def __init__(self, sources: List[SchemaSource], cache_dir: Path):
        """Initialize with multiple platform sources."""
        self.sources = sources
        self._documents = []  # Unified document store
        self.cache_dir = cache_dir

    def ensure_index(self):
        """Build or load document index."""
        pass

    def search(self, query: str, k: int, source_filter: str):
        """Search documents and return top-k results."""
        pass

    def _load_cached_index(self):
        """Load cached documents from disk."""
        pass

    def clear_cache(self):
        """Remove cached documents."""
        pass
```

### SchemaSource Structure

```python
@dataclass
class SchemaSource:
    name: str                           # Platform identifier (kql, cbc, etc.)
    schema_cache: Any                   # Platform schema cache instance
    loader: Callable                    # Function to load schema
    document_builder: Callable          # Function to build RAG documents
    version_getter: Optional[Callable]  # Function to get schema version
```

## Document Processing

### Document Types

Each platform contributes different document types:

1. **Table/Dataset Descriptions**
   ```python
   "Table: DeviceProcessEvents\n"
   "Description: Process execution events from endpoint agents\n"
   "Columns: Timestamp, DeviceName, FileName, ProcessCommandLine, ..."
   ```

2. **Field Definitions**
   ```python
   "Field: ProcessCommandLine\n"
   "Type: string\n"
   "Description: Command line used to run the process\n"
   "Example: powershell.exe -encodedcommand ..."
   ```

3. **Example Queries**
   ```python
   "Example: PowerShell with encoded command\n"
   "Query: process_name:powershell.exe AND cmdline:-encodedcommand\n"
   "Description: Finds suspicious PowerShell executions"
   ```

4. **Best Practices**
   ```python
   "Best Practice: Performance\n"
   "Use specific field values instead of wildcards\n"
   "Good: process_name:cmd.exe\n"
   "Bad: process_name:*.exe"
   ```

### Document Building Process

#### KQL Documents

```python
def build_kql_documents(schema: Dict[str, Any]) -> List[Dict[str, Any]]:
    documents = []

    # Table descriptions
    for table_name, table_info in schema.items():
        doc = f"Table: {table_name}\n"
        doc += f"Description: {table_info.get('description', '')}\n"

        # Add column info
        columns = table_info.get('columns', [])
        doc += f"Columns: {', '.join(c['name'] for c in columns)}\n"

        # Add detailed column info
        for col in columns:
            doc += f"  - {col['name']} ({col['type']}): {col.get('description', '')}\n"

        documents.append({
            "id": f"kql:{table_name}",
            "text": doc,
            "metadata": {"table": table_name}
        })

    return documents
```

#### CBC Documents

```python
def build_cbc_documents(schema: Dict[str, Any]) -> List[Dict[str, Any]]:
    documents = []

    # Search type descriptions
    for search_type, info in schema.get("search_types", {}).items():
        doc = f"Carbon Black Search Type: {search_type}\n"
        doc += f"Description: {info.get('description', '')}\n"

        # Add field info
        fields = info.get("fields", [])
        doc += f"Available Fields:\n"
        for field in fields:
            doc += f"  - {field['name']}: {field.get('description', '')}\n"

        documents.append({
            "id": f"cbc:{search_type}",
            "text": doc,
            "metadata": {"search_type": search_type}
        })

    return documents
```

#### Cortex Documents

```python
def build_cortex_documents(schema: Dict[str, Any]) -> List[Dict[str, Any]]:
    documents = []

    # Dataset descriptions
    for dataset_name, dataset_info in schema.get("datasets", {}).items():
        doc = f"Cortex XDR Dataset: {dataset_name}\n"
        doc += f"Description: {dataset_info.get('description', '')}\n"

        # Fields
        fields = dataset_info.get("fields", [])
        doc += f"Fields ({len(fields)}):\n"
        for field in fields[:20]:  # Limit for document size
            doc += f"  - {field['name']} ({field['type']})\n"

        documents.append({
            "id": f"cortex:{dataset_name}",
            "text": doc,
            "metadata": {"dataset": dataset_name}
        })

    return documents
```

#### S1 Documents

```python
def build_s1_documents(schema: Dict[str, Any]) -> List[Dict[str, Any]]:
    documents = []

    # Dataset descriptions
    for dataset_key, dataset_info in schema.get("datasets", {}).items():
        doc = f"SentinelOne Dataset: {dataset_info.get('name', dataset_key)}\n"

        metadata = dataset_info.get("metadata", {})
        if "description" in metadata:
            doc += f"Description: {metadata['description']}\n"

        # Fields
        fields = dataset_info.get("fields", [])
        doc += f"Key Fields:\n"
        for field in fields[:15]:
            doc += f"  - {field['name']}: {field.get('description', '')}\n"

        documents.append({
            "id": f"s1:{dataset_key}",
            "text": doc,
            "metadata": {"dataset": dataset_key}
        })

    return documents
```

### Document Indexing

The indexing process:

1. **Collect documents from all sources**
2. **Normalize text** (lowercase, strip whitespace)
3. **Create metadata** (source platform, document type)
4. **Cache to disk** (JSON format)

```python
def ensure_index(self, force: bool = False):
    """Build unified document index."""
    documents = []
    versions = {}

    for source in self.sources:
        try:
            # Load schema
            schema = source.load_schema(force=force)
            versions[source.name] = source.version()

            # Build documents
            docs = source.document_builder(schema)

            # Add with metadata
            for doc in docs:
                doc["source"] = source.name
                documents.append(doc)

        except Exception as e:
            logger.warning(f"Failed to build docs for {source.name}: {e}")

    self._documents = documents
    self._source_versions = versions
    
    logger.info(f"Built RAG index with {len(documents)} documents")

    # Save to cache
    self._save_cache()
```

## Search Algorithm

### Rapidfuzz-Based Search

The service uses Rapidfuzz for fast fuzzy string matching.

#### Search Process

```python
def search(
    self,
    query: str,
    k: int = 5,
    source_filter: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Search for relevant documents.

    Args:
        query: Search query string
        k: Number of results to return
        source_filter: Optional platform filter (kql, cbc, cortex, s1)

    Returns:
        List of matching documents with scores
    """
    # Ensure index is loaded
    self.ensure_index()
    
    # Filter documents by source if specified
    candidates = [
        doc for doc in self._documents
        if not source_filter or doc.get("source") == source_filter
    ]

    if not candidates:
        return []

    top_k = min(k, len(candidates))
    if top_k == 0:
        return []

    # Extract text for searching
    choices = [doc["text"] for doc in candidates]

    # Perform fuzzy search
    from rapidfuzz import process

    results = process.extract(
        query,
        choices,
        limit=top_k
    )

    # Format results
    matches = []
    for text, score, idx in results:
        doc = candidates[idx]
        matches.append({
            "source": doc.get("source"),
            "id": doc.get("id"),
            "text": doc.get("text"),
            "metadata": doc.get("metadata", {}),
            "score": float(score),
        })

    return matches
```

#### Scoring Methods

Rapidfuzz provides multiple scoring algorithms. The default scorer provides:

- **Partial string matching**: Finds best partial match within documents
- **Normalized scores**: Returns scores from 0-100
- **Fast performance**: Optimized C++ implementation

Example matches:
- Query: "process name" matches "Field: ProcessCommandLine" (partial match)
- Query: "powershell" matches documents containing "PowerShell" (case-insensitive)
- Query: "network connection" matches "network" and "connection" terms

### Search Optimization

**1. Pre-filtering**:
```python
# Filter by source before fuzzy matching
if source_filter:
    candidates = [d for d in docs if d["source"] == source_filter]
```

**2. Limit document size**:
```python
# Truncate long documents for faster matching
MAX_DOC_LENGTH = 1000
text = doc["text"][:MAX_DOC_LENGTH]
```

**3. Cache results**:
```python
from functools import lru_cache

@lru_cache(maxsize=100)
def cached_search(query: str, source: str, k: int):
    return self._search_impl(query, source, k)
```

## Caching Strategy

### Cache Structure

```
.cache/
├── rag_metadata.json       # All documents with metadata and versions
```

### Cache Lifecycle

```python
def ensure_index(self):
    """Ensure RAG index is ready."""
    # Check if cache exists and is valid
    if self._is_cache_valid():
        self._load_cached_index()
        logger.info("Loaded RAG index from cache")
    else:
        self._build_index()
        logger.info("Built new RAG index")
```

### Cache Validation

```python
def _is_cache_valid(self) -> bool:
    """Check if cached index is still valid."""
    if not self._metadata_path.exists():
        return False

    # Load cached metadata
    try:
        with self._metadata_path.open("r") as f:
            metadata = json.load(f)
    except Exception:
        return False

    # Check version for each source
    cached_versions = metadata.get("source_versions", {})
    for source in self.sources:
        current_version = source.version()
        cached_version = cached_versions.get(source.name)

        if current_version != cached_version:
            logger.info(
                f"Schema version changed for {source.name}: "
                f"{cached_version} -> {current_version}"
            )
            return False

    return True
```

### Cache Loading

```python
def _load_cached_index(self, signature: str) -> bool:
    """Load cached documents."""
    if not self._metadata_path.exists():
        return False

    try:
        with self._metadata_path.open("r", encoding="utf-8") as f:
            metadata = json.load(f)

        if metadata.get("signature") != signature:
            return False

        self._documents = metadata.get("documents", [])
        self._source_versions = metadata.get("source_versions", {})
        
        logger.info(f"Loaded {len(self._documents)} documents from cache")
        return True

    except Exception as e:
        logger.warning(f"Failed to load cache: {e}")
        return False
```

### Cache Saving

```python
def _save_cache(self):
    """Save documents to cache."""
    try:
        with self._metadata_path.open("w", encoding="utf-8") as f:
            json.dump(
                {
                    "signature": self._documents_signature(self._documents),
                    "documents": self._documents,
                    "source_versions": self._source_versions,
                },
                f,
                ensure_ascii=False,
                indent=2
            )

        logger.info("Saved RAG index to cache")

    except Exception as e:
        logger.error(f"Failed to save cache: {e}")
```

### Force Refresh

```python
def refresh(self, force: bool = True):
    """Force rebuild of RAG index."""
    if force:
        # Delete cache
        if self._metadata_path.exists():
            self._metadata_path.unlink()

        # Rebuild
        self.ensure_index(force=True)
```

## Performance Optimization

### Startup Performance

**Cold Start** (no cache):
- Document building: 500-1000ms
- Indexing: 50-100ms
- Total: ~0.5-1 second

**Warm Start** (cached):
- Cache loading: 50-100ms
- Total: ~100ms

### Optimization Techniques

#### 1. Lazy Loading

```python
class UnifiedRAGService:
    def __init__(self, sources, cache_dir):
        self.sources = sources
        self.cache_dir = cache_dir
        self._index_initialized = False

    def search(self, query, k, source_filter):
        # Build index on first search, not at init
        if not self._index_initialized:
            self.ensure_index()
            self._index_initialized = True

        return self._search_impl(query, k, source_filter)
```

#### 2. Document Chunking

```python
def build_documents(schema):
    """Build documents with size limits."""
    documents = []

    for table in schema:
        # Chunk large documents
        doc = build_table_doc(table)

        if len(doc) > MAX_DOC_SIZE:
            # Split into chunks
            chunks = chunk_document(doc, MAX_DOC_SIZE)
            documents.extend(chunks)
        else:
            documents.append(doc)

    return documents
```

#### 3. Parallel Document Building

```python
from concurrent.futures import ThreadPoolExecutor

def _build_index_parallel(self):
    """Build index using parallel document building."""
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = []

        for source in self.sources:
            future = executor.submit(
                self._build_source_documents,
                source
            )
            futures.append(future)

        # Collect results
        for future in futures:
            docs = future.result()
            self._documents.extend(docs)
```

#### 4. Result Caching

```python
from functools import lru_cache

class UnifiedRAGService:
    @lru_cache(maxsize=100)
    def search(self, query: str, k: int, source_filter: Optional[str]):
        """Cached search for frequently used queries."""
        # Note: Only works if all parameters are hashable
        return self._search_impl(query, k, source_filter)
```

### Memory Optimization

#### 1. Document Compression

```python
import gzip
import json

def _save_cache_compressed(self):
    """Save cache with compression."""
    cache_file = self.cache_dir / "rag_metadata.json.gz"

    with gzip.open(cache_file, "wt", encoding="utf-8") as f:
        json.dump(
            {
                "documents": self._documents,
                "source_versions": self._source_versions,
            },
            f
        )
```

#### 2. Sparse Document Storage

```python
# Store only essential fields
document = {
    "id": doc_id,
    "source": source,
    "text": text,
    "metadata": minimal_metadata,
}
```

#### 3. On-Demand Loading

```python
class LazyDocumentStore:
    def __init__(self, cache_dir):
        self.cache_dir = cache_dir
        self._loaded = {}

    def get_documents(self, source: str):
        if source not in self._loaded:
            self._loaded[source] = self._load_source(source)
        return self._loaded[source]
```

## Monitoring and Debugging

### Logging Search Queries

```python
def search(self, query, k, source_filter):
    logger.debug(
        f"RAG search: query='{query}' k={k} filter={source_filter}"
    )

    results = self._search_impl(query, k, source_filter)

    logger.debug(
        f"RAG results: {len(results)} matches, "
        f"top score: {results[0]['score'] if results else 0}"
    )

    return results
```

### Performance Metrics

```python
import time

def search(self, query, k, source_filter):
    start = time.time()
    results = self._search_impl(query, k, source_filter)
    elapsed = time.time() - start

    logger.info(
        f"RAG search completed in {elapsed*1000:.2f}ms "
        f"({len(results)} results)"
    )

    return results
```

### Cache Statistics

```python
def get_stats(self) -> Dict[str, Any]:
    """Get RAG service statistics."""
    return {
        "total_documents": len(self._documents),
        "sources": {
            source.name: len([
                d for d in self._documents
                if d["source"] == source.name
            ])
            for source in self.sources
        },
        "cache_valid": self._is_cache_valid(),
        "cache_size_mb": self._get_cache_size_mb(),
    }
```

---

This document provides a comprehensive understanding of the RAG internals. For usage examples, see the [API Reference](../API_REFERENCE.md).
