"""Unified retrieval service shared across CBC and KQL schemas."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

try:  # pragma: no cover - optional dependency
    from rapidfuzz import process as rapidfuzz_process
except ImportError:  # pragma: no cover - handled at runtime
    rapidfuzz_process = None  # type: ignore[assignment]

from .config import LiteLLMConfig
from .embeddings import EmbeddingService, cosine_similarity, create_embedding_service

logger = logging.getLogger(__name__)

# Security constants
MAX_CACHE_SIZE_BYTES = 100 * 1024 * 1024  # 100MB limit for cache files


from typing import Union

LoaderFn = Callable[[Any, bool], Dict[str, Any]]
VersionFn = Callable[[Any], Optional[Union[str, int]]]
DocumentBuilder = Callable[[Dict[str, Any]], Sequence[Dict[str, Any]]]


@dataclass
class SchemaSource:
    """Description of a schema source the RAG service should index."""

    name: str
    schema_cache: Any
    loader: LoaderFn
    document_builder: DocumentBuilder
    version_getter: Optional[VersionFn] = None

    def load_schema(self, force: bool = False) -> Dict[str, Any]:
        return self.loader(self.schema_cache, force)

    def version(self) -> Optional[Union[str, int]]:
        if self.version_getter is None:
            return None
        return self.version_getter(self.schema_cache)


@dataclass
class UnifiedRAGService:
    """Build and reuse embeddings for multiple schema sources."""

    sources: Sequence[SchemaSource]
    cache_dir: Path = field(default_factory=lambda: Path(".cache"))

    def __post_init__(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._documents: List[Dict[str, Any]] = []
        self._metadata_path = self.cache_dir / "rag_metadata.json"
        self._source_versions: Dict[str, Optional[Union[str, int]]] = {}
        self._embedding_service: Optional[EmbeddingService] = None
        self._embedding_model: Optional[str] = None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _documents_signature(self, documents: Sequence[Dict[str, Any]], model: Optional[str] = None) -> str:
        payload = json.dumps(
            [
                {
                    "id": doc.get("id"),
                    "source": doc.get("source"),
                    "text": doc.get("text"),
                }
                for doc in documents
            ],
            sort_keys=True,
        ).encode("utf-8")
        # Include model in signature so cache invalidates when model changes
        if model:
            payload += f"|model:{model}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _load_cached_index(self, signature: str) -> bool:
        """
        Load cached RAG index from disk with security validations.

        Includes security measures:
        - File size limits to prevent DoS via large cache files
        - Signature verification to detect tampering
        """
        if not self._metadata_path.exists():
            return False

        try:
            # Security: Check file size BEFORE reading to prevent memory exhaustion
            file_size = self._metadata_path.stat().st_size
            if file_size > MAX_CACHE_SIZE_BYTES:
                logger.error(
                    "RAG cache file %s exceeds maximum size limit (%d bytes > %d bytes). "
                    "Refusing to load potentially malicious cache.",
                    self._metadata_path,
                    file_size,
                    MAX_CACHE_SIZE_BYTES
                )
                return False

            with self._metadata_path.open("r", encoding="utf-8") as handle:
                metadata = json.load(handle)

        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse RAG metadata cache JSON: %s", exc)
            return False
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to read RAG metadata cache: %s", exc)
            return False

        # Verify signature to detect tampering
        cached_signature = metadata.get("signature")
        if cached_signature != signature:
            logger.info(
                "Cached embeddings signature mismatch. Expected: %s..., Got: %s... Rebuilding.",
                signature[:16] if signature else "None",
                cached_signature[:16] if cached_signature else "None"
            )
            return False

        # Validate structure
        documents = metadata.get("documents", [])
        if not isinstance(documents, list):
            logger.warning("Invalid cache structure: 'documents' must be a list")
            return False

        self._documents = documents
        self._source_versions = metadata.get("source_versions", {})
        self._embedding_model = metadata.get("embedding_model")

        logger.info(
            "Loaded retrieval metadata for %d documents (model=%s).",
            len(self._documents),
            self._embedding_model or "rapidfuzz",
        )
        return True

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def ensure_index(self, force: bool = False, timeout: float = 120.0) -> None:
        """Ensure the embedding index is built for all registered sources.
        
        Parameters
        ----------
        force:
            If True, rebuild index from scratch even if cache exists.
        timeout:
            Maximum time in seconds to spend on initialization (default: 120s).
            If exceeded, falls back to RapidFuzz.
        """
        import time
        start_time = time.time()
        
        logger.info("🔄 Starting RAG index initialization (timeout=%.0fs)...", timeout)

        # First, try to load from cache without triggering schema loading
        if not force and self._metadata_path.exists():
            try:
                # Security: Check file size BEFORE reading to prevent memory exhaustion
                file_size = self._metadata_path.stat().st_size
                if file_size > MAX_CACHE_SIZE_BYTES:
                    logger.error(
                        "⚠️ RAG cache file %s exceeds maximum size limit (%d bytes > %d bytes). "
                        "Rebuilding from source.",
                        self._metadata_path,
                        file_size,
                        MAX_CACHE_SIZE_BYTES
                    )
                else:
                    logger.info("📂 Loading cache from %s", self._metadata_path)
                    with self._metadata_path.open("r", encoding="utf-8") as handle:
                        metadata = json.load(handle)

                    cached_docs = metadata.get("documents", [])
                    cached_model = metadata.get("embedding_model")
                    cached_signature = metadata.get("signature")

                    # Validate structure
                    if not isinstance(cached_docs, list):
                        logger.warning("⚠️ Invalid cache structure: 'documents' must be a list. Rebuilding.")
                    else:
                        logger.info("📊 Cache contains %d documents, model=%s", len(cached_docs), cached_model or "None")

                        # Check if cache has valid embeddings
                        if cached_docs and all("embedding" in doc for doc in cached_docs):
                            self._documents = cached_docs
                            self._source_versions = metadata.get("source_versions", {})
                            self._embedding_model = cached_model
                            elapsed = time.time() - start_time
                            logger.info(
                                "✅ Reusing cached embeddings for %d documents (model=%s, %.2fs)",
                                len(self._documents),
                                cached_model or "rapidfuzz",
                                elapsed
                            )
                            return
                        else:
                            missing = sum(1 for doc in cached_docs if "embedding" not in doc)
                            logger.info(
                                "⚠️ Cache exists but missing embeddings (%d/%d docs), will regenerate",
                                missing,
                                len(cached_docs)
                            )
            except json.JSONDecodeError as exc:
                logger.warning("⚠️ Failed to parse cache JSON: %s, will rebuild", exc)
            except Exception as exc:
                logger.warning("⚠️ Failed to read cache: %s, will rebuild", exc)

        # Cache is invalid or missing, need to build from scratch
        # Only NOW initialize embedding service if needed
        if self._embedding_service is None:
            logger.info("🔄 Creating embedding service...")
            try:
                self._embedding_service = create_embedding_service()
                if self._embedding_service:
                    self._embedding_model = self._embedding_service.config.model
                    logger.info("✅ Embedding service created with model=%s", self._embedding_model)
                else:
                    logger.warning("⚠️ Embedding service not available, will use RapidFuzz")
            except Exception as exc:
                logger.warning("⚠️ Failed to create embedding service: %s", exc)

        documents: List[Dict[str, Any]] = []
        versions: Dict[str, Optional[Union[str, int]]] = {}

        logger.info("🔄 Loading schemas from %d sources...", len(self.sources))
        for source in self.sources:
            try:
                schema = source.load_schema(force=force)
                versions[source.name] = source.version()
                doc_count = 0
                for raw_doc in source.document_builder(schema):
                    if "text" not in raw_doc:
                        continue
                    doc = dict(raw_doc)
                    doc.setdefault("id", f"{source.name}:{len(documents)}")
                    doc["source"] = source.name
                    documents.append(doc)
                    doc_count += 1
                logger.info("✅ Loaded %d documents from source '%s'", doc_count, source.name)
            except Exception as exc:
                logger.error("❌ Failed to load source '%s': %s", source.name, exc)

        if not documents:
            logger.warning("⚠️ No documents available for RAG indexing.")
            self._documents = []
            self._source_versions = versions
            return

        signature = self._documents_signature(documents, self._embedding_model)

        # Check if we can reuse cached index after loading documents
        if (
            not force
            and self._source_versions == versions
            and self._load_cached_index(signature)
        ):
            # Verify embeddings are present
            has_embeddings = all("embedding" in doc for doc in self._documents)
            if has_embeddings:
                elapsed = time.time() - start_time
                logger.info("✅ Reusing cached embeddings for %d documents (%.2fs)", len(self._documents), elapsed)
                return
            else:
                logger.info("⚠️ Cache missing embeddings, regenerating")

        # Generate embeddings if service is available
        if self._embedding_service:
            try:
                elapsed = time.time() - start_time
                remaining = timeout - elapsed
                
                if remaining <= 0:
                    logger.warning(
                        "⚠️ Timeout exceeded before embedding generation (%.2fs elapsed). Using RapidFuzz.",
                        elapsed
                    )
                    self._embedding_service = None
                    self._embedding_model = None
                else:
                    logger.info(
                        "🔄 Generating embeddings for %d documents using model=%s (%.0fs remaining)...",
                        len(documents),
                        self._embedding_model,
                        remaining,
                    )
                    texts = [doc["text"] for doc in documents]
                    embeddings = self._embedding_service.generate_embeddings(
                        texts, show_progress=len(texts) > 100
                    )

                    # Attach embeddings to documents
                    for doc, embedding in zip(documents, embeddings):
                        doc["embedding"] = embedding

                    logger.info("✅ Successfully generated %d embeddings", len(embeddings))

            except Exception as exc:
                elapsed = time.time() - start_time
                logger.warning(
                    "⚠️ Failed to generate embeddings after %.2fs: %s. Falling back to RapidFuzz.",
                    elapsed,
                    exc,
                )
                self._embedding_service = None
                self._embedding_model = None
                # Remove any partial embeddings
                for doc in documents:
                    doc.pop("embedding", None)

        # Ensure RapidFuzz is available as fallback
        if self._embedding_service is None and rapidfuzz_process is None:
            raise RuntimeError(
                "Neither embeddings nor rapidfuzz are available. "
                "Install rapidfuzz with: pip install rapidfuzz"
            )

        if self._embedding_service is None:
            logger.info(
                "ℹ️ Using rapidfuzz-based retrieval for %d documents.",
                len(documents),
            )

        self._documents = documents
        self._source_versions = versions

        # Save to cache
        try:
            with self._metadata_path.open("w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "signature": signature,
                        "documents": documents,
                        "source_versions": versions,
                        "embedding_model": self._embedding_model,
                    },
                    handle,
                    ensure_ascii=False,
                    indent=2,
                )
            logger.info("✅ Persisted retrieval cache to %s", self.cache_dir)
        except Exception as exc:
            logger.warning("⚠️ Failed to persist cache: %s", exc)

        total_duration = time.time() - start_time
        logger.info("✅ RAG index initialization complete (%.2fs)", total_duration)

    def search(self, query: str, k: int = 5, source_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return the top-k documents matching the query.

        Parameters
        ----------
        query:
            Free-form natural language query.
        k:
            Number of results to return (defaults to 5, capped at available documents).
        source_filter:
            Optional name of a registered schema source to filter results (e.g. "cbc" or "kql").
        """

        if not query or not query.strip():
            raise ValueError("Query must be a non-empty string")

        self.ensure_index()

        candidates = [doc for doc in self._documents if not source_filter or doc.get("source") == source_filter]
        if not candidates:
            return []

        top_k = min(k, len(candidates))
        if top_k == 0:
            return []

        # Try semantic search with embeddings first
        if self._embedding_service and all("embedding" in doc for doc in candidates):
            try:
                return self._semantic_search(query, candidates, top_k)
            except Exception as exc:
                logger.warning(
                    "Semantic search failed: %s. Falling back to RapidFuzz.",
                    exc,
                )
                # Fall through to RapidFuzz

        # Fallback to RapidFuzz
        return self._fuzzy_search(query, candidates, top_k)

    def _semantic_search(
        self, query: str, candidates: List[Dict[str, Any]], top_k: int
    ) -> List[Dict[str, Any]]:
        """Perform semantic search using embeddings."""
        if self._embedding_service is None:
            raise RuntimeError("Embedding service not available")

        # Generate query embedding
        query_embedding = self._embedding_service.embed_query(query)

        # Calculate similarities
        similarities: List[Tuple[float, int]] = []
        for idx, doc in enumerate(candidates):
            doc_embedding = doc.get("embedding", [])
            if not doc_embedding:
                continue
            similarity = cosine_similarity(query_embedding, doc_embedding)
            similarities.append((similarity, idx))

        # Sort by similarity (descending) and take top-k
        similarities.sort(reverse=True, key=lambda x: x[0])
        top_matches = similarities[:top_k]

        # Build results
        results: List[Dict[str, Any]] = []
        for score, idx in top_matches:
            doc = candidates[idx]
            results.append(
                {
                    "source": doc.get("source"),
                    "id": doc.get("id"),
                    "text": doc.get("text"),
                    "metadata": doc.get("metadata", {}),
                    "score": float(score),
                    "retrieval_method": "semantic",
                }
            )

        logger.debug(
            "Semantic search returned %d results for query (top score=%.3f)",
            len(results),
            results[0]["score"] if results else 0.0,
        )

        return results

    def _fuzzy_search(
        self, query: str, candidates: List[Dict[str, Any]], top_k: int
    ) -> List[Dict[str, Any]]:
        """Perform fuzzy string matching search using RapidFuzz."""
        if rapidfuzz_process is None:
            raise RuntimeError("rapidfuzz is required for retrieval")

        matches = rapidfuzz_process.extract(
            query,
            [doc["text"] for doc in candidates],
            limit=top_k,
        )

        results: List[Dict[str, Any]] = []
        for _, score, idx in matches:
            doc = candidates[idx]
            results.append(
                {
                    "source": doc.get("source"),
                    "id": doc.get("id"),
                    "text": doc.get("text"),
                    "metadata": doc.get("metadata", {}),
                    "score": float(score),
                    "retrieval_method": "fuzzy",
                }
            )

        logger.debug(
            "Fuzzy search returned %d results for query (top score=%.1f)",
            len(results),
            results[0]["score"] if results else 0.0,
        )

        return results

    def clear_cache(self) -> None:
        """Remove cached embeddings."""

        if self._metadata_path.exists():
            self._metadata_path.unlink()
        self._documents = []
        self._source_versions = {}


def build_s1_documents(schema: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert the SentinelOne schema bundle into retrieval documents."""

    documents: List[Dict[str, Any]] = []

    datasets = schema.get("datasets", {})
    if isinstance(datasets, dict):
        for key in sorted(datasets.keys()):
            dataset = datasets.get(key, {})
            if not isinstance(dataset, dict):
                continue
            fields = dataset.get("fields", {})
            lines: List[str] = []
            if isinstance(fields, dict):
                for name in sorted(fields.keys()):
                    info = fields.get(name, {})
                    if not isinstance(info, dict):
                        continue
                    dtype = str(info.get("data_type", ""))
                    description = str(info.get("description", ""))
                    parts = [name]
                    if dtype:
                        parts.append(f"({dtype})")
                    if description:
                        parts.append(f"- {description}")
                    lines.append(" ".join(parts).strip())
            documents.append(
                {
                    "id": f"s1:dataset:{key}",
                    "text": "\n".join(
                        [
                            f"Dataset: {dataset.get('name', key)}",
                            *lines,
                        ]
                    ).strip(),
                    "metadata": {
                        "section": "datasets",
                        "dataset": key,
                        "name": dataset.get("name", key),
                    },
                }
            )

    common_fields = schema.get("common_fields", {})
    if isinstance(common_fields, dict) and common_fields:
        lines = []
        for name in sorted(common_fields.keys()):
            info = common_fields.get(name, {})
            dtype = ""
            description = ""
            if isinstance(info, dict):
                dtype = str(info.get("data_type", ""))
                description = str(info.get("description", ""))
            parts = [name]
            if dtype:
                parts.append(f"({dtype})")
            if description:
                parts.append(f"- {description}")
            lines.append(" ".join(parts).strip())
        documents.append(
            {
                "id": "s1:common_fields",
                "text": "\n".join(["Common Fields:", *lines]).strip(),
                "metadata": {"section": "common_fields"},
            }
        )

    operators = schema.get("operators")
    if isinstance(operators, dict) and operators:
        entries = operators.get("operators")
        lines = []
        if isinstance(entries, list):
            for entry in entries[:100]:  # avoid overly large document
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                description = entry.get("description")
                syntax = entry.get("syntax")
                if not isinstance(name, str):
                    continue
                parts = [f"{name}:"]
                if isinstance(description, str) and description:
                    parts.append(description)
                if isinstance(syntax, str) and syntax:
                    parts.append(f"Syntax: {syntax}")
                lines.append(" ".join(parts))
        documents.append(
            {
                "id": "s1:operators",
                "text": "\n".join(["Operators:", *lines]).strip(),
                "metadata": {"section": "operators"},
            }
        )

    shortcuts = schema.get("shortcuts", [])
    if isinstance(shortcuts, list) and shortcuts:
        lines = []
        for entry in shortcuts[:100]:
            if not isinstance(entry, dict):
                continue
            shortcut = entry.get("s1ql_shortcut")
            description = entry.get("description")
            if not isinstance(shortcut, str):
                continue
            text = shortcut
            if isinstance(description, str) and description:
                text += f" - {description}"
            lines.append(text)
        documents.append(
            {
                "id": "s1:shortcuts",
                "text": "\n".join(["Shortcut queries:", *lines]).strip(),
                "metadata": {"section": "shortcuts"},
            }
        )

    # Index comprehensive security patterns
    comprehensive = schema.get("comprehensive_security_patterns")
    if isinstance(comprehensive, dict):
        patterns = comprehensive.get("patterns", {})
        if isinstance(patterns, dict) and patterns:
            for pattern_name, pattern_data in sorted(patterns.items()):
                if not isinstance(pattern_data, dict):
                    continue

                description = str(pattern_data.get("description", ""))
                indicators = pattern_data.get("indicators", [])
                query = str(pattern_data.get("query", ""))
                dataset = str(pattern_data.get("dataset", ""))
                notes = str(pattern_data.get("notes", ""))

                lines = [
                    f"Comprehensive Security Pattern: {pattern_name.replace('_', ' ').title()}",
                    f"Description: {description}",
                ]
                if indicators and isinstance(indicators, list):
                    lines.append(f"Detection Indicators: {', '.join(indicators)}")
                if dataset:
                    lines.append(f"Dataset: {dataset}")
                if query:
                    lines.append(f"Query: {query}")
                if notes:
                    lines.append(f"Notes: {notes}")

                documents.append(
                    {
                        "id": f"s1:comprehensive_pattern:{pattern_name}",
                        "text": "\n".join(lines).strip(),
                        "metadata": {
                            "section": "comprehensive_patterns",
                            "pattern_name": pattern_name,
                            "indicators": indicators,
                            "dataset": dataset,
                        },
                    }
                )

    return documents


def build_cbc_documents(schema: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert the CBC schema JSON into retrieval-friendly documents."""

    documents: List[Dict[str, Any]] = []

    search_types = schema.get("search_types", {})

    if isinstance(search_types, dict):
        for name in sorted(search_types.keys()):
            meta = search_types.get(name, {})
            description = str(meta.get("description", "")) if isinstance(meta, dict) else ""
            applicable = []
            if isinstance(meta, dict):
                raw_applicable = meta.get("applicable_to")
                if isinstance(raw_applicable, list):
                    applicable = [str(item) for item in raw_applicable]

            # Create overview document for the search type
            applies_to = ", ".join(applicable) if applicable else "General"
            overview_text = "\n".join([
                f"Search Type: {name}",
                f"Description: {description or 'Not documented.'}",
                f"Applies To: {applies_to}",
            ])

            documents.append({
                "id": f"cbc:search_type:{name}",
                "text": overview_text,
                "metadata": {
                    "section": "search_types",
                    "search_type": name,
                    "description": description,
                    "applicable_to": applicable,
                },
            })

            # Create field documents - handle split field sets for process_search
            if name == "process_search":
                # Find all process_*_fields in the schema
                for key in sorted(schema.keys()):
                    if key.startswith("process_") and key.endswith("_fields"):
                        raw_fields = schema.get(key, {})
                        if not isinstance(raw_fields, dict) or not raw_fields:
                            continue
                        
                        # Extract category name (e.g., "auth" from "process_auth_fields")
                        category = key.replace("process_", "").replace("_fields", "")
                        
                        field_lines: List[str] = []
                        for field_name in sorted(raw_fields.keys()):
                            field_meta = raw_fields.get(field_name)
                            if not isinstance(field_meta, dict):
                                continue
                            field_type = str(field_meta.get("type", ""))
                            description_line = str(field_meta.get("description", ""))
                            values = field_meta.get("values")
                            qualifiers: List[str] = []
                            if field_type:
                                qualifiers.append(field_type)
                            if field_meta.get("default_field"):
                                qualifiers.append("default")
                            header = field_name
                            if qualifiers:
                                header += f" ({', '.join(qualifiers)})"
                            parts = [header]
                            if description_line:
                                parts.append(f"- {description_line}")
                            if isinstance(values, list) and values:
                                preview = ", ".join(str(v) for v in values[:5])
                                if len(values) > 5:
                                    preview += ", ..."
                                parts.append(f"Values: {preview}")
                            field_lines.append(" ".join(parts).strip())
                        
                        if field_lines:
                            text = "\n".join([
                                f"Search Type: {name} - {category.replace('_', ' ').title()} Fields",
                                "Fields:",
                                *field_lines,
                            ])
                            
                            documents.append({
                                "id": f"cbc:search_type:{name}:{category}_fields",
                                "text": text,
                                "metadata": {
                                    "section": "search_types",
                                    "search_type": name,
                                    "category": category,
                                    "description": description,
                                    "applicable_to": applicable,
                                },
                            })
            else:
                # For other search types, use single field mapping
                field_key = {
                    "binary_search": "binary_search_fields",
                    "alert_search": "alert_search_fields",
                    "threat_report_search": "threat_report_search_fields",
                }.get(name, "")
                
                if field_key:
                    raw_fields = schema.get(field_key, {})
                    field_lines: List[str] = []
                    if isinstance(raw_fields, dict):
                        for field_name in sorted(raw_fields.keys()):
                            field_meta = raw_fields.get(field_name)
                            if not isinstance(field_meta, dict):
                                continue
                            field_type = str(field_meta.get("type", ""))
                            description_line = str(field_meta.get("description", ""))
                            values = field_meta.get("values")
                            qualifiers: List[str] = []
                            if field_type:
                                qualifiers.append(field_type)
                            if field_meta.get("default_field"):
                                qualifiers.append("default")
                            header = field_name
                            if qualifiers:
                                header += f" ({', '.join(qualifiers)})"
                            parts = [header]
                            if description_line:
                                parts.append(f"- {description_line}")
                            if isinstance(values, list) and values:
                                preview = ", ".join(str(v) for v in values[:5])
                                if len(values) > 5:
                                    preview += ", ..."
                                parts.append(f"Values: {preview}")
                            field_lines.append(" ".join(parts).strip())
                    
                    if not field_lines:
                        field_lines.append("No field metadata available.")

                    text = "\n".join([
                        f"Search Type: {name} - Fields",
                        "Fields:",
                        *field_lines,
                    ])

                    documents.append({
                        "id": f"cbc:search_type:{name}:fields",
                        "text": text,
                        "metadata": {
                            "section": "search_types",
                            "search_type": name,
                            "description": description,
                            "applicable_to": applicable,
                        },
                    })

    field_types = schema.get("field_types")
    if isinstance(field_types, dict) and field_types:
        lines: List[str] = []
        for field_type, meta in sorted(field_types.items()):
            if not isinstance(meta, dict):
                continue
            description = str(meta.get("description", ""))
            behavior = str(meta.get("search_behavior", ""))
            example = meta.get("example")
            parts = [f"Type: {field_type}"]
            if description:
                parts.append(f"Description: {description}")
            if behavior:
                parts.append(f"Search behaviour: {behavior}")
            if example:
                parts.append(f"Example: {example}")
            lines.append(" | ".join(parts))
        documents.append(
            {
                "id": "cbc:field_types",
                "text": "\n".join(["Field Type Reference:", *lines]) if lines else "Field Type Reference:",
                "metadata": {"section": "field_types"},
            }
        )

    operators = schema.get("operators")
    if isinstance(operators, dict) and operators:
        lines = ["Operator Reference:"]
        for category, entries in sorted(operators.items()):
            lines.append(f"Category: {category}")
            if isinstance(entries, dict):
                for name, meta in sorted(entries.items()):
                    if not isinstance(meta, dict):
                        continue
                    description = str(meta.get("description", ""))
                    syntax = meta.get("syntax")
                    examples = meta.get("examples")
                    line_parts = [f"- {name}"]
                    if description:
                        line_parts.append(description)
                    if isinstance(syntax, list) and syntax:
                        line_parts.append(f"Syntax: {', '.join(str(s) for s in syntax)}")
                    if isinstance(examples, list) and examples:
                        sample = "; ".join(str(e) for e in examples[:3])
                        if len(examples) > 3:
                            sample += "; ..."
                        line_parts.append(f"Examples: {sample}")
                    lines.append(" ".join(line_parts))
            lines.append("")
        documents.append(
            {
                "id": "cbc:operators",
                "text": "\n".join(lines).strip(),
                "metadata": {"section": "operators"},
            }
        )

    best_practices = schema.get("best_practices")
    if isinstance(best_practices, dict) and best_practices:
        lines = ["Best Practices:"]
        for category, tips in sorted(best_practices.items()):
            lines.append(f"Category: {category}")
            if isinstance(tips, list):
                for tip in tips:
                    lines.append(f"- {tip}")
            lines.append("")
        documents.append(
            {
                "id": "cbc:best_practices",
                "text": "\n".join(lines).strip(),
                "metadata": {"section": "best_practices"},
            }
        )

    guidelines = schema.get("query_building_guidelines")
    if isinstance(guidelines, dict) and guidelines:
        lines = ["Query Building Guidelines:"]
        for step, meta in sorted(guidelines.items()):
            if not isinstance(meta, dict):
                continue
            title = step.replace("_", " ").title()
            description = str(meta.get("description", ""))
            lines.append(f"Step: {title}")
            if description:
                lines.append(f"- {description}")
            for key in ("questions", "considerations", "rules", "validations", "tips"):
                entries = meta.get(key)
                if isinstance(entries, list) and entries:
                    lines.append(f"  {key.title()}:")
                    for entry in entries:
                        lines.append(f"    - {entry}")
            lines.append("")
        documents.append(
            {
                "id": "cbc:guidelines",
                "text": "\n".join(lines).strip(),
                "metadata": {"section": "guidelines"},
            }
        )

    example_queries = schema.get("example_queries")
    if isinstance(example_queries, dict) and example_queries:
        lines = ["Example Queries:"]
        for category, examples in sorted(example_queries.items()):
            lines.append(f"Category: {category}")
            if isinstance(examples, list):
                for example in examples:
                    if isinstance(example, dict):
                        title = str(example.get("title", ""))
                        query = str(example.get("query", ""))
                        description = str(example.get("description", ""))
                        if title:
                            lines.append(f"- {title}")
                        if description:
                            lines.append(f"  Description: {description}")
                        if query:
                            lines.append(f"  Query: {query}")
                    else:
                        lines.append(f"- {example}")
            lines.append("")
        documents.append(
            {
                "id": "cbc:examples",
                "text": "\n".join(lines).strip(),
                "metadata": {"section": "examples"},
            }
        )

    # Index comprehensive security patterns
    comprehensive = schema.get("comprehensive_security_patterns")
    if isinstance(comprehensive, dict):
        patterns = comprehensive.get("patterns", {})
        if isinstance(patterns, dict) and patterns:
            for pattern_name, pattern_data in sorted(patterns.items()):
                if not isinstance(pattern_data, dict):
                    continue

                description = str(pattern_data.get("description", ""))
                indicators = pattern_data.get("indicators", [])
                query = str(pattern_data.get("query", ""))
                search_type = str(pattern_data.get("search_type", ""))
                notes = str(pattern_data.get("notes", ""))

                lines = [
                    f"Comprehensive Security Pattern: {pattern_name.replace('_', ' ').title()}",
                    f"Description: {description}",
                ]
                if indicators and isinstance(indicators, list):
                    lines.append(f"Detection Indicators: {', '.join(indicators)}")
                if search_type:
                    lines.append(f"Search Type: {search_type}")
                if query:
                    lines.append(f"Query: {query}")
                if notes:
                    lines.append(f"Notes: {notes}")

                documents.append(
                    {
                        "id": f"cbc:comprehensive_pattern:{pattern_name}",
                        "text": "\n".join(lines).strip(),
                        "metadata": {
                            "section": "comprehensive_patterns",
                            "pattern_name": pattern_name,
                            "indicators": indicators,
                            "search_type": search_type,
                        },
                    }
                )

    return documents


def build_cortex_documents(schema: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert the Cortex XDR schema JSON into retrieval-friendly documents."""

    documents: List[Dict[str, Any]] = []

    def field_summary(field_name: str, meta: Dict[str, Any]) -> str:
        field_type = str(meta.get("type", ""))
        description = str(meta.get("description", ""))
        values = meta.get("values")
        default_flag = meta.get("default_field")

        qualifiers: List[str] = []
        if field_type:
            qualifiers.append(field_type)
        if default_flag:
            qualifiers.append("default")

        header = field_name
        if qualifiers:
            header += f" ({', '.join(qualifiers)})"

        lines = [header]
        if description:
            lines.append(f"- {description}")
        if isinstance(values, list) and values:
            preview = ", ".join(str(v) for v in values[:5])
            if len(values) > 5:
                preview += ", ..."
            lines.append(f"Values: {preview}")
        return " ".join(lines).strip()

    def add_document(doc_id: str, section: str, lines: List[str]) -> None:
        text = "\n".join(line for line in lines if line).strip()
        if text:
            documents.append({"id": f"cortex:{doc_id}", "section": section, "text": text})

    overview_lines: List[str] = []
    version = schema.get("version")
    description = schema.get("description")
    last_updated = schema.get("last_updated")
    if description:
        overview_lines.append(f"Description: {description}")
    if version:
        overview_lines.append(f"Version: {version}")
    if last_updated:
        overview_lines.append(f"Last Updated: {last_updated}")
    add_document("schema_overview", "overview", overview_lines)

    datasets = schema.get("datasets")
    if isinstance(datasets, dict):
        for name in sorted(datasets.keys()):
            meta = datasets.get(name, {})
            if not isinstance(meta, dict):
                continue
            lines = [f"Dataset: {name}"]
            ds_description = meta.get("description")
            if ds_description:
                lines.append(f"Description: {ds_description}")
            use_cases = meta.get("use_cases")
            if isinstance(use_cases, list) and use_cases:
                lines.append("Use Cases:")
                for entry in use_cases:
                    lines.append(f"- {entry}")
            performance = meta.get("performance_notes")
            if performance:
                lines.append(f"Performance Notes: {performance}")
            add_document(f"dataset:{name}", "datasets", lines)

    field_types = schema.get("field_types")
    if isinstance(field_types, dict) and field_types:
        lines = ["Field Type Reference:"]
        for field_type, meta in sorted(field_types.items()):
            if not isinstance(meta, dict):
                continue
            description = meta.get("description")
            operators = meta.get("operators")
            examples = meta.get("examples")
            entry = [f"Type: {field_type}"]
            if description:
                entry.append(f"Description: {description}")
            if isinstance(operators, list) and operators:
                entry.append("Operators: " + ", ".join(str(op) for op in operators))
            if isinstance(examples, list) and examples:
                entry.append("Examples: " + "; ".join(str(ex) for ex in examples[:3]))
            lines.append(" | ".join(entry))
        add_document("field_types", "field_types", lines)

    operators = schema.get("operators")
    if isinstance(operators, dict) and operators:
        lines = ["Operator Reference:"]
        for category, entries in sorted(operators.items()):
            lines.append(f"Category: {category}")
            if isinstance(entries, dict):
                for name, meta in sorted(entries.items()):
                    if not isinstance(meta, dict):
                        continue
                    entry_parts = [f"- {name}"]
                    description_value = meta.get("description")
                    if description_value:
                        entry_parts.append(str(description_value))
                    syntax = meta.get("syntax") or meta.get("symbol")
                    if syntax:
                        if isinstance(syntax, list):
                            entry_parts.append("Syntax: " + ", ".join(str(s) for s in syntax))
                        else:
                            entry_parts.append(f"Syntax: {syntax}")
                    examples = meta.get("examples")
                    if isinstance(examples, list) and examples:
                        entry_parts.append("Examples: " + "; ".join(str(ex) for ex in examples[:3]))
                    lines.append(" ".join(entry_parts))
            lines.append("")
        add_document("operators", "operators", lines)

    functions = schema.get("xql_functions")
    if isinstance(functions, dict) and functions:
        lines = ["XQL Functions:"]
        for name, meta in sorted(functions.items()):
            if not isinstance(meta, dict):
                continue
            entry = [f"- {name}"]
            description_value = meta.get("description")
            syntax = meta.get("syntax")
            position = meta.get("position")
            if description_value:
                entry.append(str(description_value))
            if syntax:
                entry.append(f"Syntax: {syntax}")
            if position:
                entry.append(f"Position: {position}")
            examples = meta.get("examples")
            if isinstance(examples, list) and examples:
                entry.append("Examples: " + "; ".join(str(ex) for ex in examples[:3]))
            lines.append(" ".join(entry))
        add_document("xql_functions", "functions", lines)

    example_queries = schema.get("example_queries")
    if isinstance(example_queries, dict) and example_queries:
        for category, examples in sorted(example_queries.items()):
            lines = [f"Example Queries: {category}"]
            if isinstance(examples, list):
                for example in examples:
                    if not isinstance(example, dict):
                        continue
                    title = example.get("title")
                    if title:
                        lines.append(f"- {title}")
                    description_value = example.get("description")
                    if description_value:
                        lines.append(f"  Description: {description_value}")
                    query = example.get("query")
                    if query:
                        lines.append(f"  Query: {query}")
                    use_case = example.get("use_case")
                    if use_case:
                        lines.append(f"  Use Case: {use_case}")
            add_document(f"example_queries:{category}", "examples", lines)

    best_practices = schema.get("best_practices")
    if isinstance(best_practices, dict) and best_practices:
        for category, tips in sorted(best_practices.items()):
            lines = [f"Best Practices: {category}"]
            if isinstance(tips, list):
                for tip in tips:
                    lines.append(f"- {tip}")
            add_document(f"best_practices:{category}", "best_practices", lines)

    guidelines = schema.get("query_building_guidelines")
    if isinstance(guidelines, dict) and guidelines:
        for step, meta in sorted(guidelines.items()):
            if not isinstance(meta, dict):
                continue
            title = step.replace("_", " ").title()
            lines = [f"Guideline: {title}"]
            description_value = meta.get("description")
            if description_value:
                lines.append(f"Description: {description_value}")
            for key in ("questions", "decision_tree", "considerations", "rules", "stages", "validations"):
                entries = meta.get(key)
                if isinstance(entries, list) and entries:
                    lines.append(f"{key.replace('_', ' ').title()}:")
                    for entry in entries:
                        lines.append(f"- {entry}")
                elif isinstance(entries, dict) and entries:
                    lines.append(f"{key.replace('_', ' ').title()}:")
                    for sub_key, value in entries.items():
                        lines.append(f"- {sub_key}: {value}")
            add_document(f"guideline:{step}", "guidelines", lines)

    use_cases = schema.get("common_use_cases")
    if isinstance(use_cases, dict) and use_cases:
        for name, meta in sorted(use_cases.items()):
            if not isinstance(meta, dict):
                continue
            lines = [f"Use Case: {name}"]
            description_value = meta.get("description")
            if description_value:
                lines.append(f"Description: {description_value}")
            indicators = meta.get("indicators")
            if isinstance(indicators, list) and indicators:
                lines.append("Indicators:")
                for indicator in indicators:
                    lines.append(f"- {indicator}")
            key_fields = meta.get("key_fields")
            if isinstance(key_fields, list) and key_fields:
                lines.append("Key Fields:")
                for field in key_fields:
                    lines.append(f"- {field}")
            add_document(f"use_case:{name}", "use_cases", lines)

    enum_values = schema.get("enum_values")
    if isinstance(enum_values, dict) and enum_values:
        for field_name, values in sorted(enum_values.items()):
            if not isinstance(values, dict):
                continue
            lines = [f"Enum Values: {field_name}"]
            for enum_name, meta in sorted(values.items()):
                if isinstance(meta, dict):
                    value_repr = meta.get("value")
                    description_value = meta.get("description")
                    entry = f"- {enum_name}"
                    if value_repr is not None:
                        entry += f" ({value_repr})"
                    if description_value:
                        entry += f": {description_value}"
                    lines.append(entry)
            add_document(f"enum:{field_name}", "enum_values", lines)

    techniques = schema.get("special_techniques")
    if isinstance(techniques, dict) and techniques:
        for name, meta in sorted(techniques.items()):
            if not isinstance(meta, dict):
                continue
            lines = [f"Special Technique: {name}"]
            description_value = meta.get("description")
            if description_value:
                lines.append(f"Description: {description_value}")
            for key in ("methods", "operations", "functions"):
                entries = meta.get(key)
                if isinstance(entries, list):
                    for entry in entries:
                        if isinstance(entry, dict):
                            entry_lines: List[str] = []
                            label = entry.get("name")
                            if label:
                                entry_lines.append(f"- {label}")
                            info_parts = []
                            for sub_key in ("description", "syntax", "example"):
                                value = entry.get(sub_key)
                                if value:
                                    info_parts.append(f"{sub_key.title()}: {value}")
                            if info_parts:
                                entry_lines.append("  " + " | ".join(info_parts))
                            lines.extend(entry_lines)
            add_document(f"technique:{name}", "techniques", lines)

    troubleshooting = schema.get("troubleshooting")
    if isinstance(troubleshooting, dict) and troubleshooting:
        for topic, tips in sorted(troubleshooting.items()):
            lines = [f"Troubleshooting: {topic}"]
            if isinstance(tips, list):
                for tip in tips:
                    lines.append(f"- {tip}")
            add_document(f"troubleshooting:{topic}", "troubleshooting", lines)

    integrations = schema.get("integration_notes")
    if isinstance(integrations, dict) and integrations:
        for name, meta in sorted(integrations.items()):
            if not isinstance(meta, dict):
                continue
            lines = [f"Integration: {name}"]
            description_value = meta.get("description")
            if description_value:
                lines.append(f"Description: {description_value}")
            for key in ("notes", "commands"):
                entries = meta.get(key)
                if isinstance(entries, list):
                    lines.append(f"{key.title()}:")
                    for entry in entries:
                        lines.append(f"- {entry}")
            add_document(f"integration:{name}", "integrations", lines)

    field_groups = schema.get("field_groups")
    if isinstance(field_groups, dict) and field_groups:
        for name, meta in sorted(field_groups.items()):
            if not isinstance(meta, dict):
                continue
            lines = [f"Field Group: {name}"]
            description_value = meta.get("description")
            if description_value:
                lines.append(f"Description: {description_value}")
            prefix = meta.get("prefix")
            if prefix:
                lines.append(f"Prefix: {prefix}")
            for key in ("fields", "key_fields"):
                entries = meta.get(key)
                if isinstance(entries, list) and entries:
                    lines.append(f"{key.replace('_', ' ').title()}:")
                    for entry in entries:
                        lines.append(f"- {entry}")
            add_document(f"field_group:{name}", "field_groups", lines)

    try:
        from .cortex_schema_loader import CortexSchemaCache as _CortexSchemaCache
    except ImportError:  # pragma: no cover - defensive
        dataset_map: Dict[str, str] = {}
    else:
        dataset_map = getattr(_CortexSchemaCache, "DATASET_FIELD_MAP", {})

    for dataset, field_key in dataset_map.items():
        raw_fields = schema.get(field_key, {})
        if not isinstance(raw_fields, dict) or not raw_fields:
            continue
        lines = [f"Fields for {dataset}:"]
        for field_name in sorted(raw_fields.keys()):
            field_meta = raw_fields.get(field_name)
            if isinstance(field_meta, dict):
                lines.append(field_summary(field_name, field_meta))
        add_document(f"dataset_fields:{dataset}", "fields", lines)

    # Index comprehensive security patterns
    comprehensive = schema.get("comprehensive_security_patterns")
    if isinstance(comprehensive, dict):
        patterns = comprehensive.get("patterns", {})
        if isinstance(patterns, dict) and patterns:
            for pattern_name, pattern_data in sorted(patterns.items()):
                if not isinstance(pattern_data, dict):
                    continue

                description = str(pattern_data.get("description", ""))
                indicators = pattern_data.get("indicators", [])
                query = str(pattern_data.get("query", ""))
                dataset = str(pattern_data.get("dataset", ""))
                notes = str(pattern_data.get("notes", ""))

                lines = [
                    f"Comprehensive Security Pattern: {pattern_name.replace('_', ' ').title()}",
                    f"Description: {description}",
                ]
                if indicators and isinstance(indicators, list):
                    lines.append(f"Detection Indicators: {', '.join(indicators)}")
                if dataset:
                    lines.append(f"Dataset: {dataset}")
                if query:
                    lines.append(f"Query: {query}")
                if notes:
                    lines.append(f"Notes: {notes}")

                add_document(f"comprehensive_pattern:{pattern_name}", "comprehensive_patterns", lines, {"pattern_name": pattern_name, "indicators": indicators, "dataset": dataset})

    return documents


def build_kql_documents(schema: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert the Defender schema into retrieval-friendly documents."""

    documents: List[Dict[str, Any]] = []
    for table in sorted(schema.keys()):
        table_info = schema.get(table, {})
        if not isinstance(table_info, dict):
            continue
        url = str(table_info.get("url", ""))
        columns = table_info.get("columns", []) or []

        column_lines: List[str] = []
        for column in columns:
            if not isinstance(column, dict):
                continue
            name = str(column.get("name", ""))
            ctype = str(column.get("type", ""))
            description = str(column.get("description", ""))
            parts = [part for part in [name, f"({ctype})" if ctype else "", description] if part]
            if parts:
                column_lines.append(" ".join(parts))

        if not column_lines:
            column_lines.append("No column metadata available.")

        text = "\n".join(
            [
                f"Table: {table}",
                f"Documentation: {url}" if url else "Documentation: (missing)",
                "Columns:",
                *column_lines,
            ]
        )

        documents.append(
            {
                "id": f"kql:{table}",
                "text": text,
                "metadata": {"table": table, "url": url},
            }
        )

    # Index comprehensive security patterns
    comprehensive = schema.get("comprehensive_security_patterns")
    if isinstance(comprehensive, dict):
        patterns = comprehensive.get("patterns", {})
        if isinstance(patterns, dict) and patterns:
            for pattern_name, pattern_data in sorted(patterns.items()):
                if not isinstance(pattern_data, dict):
                    continue

                description = str(pattern_data.get("description", ""))
                indicators = pattern_data.get("indicators", [])
                query = str(pattern_data.get("query", ""))
                table = str(pattern_data.get("table", ""))
                notes = str(pattern_data.get("notes", ""))

                lines = [
                    f"Comprehensive Security Pattern: {pattern_name.replace('_', ' ').title()}",
                    f"Description: {description}",
                ]
                if indicators and isinstance(indicators, list):
                    lines.append(f"Detection Indicators: {', '.join(indicators)}")
                if table:
                    lines.append(f"Table: {table}")
                if query:
                    lines.append(f"Query: {query}")
                if notes:
                    lines.append(f"Notes: {notes}")

                documents.append(
                    {
                        "id": f"kql:comprehensive_pattern:{pattern_name}",
                        "text": "\n".join(lines).strip(),
                        "metadata": {
                            "section": "comprehensive_patterns",
                            "pattern_name": pattern_name,
                            "indicators": indicators,
                            "table": table,
                        },
                    }
                )

    return documents


def build_cbr_documents(schema: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert the Carbon Black Response schema into retrieval-friendly documents."""

    documents: List[Dict[str, Any]] = []

    # Platform overview
    version = schema.get("version")
    platform = schema.get("platform")
    updated_at = schema.get("updated_at")
    
    overview_lines = ["Carbon Black Response Event Forwarder Schema"]
    if platform:
        overview_lines.append(f"Platform: {platform}")
    if version:
        overview_lines.append(f"Version: {version}")
    if updated_at:
        overview_lines.append(f"Updated: {updated_at}")
    
    documents.append({
        "id": "cbr:overview",
        "text": "\n".join(overview_lines),
        "metadata": {"section": "overview"},
    })

    # Search types overview
    search_types = schema.get("search_types", {})
    if isinstance(search_types, dict):
        for search_type, info in sorted(search_types.items()):
            if not isinstance(info, dict):
                continue
            
            description = str(info.get("description", ""))
            datasets = info.get("datasets", [])
            
            lines = [f"Search Type: {search_type}"]
            if description:
                lines.append(f"Description: {description}")
            if isinstance(datasets, list) and datasets:
                lines.append(f"Available Datasets: {len(datasets)}")
                # Show first few dataset names
                dataset_preview = ", ".join(datasets[:3])
                if len(datasets) > 3:
                    dataset_preview += f", ... ({len(datasets)} total)"
                lines.append(f"Datasets: {dataset_preview}")
            
            documents.append({
                "id": f"cbr:search_type:{search_type}",
                "text": "\n".join(lines),
                "metadata": {
                    "section": "search_types",
                    "search_type": search_type,
                    "description": description,
                },
            })

    # Field sets - process each dataset's fields
    def create_field_document(field_set_name: str, fields: Dict[str, Any], section: str) -> None:
        if not isinstance(fields, dict) or not fields:
            return
        
        # Extract meaningful name from field set
        if field_set_name.endswith("_fields"):
            display_name = field_set_name[:-7].replace("_", " ").title()
        else:
            display_name = field_set_name.replace("_", " ").title()
        
        field_lines = [f"Dataset: {display_name}"]
        
        # Add field information
        field_count = len(fields)
        field_lines.append(f"Total Fields: {field_count}")
        field_lines.append("Fields:")
        
        # List fields with their types and descriptions
        for field_name in sorted(fields.keys()):
            field_meta = fields.get(field_name)
            if not isinstance(field_meta, dict):
                continue
                
            field_type = str(field_meta.get("type", ""))
            description = str(field_meta.get("description", ""))
            
            # Format field entry
            field_entry = field_name
            if field_type:
                field_entry += f" ({field_type})"
            if description:
                field_entry += f" - {description[:100]}"  # Truncate long descriptions
                if len(description) > 100:
                    field_entry += "..."
            
            field_lines.append(f"  {field_entry}")
        
        documents.append({
            "id": f"cbr:{section}:{field_set_name}",
            "text": "\n".join(field_lines),
            "metadata": {
                "section": section,
                "dataset": field_set_name,
                "field_count": field_count,
            },
        })

    # Process all field sets in the schema
    for key, value in schema.items():
        if key.endswith("_fields") and isinstance(value, dict):
            # Determine section based on field set name
            if any(x in key for x in ["watchlist", "feed", "binaryinfo", "binarystore"]):
                section = "server_events"
            elif any(x in key for x in ["regmod", "filemod", "netconn", "moduleload", "childproc", "procstart", "crossprocopen", "emetmitigation", "processblock", "tamper"]):
                section = "endpoint_events"
            else:
                section = "fields"
            
            create_field_document(key, value, section)

    # Operators
    logical_operators = schema.get("logical_operators", {})
    field_operators = schema.get("field_operators", {})
    
    if isinstance(logical_operators, dict) or isinstance(field_operators, dict):
        lines = ["Carbon Black Response Query Operators"]
        
        if isinstance(logical_operators, dict):
            lines.append("Logical Operators:")
            for op_name, op_info in sorted(logical_operators.items()):
                if isinstance(op_info, dict):
                    desc = str(op_info.get("description", ""))
                    usage = str(op_info.get("usage", ""))
                    op_line = f"  {op_name}"
                    if desc:
                        op_line += f" - {desc}"
                    if usage:
                        op_line += f" (Usage: {usage})"
                    lines.append(op_line)
        
        if isinstance(field_operators, dict):
            lines.append("Field Operators:")
            for op_name, op_info in sorted(field_operators.items()):
                if isinstance(op_info, dict):
                    desc = str(op_info.get("description", ""))
                    example = str(op_info.get("example", ""))
                    op_line = f"  {op_name}"
                    if desc:
                        op_line += f" - {desc}"
                    if example:
                        op_line += f" (Example: {example})"
                    lines.append(op_line)
        
        # Add operator notes
        notes = schema.get("notes", [])
        if isinstance(notes, list) and notes:
            lines.append("Notes:")
            for note in notes:
                lines.append(f"  - {note}")
        
        documents.append({
            "id": "cbr:operators",
            "text": "\n".join(lines),
            "metadata": {"section": "operators"},
        })

    # Best practices
    best_practices = schema.get("field_usage", {}) or schema.get("best_practices", {})
    if isinstance(best_practices, dict):
        lines = ["Carbon Black Response Best Practices"]
        
        for category, info in sorted(best_practices.items()):
            if not isinstance(info, dict):
                continue
                
            lines.append(f"Category: {category.replace('_', ' ').title()}")
            
            # Handle different structures
            for key, value in info.items():
                if key == "recommendation" and isinstance(value, str):
                    lines.append(f"  Recommendation: {value}")
                elif key in ["good", "avoid", "example"] and isinstance(value, str):
                    lines.append(f"  {key.title()}: {value}")
                elif key == "fields" and isinstance(value, list):
                    lines.append(f"  Fields: {', '.join(value)}")
                elif key == "rationale" and isinstance(value, str):
                    lines.append(f"  Rationale: {value}")
                elif isinstance(value, dict):
                    lines.append(f"  {key.replace('_', ' ').title()}:")
                    for sub_key, sub_value in value.items():
                        lines.append(f"    {sub_key}: {sub_value}")
            
            lines.append("")
        
        documents.append({
            "id": "cbr:best_practices",
            "text": "\n".join(lines).strip(),
            "metadata": {"section": "best_practices"},
        })

    return documents
