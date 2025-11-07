from __future__ import annotations

import logging
from typing import Any, Dict, Literal, Optional

from fastmcp import FastMCP

from server_runtime import ServerRuntime

logger = logging.getLogger(__name__)


def attach_rag_context(
    *,
    runtime: ServerRuntime,
    intent: Optional[str],
    metadata: Dict[str, Any],
    source_filter: Literal["cbc", "kql", "cortex", "s1"],
    provider_label: str,
    logger: logging.Logger,
    k: int = 10,
) -> Dict[str, Any]:
    """Augment metadata with RAG context for the provided natural-language intent.

    This helper centralises the defensive logic for fetching semantic context across
    the different query builders so they remain consistent over time. It lives in the
    shared layer because callers kept reimplementing slightly different behaviours,
    which made it hard to reason about why a particular request did or did not have
    RAG context attached. The central helper keeps the "skip empty prompt", "surface
    init failures", and "log retrieval issues" conventions aligned everywhere that
    attaches RAG metadata.
    """

    if not intent or not intent.strip():
        return metadata

    rag_metadata = dict(metadata)

    if not runtime.ensure_rag_initialized():
        if runtime.rag_init_failed:
            rag_metadata.update(
                {
                    "rag_context_status": "error",
                    "rag_context_error": runtime.rag_init_error or "initialization_failed",
                }
            )
            logger.warning(
                "⚠️ Skipping %s RAG context due to initialization failure: %s",
                provider_label,
                runtime.rag_init_error or "unknown error",
            )
        else:
            logger.debug(
                "⏳ RAG not ready, skipping context retrieval for %s query", provider_label
            )
            rag_metadata.setdefault("rag_context_status", "not_ready")
        return rag_metadata

    try:
        context = runtime.rag_service.search(
            intent, k=k, source_filter=source_filter
        )
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(
            "⚠️ Unable to attach %s RAG context: %s", provider_label, exc
        )
        rag_metadata.update(
            {
                "rag_context_status": "error",
                "rag_context_error": str(exc),
            }
        )
        return rag_metadata

    if context:
        rag_metadata.update(
            {
                "rag_context": context,
                "rag_context_status": "attached",
            }
        )
    else:
        rag_metadata.setdefault("rag_context_status", "no_matches")

    return rag_metadata


def register_shared_tools(mcp: FastMCP, runtime: ServerRuntime) -> None:
    """Register shared helper tooling for schema retrieval."""

    @mcp.tool
    def retrieve_context(
        query: str,
        k: int = 10,
        query_type: Optional[Literal["cbc", "kql", "cortex", "s1"]] = None,
    ) -> Dict[str, object]:
        """Return relevant schema passages for a natural language query."""

        if not runtime.ensure_rag_initialized():
            msg = "RAG service is not ready yet. Please try again in a moment."
            if runtime.rag_init_failed:
                msg = f"RAG service initialization failed: {runtime.rag_init_error or 'unknown error'}"
            logger.warning("⚠️ %s", msg)
            return {"error": msg, "matches": []}

        try:
            results = runtime.rag_service.search(query, k=k, source_filter=query_type)
            logger.info(
                "RAG returned %d matches for query with filter=%s",
                len(results),
                query_type,
            )
            return {"matches": results}
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("⚠️ Failed to retrieve RAG context: %s", exc)
            return {"error": str(exc), "matches": []}
