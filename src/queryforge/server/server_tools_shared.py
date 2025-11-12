"""Shared utilities for MCP server tools."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def attach_rag_context(
    runtime: Any,
    intent: Optional[str],
    metadata: Dict[str, Any],
    source_filter: str,
    provider_label: str,
    logger: logging.Logger,
) -> Dict[str, Any]:
    """
    Attach RAG context metadata to query metadata for debugging/transparency.

    Args:
        runtime: Server runtime with RAG service
        intent: Natural language intent that was used for RAG search
        metadata: Query metadata to enhance
        source_filter: RAG source filter (e.g., "cbc", "kql")
        provider_label: Human-readable provider name (e.g., "CBC", "KQL")
        logger: Logger instance

    Returns:
        Enhanced metadata dictionary
    """
    if intent and runtime.rag_service:
        try:
            rag_results = runtime.rag_service.search(
                intent,
                k=5,  # Just for metadata purposes, not full context
                source_filter=source_filter
            )
            if rag_results:
                metadata["rag_enhanced"] = {
                    "intent": intent,
                    "retrieved_documents": len(rag_results),
                    "top_scores": [r.get("score", 0.0) for r in rag_results[:3]],
                    "retrieval_method": rag_results[0].get("retrieval_method") if rag_results else None,
                }
                logger.info(
                    "%s query enhanced with %d RAG documents (top score=%.3f)",
                    provider_label,
                    len(rag_results),
                    rag_results[0].get("score", 0.0) if rag_results else 0.0,
                )
        except Exception as e:
            logger.warning(f"Failed to attach RAG context metadata: {e}")
    
    return metadata


def get_rag_enhanced_examples(
    runtime: Any,
    query_intent: Optional[str],
    source_filter: str,
    fallback_examples: Dict[str, Any],
    k: int = 10,
) -> Dict[str, Any]:
    """
    Get semantically relevant examples using RAG retrieval.

    Args:
        runtime: Server runtime with RAG service
        query_intent: Natural language description of what to find
        source_filter: RAG source filter (e.g., "cbc", "kql")
        fallback_examples: Raw examples dict to use if RAG unavailable
        k: Number of examples to retrieve

    Returns:
        Dictionary with examples, either RAG-retrieved or fallback
    """
    # If no query intent, return all examples organized by category
    if not query_intent:
        return {
            "examples": fallback_examples,
            "retrieval_method": "all_categories",
            "note": "Provide a query intent to get semantically relevant examples"
        }
    
    # Try RAG retrieval for semantic search
    if runtime.rag_service:
        try:
            logger.info(
                "Searching for relevant examples using RAG: '%s'",
                query_intent[:100]
            )
            
            rag_results = runtime.rag_service.search(
                query_intent,
                k=k,
                source_filter=source_filter
            )
            
            if rag_results:
                # Filter to only example-related documents
                example_docs = [
                    r for r in rag_results
                    if r.get("metadata", {}).get("section") in ["examples", "example_queries"]
                    or "example" in r.get("id", "").lower()
                ]
                
                if example_docs:
                    # Format the retrieved examples
                    formatted_examples: List[Dict[str, Any]] = []
                    for doc in example_docs:
                        # Parse the text to extract example details
                        text = doc.get("text", "")
                        lines = text.split("\n")
                        
                        example_entry = {
                            "score": doc.get("score", 0.0),
                            "retrieval_method": doc.get("retrieval_method"),
                            "source_section": doc.get("metadata", {}).get("section"),
                        }
                        
                        # Try to extract structured information from text
                        current_example: Dict[str, str] = {}
                        for line in lines:
                            line = line.strip()
                            if line.startswith("- ") or line.startswith("Query:"):
                                # New example entry
                                if current_example and "description" in current_example:
                                    formatted_examples.append({**example_entry, **current_example})
                                    current_example = {}
                                
                                if line.startswith("Query:"):
                                    current_example["query"] = line.replace("Query:", "").strip()
                            elif line.startswith("Description:"):
                                current_example["description"] = line.replace("Description:", "").strip()
                            elif line.startswith("Use Case:"):
                                current_example["use_case"] = line.replace("Use Case:", "").strip()
                            elif ":" in line and not line.startswith("Category:"):
                                # Try to extract query from generic field:value format
                                if "query" not in current_example and len(line) > 10:
                                    current_example["query"] = line
                        
                        # Add last example if exists
                        if current_example and ("query" in current_example or "description" in current_example):
                            formatted_examples.append({**example_entry, **current_example})
                    
                    logger.info(
                        "Retrieved %d semantically relevant examples (top score=%.3f)",
                        len(formatted_examples),
                        formatted_examples[0]["score"] if formatted_examples else 0.0
                    )
                    
                    return {
                        "query_intent": query_intent,
                        "examples": formatted_examples,
                        "retrieval_method": "semantic_rag",
                        "total_retrieved": len(example_docs),
                        "formatted_count": len(formatted_examples),
                    }
        
        except Exception as e:
            logger.warning(f"RAG-based example retrieval failed: {e}, falling back to category-based")
    
    # Fallback: Return all examples organized by category
    return {
        "query_intent": query_intent,
        "examples": fallback_examples,
        "retrieval_method": "all_categories_fallback",
        "note": "RAG retrieval unavailable, showing all examples by category"
    }
