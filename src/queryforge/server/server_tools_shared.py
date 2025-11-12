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


def get_rag_enhanced_fields(
    runtime: Any,
    query_intent: Optional[str],
    source_filter: str,
    all_fields: List[Dict[str, Any]],
    dataset_name: str,
    k: int = 20,
) -> Dict[str, Any]:
    """
    Get semantically relevant fields using RAG retrieval.

    Args:
        runtime: Server runtime with RAG service
        query_intent: Natural language description of what fields to find
        source_filter: RAG source filter (e.g., "cbc", "kql")
        all_fields: Complete list of fields to filter from
        dataset_name: Name of the dataset for context
        k: Number of top fields to retrieve

    Returns:
        Dictionary with fields, either RAG-filtered or all fields
    """
    # If no query intent, return all fields
    if not query_intent:
        return {
            "fields": all_fields,
            "retrieval_method": "all_fields",
            "total_fields": len(all_fields),
            "note": "Provide a query_intent to get semantically relevant fields"
        }
    
    # Try RAG retrieval for semantic field filtering
    if runtime.rag_service:
        try:
            # Enhance query with dataset context
            enhanced_query = f"{query_intent} in {dataset_name} dataset"
            
            logger.info(
                "Searching for relevant fields using RAG: '%s'",
                enhanced_query[:100]
            )
            
            rag_results = runtime.rag_service.search(
                enhanced_query,
                k=k,
                source_filter=source_filter
            )
            
            if rag_results:
                # Extract field names mentioned in RAG results
                mentioned_fields = set()
                field_scores = {}
                
                for doc in rag_results:
                    text = doc.get("text", "").lower()
                    score = doc.get("score", 0.0)
                    
                    # Check which fields are mentioned in this document
                    for field_info in all_fields:
                        field_name = field_info.get("name", "")
                        if not field_name:
                            continue
                        
                        # Check if field name appears in the document
                        if field_name.lower() in text:
                            mentioned_fields.add(field_name)
                            # Track highest score for this field
                            if field_name not in field_scores or score > field_scores[field_name]:
                                field_scores[field_name] = score
                
                # If we found relevant fields, return them sorted by score
                if mentioned_fields:
                    relevant_fields = [
                        f for f in all_fields 
                        if f.get("name", "") in mentioned_fields
                    ]
                    
                    # Sort by RAG score
                    relevant_fields.sort(
                        key=lambda f: field_scores.get(f.get("name", ""), 0.0),
                        reverse=True
                    )
                    
                    logger.info(
                        "Retrieved %d semantically relevant fields (top score=%.3f)",
                        len(relevant_fields),
                        max(field_scores.values()) if field_scores else 0.0
                    )
                    
                    return {
                        "query_intent": query_intent,
                        "fields": relevant_fields,
                        "retrieval_method": "semantic_rag",
                        "total_fields": len(all_fields),
                        "filtered_count": len(relevant_fields),
                        "top_score": max(field_scores.values()) if field_scores else 0.0,
                    }
        
        except Exception as e:
            logger.warning(f"RAG-based field filtering failed: {e}, returning all fields")
    
    # Fallback: Return all fields
    return {
        "query_intent": query_intent,
        "fields": all_fields,
        "retrieval_method": "all_fields_fallback",
        "total_fields": len(all_fields),
        "note": "RAG retrieval unavailable or no relevant fields found, showing all fields"
    }


def get_rag_enhanced_datasets(
    runtime: Any,
    query_intent: str,
    source_filter: str,
    all_datasets: Dict[str, Any],
    k: int = 10,
) -> Dict[str, Any]:
    """
    Get semantically relevant datasets using RAG retrieval.

    Args:
        runtime: Server runtime with RAG service
        query_intent: Natural language description of what to find
        source_filter: RAG source filter (e.g., "cbc", "kql")
        all_datasets: Dictionary of all available datasets
        k: Number of top datasets to retrieve

    Returns:
        Dictionary with datasets, either RAG-ranked or all datasets
    """
    if not query_intent:
        return {
            "datasets": all_datasets,
            "retrieval_method": "all_datasets",
            "note": "Provide a query_intent to get semantically relevant datasets"
        }
    
    # Try RAG retrieval for semantic dataset ranking
    if runtime.rag_service:
        try:
            logger.info(
                "Searching for relevant datasets using RAG: '%s'",
                query_intent[:100]
            )
            
            rag_results = runtime.rag_service.search(
                query_intent,
                k=k,
                source_filter=source_filter
            )
            
            if rag_results:
                # Score datasets based on mentions in RAG results
                dataset_scores = {}
                
                for doc in rag_results:
                    text = doc.get("text", "").lower()
                    score = doc.get("score", 0.0)
                    metadata = doc.get("metadata", {})
                    
                    # Check dataset mentioned in metadata
                    doc_dataset = metadata.get("dataset") or metadata.get("search_type") or metadata.get("table")
                    if doc_dataset:
                        if doc_dataset not in dataset_scores or score > dataset_scores[doc_dataset]:
                            dataset_scores[doc_dataset] = score
                    
                    # Also check for dataset names in text
                    for dataset_key in all_datasets.keys():
                        if dataset_key.lower() in text:
                            if dataset_key not in dataset_scores or score > dataset_scores[dataset_key]:
                                dataset_scores[dataset_key] = score
                
                # If we found relevant datasets, return them sorted by score
                if dataset_scores:
                    relevant_datasets = {
                        k: v for k, v in all_datasets.items()
                        if k in dataset_scores
                    }
                    
                    # Sort by score
                    sorted_datasets = dict(
                        sorted(
                            relevant_datasets.items(),
                            key=lambda item: dataset_scores.get(item[0], 0.0),
                            reverse=True
                        )
                    )
                    
                    logger.info(
                        "Retrieved %d semantically relevant datasets (top score=%.3f)",
                        len(sorted_datasets),
                        max(dataset_scores.values()) if dataset_scores else 0.0
                    )
                    
                    return {
                        "query_intent": query_intent,
                        "datasets": sorted_datasets,
                        "retrieval_method": "semantic_rag",
                        "total_datasets": len(all_datasets),
                        "filtered_count": len(sorted_datasets),
                        "scores": dataset_scores,
                    }
        
        except Exception as e:
            logger.warning(f"RAG-based dataset ranking failed: {e}, returning all datasets")
    
    # Fallback: Return all datasets
    return {
        "query_intent": query_intent,
        "datasets": all_datasets,
        "retrieval_method": "all_datasets_fallback",
        "total_datasets": len(all_datasets),
        "note": "RAG retrieval unavailable or no relevant datasets found, showing all datasets"
    }
