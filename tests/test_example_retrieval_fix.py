"""Test that example retrieval uses RAG instead of falling back to JSON."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from queryforge.server.server_tools_shared import get_rag_enhanced_examples


def test_get_rag_enhanced_examples_with_intent():
    """Test that providing query_intent triggers RAG retrieval."""
    
    # Mock runtime with RAG service
    mock_runtime = MagicMock()
    mock_runtime.rag_service = MagicMock()
    
    # Mock RAG search results with example-related documents
    mock_runtime.rag_service.search.return_value = [
        {
            "id": "cbc:examples:process_search",
            "text": (
                "Example Queries: process_search\n"
                "- Find processes with network connections\n"
                "  Description: Identify processes making external connections\n"
                "  Query: netconn_count:[1 TO *] AND -netconn_domain:.microsoft.com\n"
            ),
            "metadata": {"section": "examples"},
            "score": 0.85,
            "retrieval_method": "semantic",
        },
        {
            "id": "cbc:examples:complex",
            "text": (
                "Category: complex_queries\n"
                "- Find suspicious PowerShell with network activity\n"
                "  Query: process_name:powershell.exe AND netconn_count:[1 TO *]\n"
            ),
            "metadata": {"section": "example_queries"},
            "score": 0.78,
            "retrieval_method": "semantic",
        },
    ]
    
    fallback_examples = {"process_search": [], "binary_search": []}
    
    # Call the function with query intent
    result = get_rag_enhanced_examples(
        runtime=mock_runtime,
        query_intent="find network connections from PowerShell",
        source_filter="cbc",
        fallback_examples=fallback_examples,
        k=10,
    )
    
    # Verify RAG was called
    mock_runtime.rag_service.search.assert_called_once_with(
        "find network connections from PowerShell",
        k=10,
        source_filter="cbc"
    )
    
    # Verify result structure
    assert result["retrieval_method"] == "semantic_rag"
    assert result["query_intent"] == "find network connections from PowerShell"
    assert "examples" in result
    assert isinstance(result["examples"], list)
    assert len(result["examples"]) > 0
    
    # Verify examples have score and retrieval metadata
    for example in result["examples"]:
        assert "score" in example
        assert "retrieval_method" in example


def test_get_rag_enhanced_examples_without_intent():
    """Test that without query_intent, returns all categories."""
    
    mock_runtime = MagicMock()
    mock_runtime.rag_service = MagicMock()
    
    fallback_examples = {
        "process_search": [{"query": "test1"}],
        "binary_search": [{"query": "test2"}],
    }
    
    # Call without query intent
    result = get_rag_enhanced_examples(
        runtime=mock_runtime,
        query_intent=None,
        source_filter="cbc",
        fallback_examples=fallback_examples,
        k=10,
    )
    
    # Verify RAG was NOT called
    mock_runtime.rag_service.search.assert_not_called()
    
    # Verify it returns all examples
    assert result["retrieval_method"] == "all_categories"
    assert result["examples"] == fallback_examples


def test_get_rag_enhanced_examples_rag_unavailable():
    """Test fallback when RAG service is unavailable."""
    
    # Mock runtime without RAG service
    mock_runtime = MagicMock()
    mock_runtime.rag_service = None
    
    fallback_examples = {"process_search": [{"query": "test"}]}
    
    # Call with query intent but no RAG
    result = get_rag_enhanced_examples(
        runtime=mock_runtime,
        query_intent="find something",
        source_filter="cbc",
        fallback_examples=fallback_examples,
        k=10,
    )
    
    # Verify fallback was used
    assert result["retrieval_method"] == "all_categories_fallback"
    assert result["examples"] == fallback_examples
    assert "note" in result


def test_get_rag_enhanced_examples_rag_error():
    """Test fallback when RAG search raises an exception."""
    
    mock_runtime = MagicMock()
    mock_runtime.rag_service = MagicMock()
    mock_runtime.rag_service.search.side_effect = Exception("RAG error")
    
    fallback_examples = {"process_search": [{"query": "test"}]}
    
    # Call with query intent
    result = get_rag_enhanced_examples(
        runtime=mock_runtime,
        query_intent="find something",
        source_filter="cbc",
        fallback_examples=fallback_examples,
        k=10,
    )
    
    # Verify fallback was used after error
    assert result["retrieval_method"] == "all_categories_fallback"
    assert result["examples"] == fallback_examples


def test_get_rag_enhanced_examples_no_example_docs():
    """Test when RAG returns results but none are example-related."""
    
    mock_runtime = MagicMock()
    mock_runtime.rag_service = MagicMock()
    
    # Mock RAG results with non-example documents
    mock_runtime.rag_service.search.return_value = [
        {
            "id": "cbc:field_types",
            "text": "Field Type Reference...",
            "metadata": {"section": "field_types"},
            "score": 0.9,
            "retrieval_method": "semantic",
        },
    ]
    
    fallback_examples = {"process_search": [{"query": "test"}]}
    
    # Call with query intent
    result = get_rag_enhanced_examples(
        runtime=mock_runtime,
        query_intent="find something",
        source_filter="cbc",
        fallback_examples=fallback_examples,
        k=10,
    )
    
    # Verify fallback was used when no example docs found
    assert result["retrieval_method"] == "all_categories_fallback"
    assert result["examples"] == fallback_examples


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
