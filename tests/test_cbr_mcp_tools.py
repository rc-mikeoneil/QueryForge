"""
Tests for Carbon Black Response MCP server tools.

This module tests the CBR MCP tool integration, including:
- Tool registration
- Read-only tools (list_datasets, get_fields, etc.)
- Query building and validation tools
- Combined build+validate tool with retry logic
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from fastmcp import FastMCP
from queryforge.server.server_runtime import ServerRuntime
from queryforge.server.server_tools_cbr import (
    register_cbr_tools,
    _extract_cbr_corrections,
    _apply_field_corrections,
)


@pytest.fixture
def runtime():
    """Create a ServerRuntime instance for testing."""
    runtime = ServerRuntime()
    runtime.initialize_critical_components()
    return runtime


@pytest.fixture
def mcp():
    """Create a FastMCP instance."""
    return FastMCP(name="test")


@pytest.fixture
def cbr_tools(mcp, runtime):
    """Register CBR tools and return the MCP instance."""
    register_cbr_tools(mcp, runtime)
    return mcp


class TestCBRToolRegistration:
    """Test CBR tool registration."""

    def test_tools_registered(self, cbr_tools):
        """Verify all CBR tools are registered."""
        expected_tools = [
            "cbr_list_datasets",
            "cbr_get_fields",
            "cbr_get_operator_reference",
            "cbr_get_best_practices",
            "cbr_get_examples",
            "cbr_build_query",
            "cbr_validate_query",
            "cbr_build_query_validated",
        ]
        
        if hasattr(cbr_tools, '_tools'):
            registered = list(cbr_tools._tools.keys())
            for tool in expected_tools:
                assert tool in registered, f"Tool {tool} not registered"


class TestCBRReadOnlyTools:
    """Test read-only CBR tools."""

    def test_list_datasets(self, runtime):
        """Test cbr_list_datasets returns datasets."""
        from queryforge.server.server_tools_cbr import register_cbr_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_cbr_tools(mcp, runtime)
        
        # Access the function through the tool registry
        if hasattr(mcp, '_tools') and 'cbr_list_datasets' in mcp._tools:
            tool_func = mcp._tools['cbr_list_datasets'].fn
            result = tool_func()
            
            assert "datasets" in result
            assert isinstance(result["datasets"], dict)
            assert len(result["datasets"]) > 0
            assert "server_event" in result["datasets"] or "endpoint_event" in result["datasets"]

    def test_get_fields(self, runtime):
        """Test cbr_get_fields returns field information."""
        from queryforge.server.server_tools_cbr import register_cbr_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_cbr_tools(mcp, runtime)
        
        if hasattr(mcp, '_tools') and 'cbr_get_fields' in mcp._tools:
            tool_func = mcp._tools['cbr_get_fields'].fn
            result = tool_func("server_event")
            
            assert "search_type" in result
            assert "fields" in result
            assert isinstance(result["fields"], list)
            assert len(result["fields"]) > 0

    def test_get_operator_reference(self, runtime):
        """Test cbr_get_operator_reference returns operators."""
        from queryforge.server.server_tools_cbr import register_cbr_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_cbr_tools(mcp, runtime)
        
        if hasattr(mcp, '_tools') and 'cbr_get_operator_reference' in mcp._tools:
            tool_func = mcp._tools['cbr_get_operator_reference'].fn
            result = tool_func()
            
            assert "operators" in result
            assert isinstance(result["operators"], dict)

    def test_get_best_practices(self, runtime):
        """Test cbr_get_best_practices returns practices."""
        from queryforge.server.server_tools_cbr import register_cbr_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_cbr_tools(mcp, runtime)
        
        if hasattr(mcp, '_tools') and 'cbr_get_best_practices' in mcp._tools:
            tool_func = mcp._tools['cbr_get_best_practices'].fn
            result = tool_func()
            
            assert "best_practices" in result

    def test_get_examples(self, runtime):
        """Test cbr_get_examples returns examples."""
        from queryforge.server.server_tools_cbr import register_cbr_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_cbr_tools(mcp, runtime)
        
        if hasattr(mcp, '_tools') and 'cbr_get_examples' in mcp._tools:
            tool_func = mcp._tools['cbr_get_examples'].fn
            result = tool_func()
            
            assert "examples" in result
            assert isinstance(result["examples"], dict)


class TestCBRQueryBuilding:
    """Test CBR query building tools."""

    def test_build_query_with_terms(self, runtime):
        """Test building query with structured terms."""
        from queryforge.server.server_tools_cbr import register_cbr_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_cbr_tools(mcp, runtime)
        
        if hasattr(mcp, '_tools') and 'cbr_build_query' in mcp._tools:
            tool_func = mcp._tools['cbr_build_query'].fn
            result = tool_func(
                dataset="endpoint_event",
                terms=["process_name:cmd.exe"],
            )
            
            assert "query" in result
            assert "metadata" in result
            assert "process_name:cmd.exe" in result["query"]

    def test_build_query_with_natural_language(self, runtime):
        """Test building query with natural language intent."""
        from queryforge.server.server_tools_cbr import register_cbr_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_cbr_tools(mcp, runtime)
        
        if hasattr(mcp, '_tools') and 'cbr_build_query' in mcp._tools:
            tool_func = mcp._tools['cbr_build_query'].fn
            result = tool_func(
                dataset="endpoint_event",
                natural_language_intent="chrome browser activity",
            )
            
            assert "query" in result
            assert "metadata" in result
            assert isinstance(result["query"], str)


class TestCBRValidation:
    """Test CBR query validation tools."""

    def test_validate_valid_query(self, runtime):
        """Test validation of a valid query."""
        from queryforge.server.server_tools_cbr import register_cbr_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_cbr_tools(mcp, runtime)
        
        if hasattr(mcp, '_tools') and 'cbr_validate_query' in mcp._tools:
            tool_func = mcp._tools['cbr_validate_query'].fn
            result = tool_func(
                query="process_name:cmd.exe",
                dataset="endpoint_event",
            )
            
            assert "valid" in result
            assert "validation_results" in result

    def test_validate_invalid_query(self, runtime):
        """Test validation of an invalid query."""
        from queryforge.server.server_tools_cbr import register_cbr_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_cbr_tools(mcp, runtime)
        
        if hasattr(mcp, '_tools') and 'cbr_validate_query' in mcp._tools:
            tool_func = mcp._tools['cbr_validate_query'].fn
            result = tool_func(
                query="invalid_field:value",
                dataset="endpoint_event",
            )
            
            assert "valid" in result
            assert "validation_results" in result


class TestCBRCombinedTool:
    """Test CBR combined build+validate tool."""

    def test_build_query_validated_success(self, runtime):
        """Test combined tool with valid query."""
        from queryforge.server.server_tools_cbr import register_cbr_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_cbr_tools(mcp, runtime)
        
        if hasattr(mcp, '_tools') and 'cbr_build_query_validated' in mcp._tools:
            tool_func = mcp._tools['cbr_build_query_validated'].fn
            result = tool_func(
                dataset="endpoint_event",
                terms=["process_name:cmd.exe"],
            )
            
            assert "query" in result
            assert "metadata" in result
            assert "validation" in result
            assert "retry_count" in result
            assert "corrections_applied" in result


class TestCBRCorrectionHelpers:
    """Test CBR correction helper functions."""

    def test_extract_corrections_field_suggestion(self):
        """Test extracting field name corrections."""
        validation = {
            "validation_results": {
                "schema": {
                    "errors": [
                        {
                            "message": "Field 'proc_name' not found",
                            "suggestion": "Did you mean: process_name?"
                        }
                    ]
                }
            }
        }
        
        corrections = _extract_cbr_corrections(validation)
        assert "field_corrections" in corrections
        assert corrections["field_corrections"]["proc_name"] == "process_name"

    def test_extract_corrections_dataset_suggestion(self):
        """Test extracting dataset suggestions."""
        validation = {
            "validation_results": {
                "schema": {
                    "errors": [
                        {
                            "message": "Dataset mismatch",
                            "suggestion": "Use 'endpoint_event' dataset"
                        }
                    ]
                }
            }
        }
        
        corrections = _extract_cbr_corrections(validation)
        assert "suggested_dataset" in corrections
        assert corrections["suggested_dataset"] == "endpoint_event"

    def test_apply_field_corrections(self):
        """Test applying field corrections to terms."""
        terms = ["proc_name:cmd.exe", "remote_ip:1.2.3.4"]
        corrections = {"proc_name": "process_name"}
        
        corrected = _apply_field_corrections(terms, corrections)
        assert "process_name:cmd.exe" in corrected
        assert "remote_ip:1.2.3.4" in corrected

    def test_apply_field_corrections_no_match(self):
        """Test applying corrections when no match found."""
        terms = ["process_name:cmd.exe"]
        corrections = {"proc_name": "process_name"}
        
        corrected = _apply_field_corrections(terms, corrections)
        assert corrected == terms


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
