"""
Carbon Black Response (CBR) Query Builder Module

This module provides functionality for building, validating, and executing
queries against Carbon Black Response (CBR) Event Forwarder data.

Components:
- schema_loader: Load and cache CBR field schemas
- query_builder: Build queries from natural language or structured inputs
- validator: Validate queries for syntax, schema compliance, and best practices

Usage:
    from cbr.schema_loader import CBResponseSchemaCache
    from cbr.query_builder import build_cbr_query
    from cbr.validator import CBRValidator
"""

__version__ = "1.0.0"
__author__ = "QueryForge"

# Module exports
__all__ = ['CBResponseSchemaCache', 'normalise_search_type', 'build_cbr_query', 'QueryBuildError']

# Phase 2: Schema Loader ✅ Complete
from .schema_loader import CBResponseSchemaCache, normalise_search_type

# Phase 3: Query Builder ✅ Complete
from .query_builder import build_cbr_query, QueryBuildError

# Phase 4: Validator ✅ Complete
from .validator import CBRValidator
__all__.append('CBRValidator')
