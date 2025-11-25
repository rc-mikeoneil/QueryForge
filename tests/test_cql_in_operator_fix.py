"""
Test for CQL IN operator validation fix.

This test verifies that the validator correctly:
1. Rejects SQL-style IN syntax (error)
2. Accepts CQL in() function syntax (valid)
3. Warns about unquoted string values in in() functions
"""

import pytest
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from queryforge.platforms.cql.schema_loader import CQLSchemaLoader
from queryforge.platforms.cql.validator import CQLValidator


@pytest.fixture
def schema_loader():
    """Create a CQL schema loader for testing."""
    schema_dir = Path(__file__).parent.parent / "src" / "queryforge" / "platforms" / "cql" / "cql_schemas"
    return CQLSchemaLoader(schema_dir=schema_dir)


@pytest.fixture
def validator(schema_loader):
    """Create a CQL validator for testing."""
    return CQLValidator(schema_loader)


class TestCQLInOperatorFix:
    """Test suite for CQL IN operator validation fix."""

    def test_sql_style_in_rejected(self, validator):
        """Test that SQL-style IN syntax is rejected with an error."""
        query = "#event_simpleName=ProcessRollup2 LogonType IN (2,10)"
        metadata = {"dataset": "events"}
        
        result = validator.validate(query, metadata=metadata)
        
        # Should have syntax errors
        assert not result["valid"], "Query should be invalid"
        assert len(result["validation_results"]["syntax"]["errors"]) > 0, "Should have syntax errors"
        
        # Check for specific error message about SQL-style IN
        syntax_errors = result["validation_results"]["syntax"]["errors"]
        sql_in_error = any("SQL-style 'IN' syntax" in err["message"] for err in syntax_errors)
        assert sql_in_error, "Should have error about SQL-style IN syntax"
        
        # Check suggestion mentions in() function
        sql_in_suggestion = any("in(LogonType, values=" in err["suggestion"] for err in syntax_errors)
        assert sql_in_suggestion, "Should suggest using in() function"

    def test_cql_in_function_with_numbers_accepted(self, validator):
        """Test that CQL in() function with numeric values is accepted."""
        query = "#event_simpleName=ProcessRollup2 in(LogonType, values=[2,10]) | limit 100"
        metadata = {"dataset": "events"}
        
        result = validator.validate(query, metadata=metadata)
        
        # Should have no syntax errors related to in()
        syntax_errors = result["validation_results"]["syntax"]["errors"]
        in_errors = [err for err in syntax_errors if "in()" in err["message"].lower()]
        assert len(in_errors) == 0, "Should have no errors about in() function syntax"

    def test_cql_in_function_with_quoted_strings_accepted(self, validator):
        """Test that CQL in() function with quoted string values is accepted."""
        queries = [
            'in(ImageFileName, values=["cmd.exe","powershell.exe"])',
            "in(LogonDomain, values=['acme.com','beta.com'])",
        ]
        
        for query_snippet in queries:
            query = f"#event_simpleName=ProcessRollup2 {query_snippet} | limit 100"
            metadata = {"dataset": "events"}
            
            result = validator.validate(query, metadata=metadata)
            
            # Should have no syntax errors about unquoted values
            syntax_warnings = result["validation_results"]["syntax"]["warnings"]
            unquoted_warnings = [w for w in syntax_warnings if "unquoted" in w["message"].lower()]
            assert len(unquoted_warnings) == 0, f"Should have no warnings about unquoted values for: {query_snippet}"

    def test_cql_in_function_with_unquoted_strings_warned(self, validator):
        """Test that CQL in() function with unquoted string values generates a warning."""
        query = "#event_simpleName=ProcessRollup2 in(ImageFileName, values=[cmd.exe, powershell.exe]) | limit 100"
        metadata = {"dataset": "events"}
        
        result = validator.validate(query, metadata=metadata)
        
        # Should have warning about unquoted values
        syntax_warnings = result["validation_results"]["syntax"]["warnings"]
        unquoted_warning = any("unquoted string value" in w["message"].lower() for w in syntax_warnings)
        assert unquoted_warning, "Should have warning about unquoted string values"

    def test_multiple_sql_style_in_all_rejected(self, validator):
        """Test that multiple SQL-style IN clauses are all caught."""
        query = "#event_simpleName=ProcessRollup2 LogonType IN (2,10) OR ImageFileName IN ('cmd.exe','powershell.exe')"
        metadata = {"dataset": "events"}
        
        result = validator.validate(query, metadata=metadata)
        
        # Should have errors for both SQL-style IN usages
        syntax_errors = result["validation_results"]["syntax"]["errors"]
        sql_in_errors = [err for err in syntax_errors if "SQL-style 'IN' syntax" in err["message"]]
        assert len(sql_in_errors) == 2, "Should have errors for both SQL-style IN usages"

    def test_complex_query_with_valid_cql_in(self, validator):
        """Test a complex query with valid CQL in() function."""
        query = """#event_simpleName=ProcessRollup2 
in(FileName, values=["certutil.exe", "bitsadmin.exe", "mshta.exe"]) 
AND NOT in(LogonType, values=[2,3]) 
| groupBy([ComputerName, FileName]) 
| limit 1000"""
        metadata = {"dataset": "events"}
        
        result = validator.validate(query, metadata=metadata)
        
        # Should have no syntax errors about in() function
        syntax_errors = result["validation_results"]["syntax"]["errors"]
        in_errors = [err for err in syntax_errors if "in()" in err["message"].lower() or "SQL-style" in err["message"]]
        assert len(in_errors) == 0, "Should have no errors about in() function for valid usage"

    def test_case_insensitive_sql_in_detection(self, validator):
        """Test that SQL-style IN is detected case-insensitively."""
        queries = [
            "#event_simpleName=ProcessRollup2 LogonType IN (2,10)",
            "#event_simpleName=ProcessRollup2 LogonType in (2,10)",
            "#event_simpleName=ProcessRollup2 LogonType In (2,10)",
        ]
        
        for query in queries:
            metadata = {"dataset": "events"}
            result = validator.validate(query, metadata=metadata)
            
            # Should detect SQL-style IN regardless of case
            syntax_errors = result["validation_results"]["syntax"]["errors"]
            sql_in_error = any("SQL-style 'IN' syntax" in err["message"] for err in syntax_errors)
            assert sql_in_error, f"Should detect SQL-style IN in: {query}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
