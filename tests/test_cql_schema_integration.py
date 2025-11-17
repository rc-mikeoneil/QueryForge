"""
Test CQL schema integration with schema loader, query builder, and validator.
"""

import unittest
from pathlib import Path

from queryforge.platforms.cql.schema_loader import CQLSchemaLoader
from queryforge.platforms.cql.query_builder import CQLQueryBuilder
from queryforge.platforms.cql.validator import CQLValidator


class TestCQLSchemaIntegration(unittest.TestCase):
    """Test that CQL schemas are properly connected to all components."""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures."""
        cls.schema_loader = CQLSchemaLoader()
        cls.query_builder = CQLQueryBuilder(cls.schema_loader)
        cls.validator = CQLValidator(cls.schema_loader)

    def test_schema_loader_loads_core(self):
        """Test that schema loader can load core schema."""
        core = self.schema_loader.get_core_info()
        self.assertIn("platform", core)
        self.assertEqual(core["platform"]["short_name"], "cql")
        self.assertIn("datasets", core)

    def test_schema_loader_loads_datasets(self):
        """Test that schema loader can load datasets."""
        datasets = self.schema_loader.get_datasets()
        self.assertIn("datasets", datasets)
        self.assertGreater(len(datasets["datasets"]), 0)
        
        # Check for expected datasets
        dataset_names = [d["name"] for d in datasets["datasets"]]
        self.assertIn("events", dataset_names)

    def test_schema_loader_loads_fields(self):
        """Test that schema loader can load fields for a dataset."""
        fields = self.schema_loader.get_fields("events")
        self.assertIn("fields", fields)
        self.assertGreater(len(fields["fields"]), 0)
        
        # Check for common fields
        field_names = [f["name"] for f in fields["fields"]]
        self.assertIn("aid", field_names)
        self.assertIn("ComputerName", field_names)
        self.assertIn("FileName", field_names)

    def test_schema_loader_loads_operators(self):
        """Test that schema loader can load operators."""
        operators = self.schema_loader.get_operators()
        self.assertIn("operators", operators)
        self.assertGreater(len(operators["operators"]), 0)

    def test_schema_loader_loads_best_practices(self):
        """Test that schema loader can load best practices."""
        best_practices = self.schema_loader.get_best_practices()
        self.assertIsInstance(best_practices, list)
        self.assertGreater(len(best_practices), 0)

    def test_schema_loader_loads_examples(self):
        """Test that schema loader can load examples."""
        examples = self.schema_loader.get_examples()
        self.assertIn("examples", examples)
        self.assertGreater(len(examples["examples"]), 0)

    def test_schema_loader_normalizes_operators(self):
        """Test that schema loader can normalize operators."""
        # Test various operator aliases
        self.assertEqual(self.schema_loader.normalize_operator("=="), "=")
        self.assertEqual(self.schema_loader.normalize_operator("equals"), "=")
        self.assertEqual(self.schema_loader.normalize_operator("!="), "!=")
        self.assertEqual(self.schema_loader.normalize_operator("not equals"), "!=")

    def test_schema_loader_validates_field_exists(self):
        """Test field existence validation."""
        # Test valid field
        self.assertTrue(self.schema_loader.validate_field_exists("events", "aid"))
        self.assertTrue(self.schema_loader.validate_field_exists("events", "ComputerName"))
        
        # Test invalid field
        self.assertFalse(self.schema_loader.validate_field_exists("events", "nonexistent_field"))

    def test_schema_loader_gets_field_type(self):
        """Test getting field type."""
        # Test valid fields
        self.assertEqual(self.schema_loader.get_field_type("events", "aid"), "string")
        self.assertEqual(self.schema_loader.get_field_type("events", "TargetProcessId"), "long")
        
        # Test invalid field
        self.assertIsNone(self.schema_loader.get_field_type("events", "nonexistent_field"))

    def test_query_builder_builds_simple_query(self):
        """Test that query builder can build a simple query."""
        result = self.query_builder.build_query(
            dataset="events",
            filters=[{"field": "FileName", "operator": "=", "value": "powershell.exe"}]
        )
        
        self.assertIn("query", result)
        self.assertIn("metadata", result)
        self.assertIn("FileName", result["query"])
        self.assertIn("powershell.exe", result["query"])

    def test_query_builder_uses_schema_for_fields(self):
        """Test that query builder uses schema for field validation."""
        # This should work - valid field
        result = self.query_builder.build_query(
            dataset="events",
            filters=[{"field": "aid", "operator": "=", "value": "test-aid"}]
        )
        self.assertIn("query", result)

    def test_query_builder_handles_natural_language(self):
        """Test that query builder handles natural language intent."""
        result = self.query_builder.build_query(
            natural_language_intent="find powershell processes"
        )
        
        self.assertIn("query", result)
        self.assertIn("metadata", result)

    def test_validator_validates_syntax(self):
        """Test that validator can validate syntax."""
        query = "#event_simpleName=ProcessRollup2 FileName=powershell.exe"
        
        validation = self.validator.validate_syntax(query)
        # Should have no errors for this simple query
        self.assertIsInstance(validation, list)

    def test_validator_validates_schema(self):
        """Test that validator validates against schema."""
        query = "#event_simpleName=ProcessRollup2 FileName=powershell.exe"
        metadata = {
            "dataset": "events",
            "inferred_conditions": [
                {"field": "FileName", "operator": "=", "value": "powershell.exe"}
            ]
        }
        
        issues = self.validator.validate_schema(query, metadata)
        # Should have no errors for valid field
        errors = [i for i in issues if i.severity.name == "ERROR"]
        self.assertEqual(len(errors), 0)

    def test_validator_detects_invalid_field(self):
        """Test that validator detects invalid fields."""
        query = "#event_simpleName=ProcessRollup2 InvalidField=value"
        metadata = {
            "dataset": "events",
            "inferred_conditions": [
                {"field": "InvalidField", "operator": "=", "value": "value"}
            ]
        }
        
        issues = self.validator.validate_schema(query, metadata)
        # Should have errors for invalid field
        errors = [i for i in issues if i.severity.name == "ERROR"]
        self.assertGreater(len(errors), 0)

    def test_validator_validates_operators(self):
        """Test that validator validates operators."""
        query = "#event_simpleName=ProcessRollup2 FileName=powershell.exe"
        metadata = {
            "dataset": "events",
            "inferred_conditions": [
                {"field": "FileName", "operator": "=", "value": "powershell.exe"}
            ]
        }
        
        issues = self.validator.validate_operators(query, metadata)
        # Should have no errors for valid operator
        errors = [i for i in issues if i.severity.name == "ERROR"]
        self.assertEqual(len(errors), 0)

    def test_validator_full_validation(self):
        """Test full validation workflow."""
        query = "#event_simpleName=ProcessRollup2 FileName=powershell.exe | groupBy([ComputerName])"
        metadata = {
            "dataset": "events",
            "inferred_conditions": [
                {"field": "FileName", "operator": "=", "value": "powershell.exe"}
            ],
            "conditions_count": 1
        }
        
        result = self.validator.validate(query, "events", metadata)
        
        self.assertIn("valid", result)
        self.assertIn("validation_results", result)
        self.assertIsInstance(result["valid"], bool)

    def test_end_to_end_workflow(self):
        """Test complete end-to-end workflow: build -> validate."""
        # Build query
        build_result = self.query_builder.build_query(
            dataset="events",
            filters=[{"field": "FileName", "operator": "=", "value": "cmd.exe"}],
            limit=100
        )
        
        self.assertIn("query", build_result)
        self.assertIn("metadata", build_result)
        
        # Validate query
        validation_result = self.validator.validate(
            build_result["query"],
            build_result["metadata"].get("dataset"),
            build_result["metadata"]
        )
        
        self.assertIn("valid", validation_result)
        self.assertIn("validation_results", validation_result)
        
        # Query should be valid
        self.assertTrue(validation_result["valid"])


if __name__ == "__main__":
    unittest.main()
