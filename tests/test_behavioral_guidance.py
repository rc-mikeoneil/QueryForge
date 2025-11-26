"""
Tests for Behavioral Detection Guidance System
"""

import pytest
from src.queryforge.shared.behavioral_guidance import BehavioralGuidance


class TestBehavioralGuidance:
    """Test behavioral detection guidance functionality."""
    
    def test_webshell_guidance(self):
        """Test webshell detection guidance."""
        recommendation = BehavioralGuidance.get_recommendation("webshell")
        
        assert recommendation is not None
        assert recommendation.threat_type == "Webshell Detection"
        assert recommendation.recommended_approach == "BEHAVIORAL"
        assert len(recommendation.behavioral_indicators) > 0
        assert len(recommendation.static_indicators) > 0
        
        # Verify behavioral indicators are process-focused
        behavioral_text = " ".join(recommendation.behavioral_indicators).lower()
        assert any(keyword in behavioral_text for keyword in ["process", "spawning", "command"])
    
    def test_analyze_webshell_intent(self):
        """Test intent analysis for webshell queries."""
        intents = [
            "detect webshells on web servers",
            "find web shell compromise",
            "PHP shell detection",
            "web application compromise"
        ]
        
        for intent in intents:
            matches = BehavioralGuidance.analyze_query_intent(intent)
            assert "webshell" in matches, f"Failed to detect webshell intent in: {intent}"
    
    def test_ransomware_guidance(self):
        """Test ransomware detection guidance."""
        recommendation = BehavioralGuidance.get_recommendation("ransomware")
        
        assert recommendation is not None
        assert recommendation.threat_type == "Ransomware Detection"
        assert recommendation.recommended_approach == "BEHAVIORAL"
        
        # Verify behavioral indicators focus on file operations
        behavioral_text = " ".join(recommendation.behavioral_indicators).lower()
        assert any(keyword in behavioral_text for keyword in ["file", "encrypt", "delete"])
    
    def test_lateral_movement_guidance(self):
        """Test lateral movement detection guidance."""
        recommendation = BehavioralGuidance.get_recommendation("lateral_movement")
        
        assert recommendation is not None
        assert recommendation.threat_type == "Lateral Movement Detection"
        
        # Verify behavioral indicators focus on remote execution
        behavioral_text = " ".join(recommendation.behavioral_indicators).lower()
        assert any(keyword in behavioral_text for keyword in ["remote", "execution", "authentication"])
    
    def test_get_guidance_for_intent(self):
        """Test getting all relevant guidance for a complex intent."""
        intent = "detect webshells and lateral movement from compromised web servers"
        
        guidance = BehavioralGuidance.get_guidance_for_intent(intent)
        
        # Should match both webshell and lateral movement
        assert "webshell" in guidance
        assert "lateral_movement" in guidance
        assert len(guidance) >= 2
    
    def test_format_guidance(self):
        """Test formatting of behavioral guidance."""
        recommendation = BehavioralGuidance.get_recommendation("webshell")
        formatted = BehavioralGuidance.format_guidance(recommendation)
        
        # Verify formatted output contains key sections
        assert "BEHAVIORAL DETECTION GUIDANCE" in formatted
        assert "BEHAVIORAL INDICATORS" in formatted
        assert "STATIC INDICATORS" in formatted
        assert "EXAMPLE BEHAVIORAL QUERY" in formatted
        assert "✅" in formatted  # Behavioral indicator marker
        assert "⚠️" in formatted  # Static indicator marker
    
    def test_all_threat_types_have_guidance(self):
        """Test that all defined threat types have complete guidance."""
        threat_types = [
            "webshell", "ransomware", "lateral_movement", 
            "privilege_escalation", "data_exfiltration",
            "persistence", "credential_access", "command_and_control"
        ]
        
        for threat_type in threat_types:
            recommendation = BehavioralGuidance.get_recommendation(threat_type)
            
            assert recommendation is not None, f"No guidance for {threat_type}"
            assert len(recommendation.behavioral_indicators) >= 3, \
                f"{threat_type} needs at least 3 behavioral indicators"
            assert len(recommendation.static_indicators) >= 3, \
                f"{threat_type} needs at least 3 static indicators"
            assert recommendation.example_description, \
                f"{threat_type} needs example description"
            assert "higher fidelity" in recommendation.fidelity_note.lower() or \
                   "catches" in recommendation.fidelity_note.lower() or \
                   "identifies" in recommendation.fidelity_note.lower(), \
                f"{threat_type} needs clear fidelity explanation"
    
    def test_behavioral_vs_static_distinction(self):
        """Test that behavioral and static indicators are properly distinguished."""
        recommendation = BehavioralGuidance.get_recommendation("webshell")
        
        # Behavioral indicators should mention actions/behaviors
        behavioral_keywords = ["spawning", "executing", "connecting", "reading", "creating"]
        behavioral_text = " ".join(recommendation.behavioral_indicators).lower()
        assert any(keyword in behavioral_text for keyword in behavioral_keywords), \
            "Behavioral indicators should describe actions"
        
        # Static indicators should mention artifacts/files
        static_keywords = ["file", "hash", "extension", "directory", "name"]
        static_text = " ".join(recommendation.static_indicators).lower()
        assert any(keyword in static_text for keyword in static_keywords), \
            "Static indicators should describe artifacts"
    
    def test_case_insensitive_lookup(self):
        """Test that threat type lookup is case-insensitive."""
        variations = ["webshell", "Webshell", "WEBSHELL", "WebShell"]
        
        for variation in variations:
            recommendation = BehavioralGuidance.get_recommendation(variation)
            assert recommendation is not None, f"Failed for case: {variation}"
            assert recommendation.threat_type == "Webshell Detection"
    
    def test_intent_analysis_multiple_threats(self):
        """Test intent analysis with multiple threat types in one query."""
        intent = "detect ransomware with credential theft and command and control"
        
        matches = BehavioralGuidance.analyze_query_intent(intent)
        
        assert "ransomware" in matches
        assert "credential_access" in matches
        assert "command_and_control" in matches
        assert len(matches) == 3


def test_webshell_demo():
    """Demonstrate behavioral guidance for webshell detection."""
    print("\n" + "="*80)
    print("BEHAVIORAL GUIDANCE DEMO: Webshell Detection")
    print("="*80)
    
    # Analyze intent
    intent = "detect webshells on web servers"
    print(f"\nQuery Intent: '{intent}'")
    
    guidance = BehavioralGuidance.get_guidance_for_intent(intent)
    
    for threat_type, recommendation in guidance.items():
        formatted = BehavioralGuidance.format_guidance(recommendation)
        print(formatted)


if __name__ == "__main__":
    # Run demo
    test_webshell_demo()
    
    # Run tests
    pytest.main([__file__, "-v"])
