"""
Behavioral Detection Guidance System

This module provides behavioral detection recommendations for security queries.
It helps ensure queries focus on detecting threat behaviors rather than just
static indicators.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class BehavioralRecommendation:
    """Represents a behavioral detection recommendation."""
    
    threat_type: str
    behavioral_indicators: List[str]
    static_indicators: List[str]
    recommended_approach: str
    example_description: str
    fidelity_note: str


class BehavioralGuidance:
    """Provides behavioral detection guidance for security queries."""
    
    # Common threat patterns with behavioral recommendations
    THREAT_PATTERNS = {
        "webshell": BehavioralRecommendation(
            threat_type="Webshell Detection",
            behavioral_indicators=[
                "Web server process spawning command shells (cmd.exe, powershell.exe, bash, sh)",
                "Web application process executing system commands",
                "Unusual child processes from web server parent (w3wp.exe, httpd, nginx, tomcat)",
                "Web server connecting to external network locations",
                "Web server reading sensitive files outside web directories"
            ],
            static_indicators=[
                "Files with .php, .jsp, .asp, .aspx extensions in web directories",
                "Files in /var/www/html, wwwroot, htdocs directories",
                "Known webshell file hashes",
                "Suspicious file names (shell.php, cmd.jsp, etc.)"
            ],
            recommended_approach="BEHAVIORAL",
            example_description="src.process.parent.name in ('w3wp.exe', 'httpd', 'nginx') AND src.process.name in ('cmd.exe', 'bash', 'powershell.exe')",
            fidelity_note="Behavioral detection has HIGHER fidelity - catches active exploitation regardless of file name or location"
        ),
        
        "ransomware": BehavioralRecommendation(
            threat_type="Ransomware Detection",
            behavioral_indicators=[
                "Process creating/modifying large numbers of files rapidly",
                "Process deleting shadow copies or backups",
                "Process encrypting files (high entropy file creation)",
                "Process dropping ransom notes (.txt, .html files)",
                "Unusual file extension changes across many files",
                "Process accessing many file types sequentially"
            ],
            static_indicators=[
                "Files with .encrypted, .locked, .crypted extensions",
                "Presence of ransom note files (README.txt, HOW_TO_DECRYPT.html)",
                "Known ransomware executable hashes",
                "Specific ransomware family file markers"
            ],
            recommended_approach="BEHAVIORAL",
            example_description="High file modification rate + file deletion + entropy changes + ransom note creation",
            fidelity_note="Behavioral detection catches ransomware during execution, before significant damage occurs"
        ),
        
        "lateral_movement": BehavioralRecommendation(
            threat_type="Lateral Movement Detection",
            behavioral_indicators=[
                "Remote process creation (psexec, wmic, winrm patterns)",
                "Authentication followed by process creation on remote host",
                "SMB connections followed by service creation",
                "Remote scheduled task creation",
                "Pass-the-hash authentication patterns",
                "Unusual remote desktop connections"
            ],
            static_indicators=[
                "Presence of psexec.exe, wmic.exe on disk",
                "Known lateral movement tool hashes",
                "Suspicious executables in admin shares",
                "Known credential dumping tool artifacts"
            ],
            recommended_approach="BEHAVIORAL",
            example_description="Network authentication + remote service creation + new process execution within short timeframe",
            fidelity_note="Behavioral detection identifies lateral movement technique regardless of specific tool used"
        ),
        
        "privilege_escalation": BehavioralRecommendation(
            threat_type="Privilege Escalation Detection",
            behavioral_indicators=[
                "Process spawning with higher privileges than parent",
                "Token manipulation or impersonation",
                "Exploitation of vulnerable services/drivers",
                "SeDebugPrivilege or SeImpersonatePrivilege usage",
                "Process injection into privileged processes",
                "Unusual parent-child process relationships with privilege changes"
            ],
            static_indicators=[
                "Known exploit executable hashes",
                "Vulnerable driver files present",
                "Known privilege escalation tool names",
                "Suspicious DLL files in system directories"
            ],
            recommended_approach="BEHAVIORAL",
            example_description="Low-privilege process → creates high-privilege child process OR process injection into SYSTEM process",
            fidelity_note="Behavioral detection catches privilege escalation regardless of exploitation method"
        ),
        
        "data_exfiltration": BehavioralRecommendation(
            threat_type="Data Exfiltration Detection",
            behavioral_indicators=[
                "Large file transfers to external IPs",
                "Compressed archives created and immediately transferred",
                "Access to multiple sensitive file locations followed by network activity",
                "Unusual upload patterns (size, frequency, destination)",
                "Cloud storage sync from unusual processes",
                "Database dumps followed by external transfers"
            ],
            static_indicators=[
                "Large .zip, .rar, .7z files in temp directories",
                "Presence of known exfiltration tools",
                "Specific file extensions being collected",
                "Known C2 infrastructure IP addresses"
            ],
            recommended_approach="BEHAVIORAL",
            example_description="Process accesses sensitive files + creates archive + network upload to external destination",
            fidelity_note="Behavioral detection identifies data theft patterns regardless of tool or destination"
        ),
        
        "persistence": BehavioralRecommendation(
            threat_type="Persistence Mechanism Detection",
            behavioral_indicators=[
                "Registry Run key modifications",
                "Scheduled task creation by unusual processes",
                "Service creation or modification",
                "WMI event subscription creation",
                "Startup folder modifications",
                "DLL hijacking via file placement + process load patterns"
            ],
            static_indicators=[
                "Suspicious files in startup directories",
                "Known malware file hashes in auto-run locations",
                "Specific registry key values",
                "Suspicious scheduled task files"
            ],
            recommended_approach="BEHAVIORAL",
            example_description="Suspicious process creates registry Run key OR scheduled task OR service pointing to executable",
            fidelity_note="Behavioral detection catches persistence attempts regardless of specific technique variant"
        ),
        
        "credential_access": BehavioralRecommendation(
            threat_type="Credential Access Detection",
            behavioral_indicators=[
                "Process accessing LSASS memory",
                "Reads of SAM/SECURITY registry hives",
                "NTDS.dit file access patterns",
                "Registry key access for credential stores",
                "Browser process memory access by unusual processes",
                "Kerberos ticket extraction patterns"
            ],
            static_indicators=[
                "Known credential dumping tool hashes (mimikatz, etc.)",
                "Suspicious executables with credential-related names",
                "Dumped credential files (*.dmp, *.kirbi)",
                "Known tool artifacts on disk"
            ],
            recommended_approach="BEHAVIORAL",
            example_description="Unusual process reads LSASS memory OR accesses SAM hive OR extracts password files",
            fidelity_note="Behavioral detection identifies credential theft regardless of specific tool or technique"
        ),
        
        "command_and_control": BehavioralRecommendation(
            threat_type="Command & Control Detection",
            behavioral_indicators=[
                "Beaconing network traffic patterns (regular intervals)",
                "Process making periodic external connections",
                "Unusual process with persistent network connections",
                "DNS tunneling patterns (long queries, high volume)",
                "Encoded/encrypted traffic from unexpected processes",
                "Multiple failed connections followed by success pattern"
            ],
            static_indicators=[
                "Connections to known C2 IP addresses",
                "Known C2 tool hashes",
                "Suspicious domains in network logs",
                "Specific user-agent strings"
            ],
            recommended_approach="BEHAVIORAL",
            example_description="Process establishes persistent connection with regular beacon intervals to external IP",
            fidelity_note="Behavioral detection identifies C2 communication patterns regardless of infrastructure"
        )
    }
    
    @classmethod
    def get_recommendation(cls, threat_type: str) -> Optional[BehavioralRecommendation]:
        """
        Get behavioral detection recommendation for a threat type.
        
        Args:
            threat_type: Type of threat (e.g., 'webshell', 'ransomware')
            
        Returns:
            BehavioralRecommendation if found, None otherwise
        """
        return cls.THREAT_PATTERNS.get(threat_type.lower())
    
    @classmethod
    def analyze_query_intent(cls, intent: str) -> List[str]:
        """
        Analyze natural language intent to identify relevant threat types.
        
        Args:
            intent: Natural language query description
            
        Returns:
            List of matching threat type keys
        """
        intent_lower = intent.lower()
        matches = []
        
        # Keyword matching for threat types
        threat_keywords = {
            "webshell": ["webshell", "web shell", "web application compromise", "php shell", "jsp shell", "asp shell"],
            "ransomware": ["ransomware", "encryption", "ransom", "crypto", "locked files"],
            "lateral_movement": ["lateral movement", "lateral", "psexec", "remote execution", "remote process", "wmi"],
            "privilege_escalation": ["privilege escalation", "elevation", "admin rights", "system privileges", "UAC bypass"],
            "data_exfiltration": ["exfiltration", "data theft", "data leak", "file transfer", "upload", "exfil"],
            "persistence": ["persistence", "auto-run", "startup", "scheduled task", "registry run", "service creation"],
            "credential_access": ["credential", "password", "lsass", "mimikatz", "password dump", "credential theft"],
            "command_and_control": ["c2", "command and control", "beacon", "callback", "c&c", "remote control"]
        }
        
        for threat_type, keywords in threat_keywords.items():
            if any(keyword in intent_lower for keyword in keywords):
                matches.append(threat_type)
        
        return matches
    
    @classmethod
    def get_guidance_for_intent(cls, intent: str) -> Dict[str, BehavioralRecommendation]:
        """
        Get all relevant behavioral recommendations for a natural language intent.
        
        Args:
            intent: Natural language query description
            
        Returns:
            Dictionary mapping threat types to recommendations
        """
        matching_threats = cls.analyze_query_intent(intent)
        
        guidance = {}
        for threat_type in matching_threats:
            recommendation = cls.get_recommendation(threat_type)
            if recommendation:
                guidance[threat_type] = recommendation
        
        return guidance
    
    @classmethod
    def format_guidance(cls, recommendation: BehavioralRecommendation) -> str:
        """
        Format a behavioral recommendation as readable text.
        
        Args:
            recommendation: BehavioralRecommendation to format
            
        Returns:
            Formatted guidance string
        """
        output = [
            f"\n{'='*80}",
            f"BEHAVIORAL DETECTION GUIDANCE: {recommendation.threat_type}",
            f"{'='*80}\n",
            f"RECOMMENDED APPROACH: {recommendation.recommended_approach}\n",
            f"WHY: {recommendation.fidelity_note}\n",
            "\nBEHAVIORAL INDICATORS (Preferred - High Fidelity):",
        ]
        
        for indicator in recommendation.behavioral_indicators:
            output.append(f"  ✅ {indicator}")
        
        output.append("\nSTATIC INDICATORS (Supplementary - Lower Fidelity):")
        for indicator in recommendation.static_indicators:
            output.append(f"  ⚠️  {indicator}")
        
        output.append(f"\nEXAMPLE BEHAVIORAL QUERY:")
        output.append(f"  {recommendation.example_description}\n")
        output.append("="*80 + "\n")
        
        return "\n".join(output)
