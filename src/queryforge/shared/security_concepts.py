"""
Security Concepts Dictionary - Platform-Agnostic Security Indicator Mappings

This module provides semantic mappings from common security concepts to their
detection indicators across multiple EDR/XDR platforms. It enables automatic
query expansion when users reference security concepts in natural language.

Usage:
    from shared.security_concepts import expand_security_concept

    indicators = expand_security_concept("rdp", platform="cbc")
    # Returns: {"processes": [...], "ports": [...], "cmdline_patterns": [...]}

Design Principles:
    - Platform-agnostic concept definitions with platform-specific mappings
    - No hardcoded query logic - only indicator mappings
    - Extensible for new concepts and platforms
    - Compatible with existing query builders via keyword hints
"""

from typing import Dict, List, Optional, Set


# Platform-agnostic security concept definitions
SECURITY_CONCEPTS = {
    "rdp": {
        "description": "Remote Desktop Protocol detection",
        "keywords": ["rdp", "remote desktop", "mstsc", "terminal services"],
        "indicators": {
            "processes": ["mstsc.exe", "rdpclip.exe", "rdpinit.exe", "termsrv.dll"],
            "ports": [3389, 3388],
            "cmdline_patterns": ["mstsc", "/v:", "/admin"],
            "domain_patterns": ["rdp", "remote"],
        }
    },
    "smb": {
        "description": "SMB-based lateral movement and file sharing",
        "keywords": ["smb", "lateral movement", "admin share", "psexec"],
        "indicators": {
            "processes": ["net.exe", "net1.exe", "psexec.exe", "paexec.exe"],
            "ports": [445, 139],
            "cmdline_patterns": ["\\\\admin$", "\\\\c$", "net use", "net share"],
            "share_patterns": ["\\\\\\\\"],
        }
    },
    "powershell": {
        "description": "PowerShell execution with common evasion patterns",
        "keywords": ["powershell", "pwsh", "ps1", "encoded command"],
        "indicators": {
            "processes": ["powershell.exe", "pwsh.exe", "powershell_ise.exe"],
            "cmdline_patterns": [
                "-enc", "-encodedcommand", "-w hidden", "-windowstyle hidden",
                "-nop", "-noprofile", "-ep bypass", "-executionpolicy bypass",
                "invoke-expression", "iex", "downloadstring", "downloadfile"
            ],
        }
    },
    "wmi": {
        "description": "Windows Management Instrumentation execution",
        "keywords": ["wmi", "wmic", "wmiprvse"],
        "indicators": {
            "processes": ["wmic.exe", "wmiprvse.exe", "scrcons.exe"],
            "cmdline_patterns": ["wmic", "/node:", "process call create"],
        }
    },
    "credential_dumping": {
        "description": "Credential harvesting and LSASS access",
        "keywords": ["credential dump", "mimikatz", "lsass", "procdump"],
        "indicators": {
            "processes": ["mimikatz.exe", "procdump.exe", "sqldumper.exe"],
            "cmdline_patterns": ["sekurlsa", "lsass", "procdump", "comsvcs.dll", "minidump"],
            "target_processes": ["lsass.exe"],
            "registry_paths": ["\\sam\\", "\\security\\"],
        }
    },
    "webshell": {
        "description": "Web shell detection via web server child processes",
        "keywords": ["webshell", "web shell", "backdoor"],
        "indicators": {
            "parent_processes": ["w3wp.exe", "httpd.exe", "nginx.exe", "apache.exe", "tomcat.exe"],
            "child_processes": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "net.exe", "whoami.exe", "ipconfig.exe", "ping.exe"],
        }
    },
    "scheduled_task": {
        "description": "Scheduled task creation for persistence",
        "keywords": ["scheduled task", "schtasks", "persistence"],
        "indicators": {
            "processes": ["schtasks.exe", "at.exe"],
            "cmdline_patterns": ["schtasks", "/create", "New-ScheduledTask", "Register-ScheduledTask"],
        }
    },
    "service_creation": {
        "description": "Windows service creation and modification",
        "keywords": ["service", "sc.exe", "new-service"],
        "indicators": {
            "processes": ["sc.exe"],
            "cmdline_patterns": ["create", "config", "New-Service", "Set-Service"],
            "registry_paths": ["\\system\\currentcontrolset\\services\\"],
        }
    },
    "registry_persistence": {
        "description": "Registry Run key persistence mechanisms",
        "keywords": ["registry", "run key", "autorun", "persistence"],
        "indicators": {
            "registry_paths": [
                "\\Microsoft\\Windows\\CurrentVersion\\Run",
                "\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
                "\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell"
            ],
        }
    },
    "lolbins": {
        "description": "Living Off the Land Binaries abuse",
        "keywords": ["lolbin", "lolbas", "living off the land"],
        "indicators": {
            "processes": [
                "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
                "msiexec.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
                "msxsl.exe", "odbcconf.exe", "forfiles.exe", "pcalua.exe"
            ],
            "cmdline_patterns": ["javascript:", "vbscript:", "/i:http", "-decode"],
        }
    },
    "file_download": {
        "description": "Suspicious file downloads from internet",
        "keywords": ["download", "wget", "curl", "downloadfile"],
        "indicators": {
            "processes": [
                "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"
            ],
            "cmdline_patterns": [
                "http://", "https://", "ftp://", "downloadfile", "downloadstring",
                "invoke-webrequest", "wget", "curl", "-decode", "bitstransfer"
            ],
        }
    },
    "process_injection": {
        "description": "Process injection techniques",
        "keywords": ["process injection", "code injection", "dll injection"],
        "indicators": {
            "cmdline_patterns": ["virtualalloc", "writeprocessmemory", "createremotethread", "ntcreatethreadex"],
            "behaviors": ["cross_process_injection", "remote_thread", "process_hollowing"],
        }
    },
    "uac_bypass": {
        "description": "User Account Control bypass techniques",
        "keywords": ["uac bypass", "privilege escalation"],
        "indicators": {
            "cmdline_patterns": ["eventvwr.exe", "fodhelper.exe", "computerdefaults.exe"],
            "processes": ["dism.exe"],
        }
    },
    "network_scanning": {
        "description": "Network scanning and reconnaissance",
        "keywords": ["port scan", "network scan", "nmap", "reconnaissance"],
        "indicators": {
            "processes": ["nmap.exe", "masscan.exe", "angry_ip_scanner.exe", "advanced_port_scanner.exe"],
            "behaviors": ["high_connection_rate"],
        }
    },
    "data_exfiltration": {
        "description": "Data exfiltration via file transfers",
        "keywords": ["exfiltration", "data theft", "file transfer"],
        "indicators": {
            "ports": [21, 22, 69, 873],
            "cmdline_patterns": ["copy", "xcopy", "robocopy"],
            "domain_patterns": ["ftp", "sftp"],
        }
    },
}


# Platform-specific field name mappings
PLATFORM_FIELD_MAPPINGS = {
    "cbc": {
        "process": "process_name",
        "parent_process": "parent_name",
        "child_process": "childproc_name",
        "cmdline": "process_cmdline",
        "port": "netconn_port",
        "domain": "netconn_domain",
        "registry": "regmod_name",
        "module": "modload_name",
        "target_process": "process_name",
    },
    "cortex": {
        "process": "actor_process_image_name",
        "parent_process": "causality_actor_process_image_name",
        "child_process": "actor_process_image_name",
        "cmdline": "actor_process_command_line",
        "port_local": "action_local_port",
        "port_remote": "action_remote_port",
        "domain": "dst_action_external_hostname",
        "registry": "action_registry_key_name",
        "target_process": "action_process_image_name",
    },
    "kql": {
        "process": "FileName",
        "parent_process": "InitiatingProcessFileName",
        "child_process": "FileName",
        "cmdline": "ProcessCommandLine",
        "port_local": "LocalPort",
        "port_remote": "RemotePort",
        "domain": "RemoteUrl",
        "registry": "RegistryKey",
        "target_process": "FileName",
    },
    "s1": {
        "process": "SrcProcName",
        "parent_process": "SrcProcParentName",
        "child_process": "TgtProcName",
        "cmdline": "SrcProcCmdLine",
        "port_local": "TgtProcNetConnLocalPort",
        "port_remote": "TgtProcNetConnRemotePort",
        "domain": "TgtProcNetConnRemoteDomain",
        "registry": "TgtProcRegistryKeyPath",
        "target_process": "TgtProcName",
    },
    "cql": {
        "process": "process_name",
        "parent_process": "parent_process_name",
        "child_process": "process_name",
        "cmdline": "command_line",
        "port_local": "source_port",
        "port_remote": "destination_port",
        "domain": "http_host",
        "registry": "registry_key",
        "target_process": "process_name",
        "file": "file_path",
        "hash": "file_hash",
        "user": "user_name",
        "ip": "source_ip",
        "remote_ip": "destination_ip",
    },
}


def detect_security_concepts(intent: str) -> Set[str]:
    """
    Detect security concepts mentioned in natural language intent.

    Args:
        intent: Natural language query intent

    Returns:
        Set of detected security concept IDs
    """
    if not intent:
        return set()

    intent_lower = intent.lower()
    detected = set()

    for concept_id, concept_data in SECURITY_CONCEPTS.items():
        keywords = concept_data.get("keywords", [])
        for keyword in keywords:
            if keyword.lower() in intent_lower:
                detected.add(concept_id)
                break

    return detected


def expand_security_concept(
    concept_id: str,
    platform: str,
    include_descriptions: bool = False
) -> Dict[str, List[str]]:
    """
    Expand a security concept into platform-specific indicators.

    Args:
        concept_id: Security concept identifier (e.g., "rdp", "smb")
        platform: Platform identifier ("cbc", "cortex", "kql", "s1")
        include_descriptions: Include description in output

    Returns:
        Dictionary of indicator categories and their values

    Example:
        >>> expand_security_concept("rdp", "cbc")
        {
            "processes": ["mstsc.exe", "rdpclip.exe", ...],
            "ports": [3389, 3388],
            "cmdline_patterns": ["mstsc", "/v:", ...]
        }
    """
    if concept_id not in SECURITY_CONCEPTS:
        return {}

    concept = SECURITY_CONCEPTS[concept_id]
    indicators = concept.get("indicators", {})

    result = {}
    if include_descriptions:
        result["description"] = concept.get("description", "")

    # Copy indicator data
    for category, values in indicators.items():
        if isinstance(values, list):
            result[category] = values.copy()
        else:
            result[category] = values

    return result


def get_platform_field_name(platform: str, generic_field: str) -> Optional[str]:
    """
    Get platform-specific field name for a generic field type.

    Args:
        platform: Platform identifier ("cbc", "cortex", "kql", "s1", "cql")
        generic_field: Generic field type (e.g., "process", "cmdline", "port")

    Returns:
        Platform-specific field name or None if not found

    Example:
        >>> get_platform_field_name("cbc", "process")
        "process_name"
        >>> get_platform_field_name("cortex", "cmdline")
        "actor_process_command_line"
        >>> get_platform_field_name("cql", "process")
        "process_name"
    """
    platform_lower = platform.lower()
    if platform_lower not in PLATFORM_FIELD_MAPPINGS:
        return None

    return PLATFORM_FIELD_MAPPINGS[platform_lower].get(generic_field)


def generate_concept_hints(
    detected_concepts: Set[str],
    platform: str
) -> Dict[str, List[str]]:
    """
    Generate query builder hints from detected security concepts.

    This provides keyword hints that can be passed to query builders
    to influence term selection and field expansion.

    Args:
        detected_concepts: Set of detected concept IDs
        platform: Platform identifier

    Returns:
        Dictionary of hint categories with suggested values

    Example:
        >>> generate_concept_hints({"rdp"}, "cbc")
        {
            "process_keywords": ["mstsc.exe", "rdpclip.exe", ...],
            "port_keywords": ["3389", "3388"],
            "cmdline_keywords": ["mstsc", "/v:", ...]
        }
    """
    hints = {
        "process_keywords": [],
        "cmdline_keywords": [],
        "port_keywords": [],
        "domain_keywords": [],
        "registry_keywords": [],
    }

    for concept_id in detected_concepts:
        expanded = expand_security_concept(concept_id, platform)

        # Aggregate indicators into hint categories
        if "processes" in expanded:
            hints["process_keywords"].extend(expanded["processes"])
        if "parent_processes" in expanded:
            hints["process_keywords"].extend(expanded["parent_processes"])
        if "child_processes" in expanded:
            hints["process_keywords"].extend(expanded["child_processes"])
        if "cmdline_patterns" in expanded:
            hints["cmdline_keywords"].extend(expanded["cmdline_patterns"])
        if "ports" in expanded:
            hints["port_keywords"].extend([str(p) for p in expanded["ports"]])
        if "domain_patterns" in expanded:
            hints["domain_keywords"].extend(expanded["domain_patterns"])
        if "registry_paths" in expanded:
            hints["registry_keywords"].extend(expanded["registry_paths"])

    # Remove duplicates while preserving order
    for category in hints:
        hints[category] = list(dict.fromkeys(hints[category]))

    # Remove empty categories
    hints = {k: v for k, v in hints.items() if v}

    return hints


def get_concept_description(concept_id: str) -> str:
    """Get human-readable description of a security concept."""
    if concept_id not in SECURITY_CONCEPTS:
        return ""
    return SECURITY_CONCEPTS[concept_id].get("description", "")
