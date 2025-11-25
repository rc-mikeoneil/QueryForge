#!/usr/bin/env python3
"""
Script to add missing fields to CQL table schemas based on validation data.
This adds genuinely missing source fields identified in CQL_VALIDATION_REPORT.md
"""

import json
from pathlib import Path

TABLES_DIR = Path("src/queryforge/platforms/cql/cql_schemas/tables")

# Define missing fields for each table (focusing on genuine source fields, not calculated/aggregate)
MISSING_FIELDS = {
    "ZeroTrustHostAssessment": [
        {
            "name": "CpuProcessorName",
            "type": "string",
            "description": "Name/model of the CPU processor",
            "field_category": "source",
            "searchable": True,
            "common_usage": ["hardware inventory", "system profiling"]
        },
        {
            "name": "MemoryTotal",
            "type": "long",
            "description": "Total physical memory (RAM) in bytes",
            "field_category": "source",
            "common_usage": ["capacity planning", "system requirements"]
        },
        {
            "name": "UEFI",
            "type": "boolean",
            "description": "Whether system uses UEFI firmware (true) or legacy BIOS (false)",
            "field_category": "source",
            "common_usage": ["firmware assessment", "security posture"]
        },
        {
            "name": "TPM",
            "type": "string",
            "description": "Trusted Platform Module version information",
            "field_category": "source",
            "common_usage": ["hardware security assessment", "TPM compliance"]
        },
        {
            "name": "TpmFirmwareVersion",
            "type": "string",
            "description": "TPM firmware version string",
            "field_category": "source",
            "searchable": True,
            "common_usage": ["firmware tracking", "compliance validation"]
        },
        {
            "name": "BiosManufacturer",
            "type": "string",
            "description": "BIOS/UEFI manufacturer name",
            "field_category": "source",
            "searchable": True,
            "common_usage": ["hardware inventory", "vendor tracking"]
        }
    ],
    "SystemCapacity": [
        {
            "name": "CpuProcessorName",
            "type": "string",
            "description": "Name/model of the CPU processor",
            "field_category": "source",
            "searchable": True,
            "common_usage": ["hardware inventory", "system profiling"]
        },
        {
            "name": "MemoryTotal",
            "type": "long",
            "description": "Total physical memory (RAM) in bytes",
            "field_category": "source",
            "common_usage": ["capacity planning", "system requirements"]
        },
        {
            "name": "UEFI",
            "type": "boolean",
            "description": "Whether system uses UEFI firmware",
            "field_category": "source",
            "common_usage": ["firmware assessment"]
        },
        {
            "name": "TPM",
            "type": "string",
            "description": "Trusted Platform Module information",
            "field_category": "source",
            "common_usage": ["hardware security"]
        },
        {
            "name": "TpmFirmwareVersion",
            "type": "string",
            "description": "TPM firmware version",
            "field_category": "source",
            "searchable": True,
            "common_usage": ["firmware tracking"]
        },
        {
            "name": "BiosManufacturer",
            "type": "string",
            "description": "BIOS/UEFI manufacturer",
            "field_category": "source",
            "searchable": True,
            "common_usage": ["hardware inventory"]
        }
    ],
    "ResourceUtilization": [
        {
            "name": "CpuProcessorName",
            "type": "string",
            "description": "CPU processor name/model",
            "field_category": "source",
            "searchable": True,
            "common_usage": ["hardware tracking"]
        },
        {
            "name": "MemoryTotal",
            "type": "long",
            "description": "Total physical memory in bytes",
            "field_category": "source",
            "common_usage": ["resource monitoring"]
        }
    ],
    "AgentOnline": [
        {
            "name": "CpuProcessorName",
            "type": "string",
            "description": "CPU processor name",
            "field_category": "source",
            "searchable": True,
            "common_usage": ["inventory"]
        },
        {
            "name": "MemoryTotal",
            "type": "long",
            "description": "Total memory in bytes",
            "field_category": "source",
            "common_usage": ["capacity tracking"]
        },
        {
            "name": "UEFI",
            "type": "boolean",
            "description": "UEFI firmware indicator",
            "field_category": "source",
            "common_usage": ["firmware type"]
        },
        {
            "name": "TPM",
            "type": "string",
            "description": "TPM information",
            "field_category": "source",
            "common_usage": ["security posture"]
        },
        {
            "name": "TpmFirmwareVersion",
            "type": "string",
            "description": "TPM firmware version",
            "field_category": "source",
            "common_usage": ["firmware tracking"]
        },
        {
            "name": "BiosManufacturer",
            "type": "string",
            "description": "BIOS manufacturer",
            "field_category": "source",
            "searchable": True,
            "common_usage": ["vendor tracking"]
        }
    ],
    "UserLogon": [
        {
            "name": "LogonType",
            "type": "long",
            "description": "Windows logon type (2=Interactive, 3=Network, 10=RemoteInteractive/RDP, etc.)",
            "field_category": "source",
            "example_values": [2, 3, 10],
            "common_usage": ["logon analysis", "authentication tracking", "lateral movement detection"]
        },
        {
            "name": "LogonDomain",
            "type": "string",
            "description": "Domain or workgroup name for the logon",
            "field_category": "source",
            "searchable": True,
            "common_usage": ["domain filtering", "authentication analysis"]
        }
    ],
    "HttpRequestDetect": [
        {
            "name": "HttpUrl",
            "type": "string",
            "description": "Full HTTP request URL",
            "field_category": "source",
            "searchable": True,
            "supports_regex": True,
            "common_usage": ["web traffic analysis", "URL filtering", "threat hunting"]
        },
        {
            "name": "HttpMethod",
            "type": "string",
            "description": "HTTP request method (GET, POST, PUT, DELETE, etc.)",
            "field_category": "source",
            "example_values": ["GET", "POST", "PUT", "DELETE"],
            "common_usage": ["request type filtering", "API analysis"]
        },
        {
            "name": "UserAgentString",
            "type": "string",
            "description": "HTTP User-Agent header value",
            "field_category": "source",
            "searchable": True,
            "supports_regex": True,
            "common_usage": ["browser identification", "bot detection", "client analysis"]
        },
        {
            "name": "HttpRequestHeader",
            "type": "string",
            "description": "Full HTTP request headers",
            "field_category": "source",
            "searchable": True,
            "common_usage": ["header analysis", "traffic inspection"]
        }
    ],
    "ReflectiveDotnetModuleLoad": [
        {
            "name": "ManagedPdbBuildPath",
            "type": "string",
            "description": "Path to .NET Program Database (PDB) file for managed assemblies",
            "field_category": "source",
            "searchable": True,
            "supports_regex": True,
            "common_usage": ["malware detection", ".NET analysis", "reflective loading detection"]
        }
    ],
    "DriverLoad": [
        {
            "name": "ExternalApiType",
            "type": "string",
            "description": "Type of external API used for driver loading",
            "field_category": "source",
            "searchable": True,
            "common_usage": ["API tracking", "driver analysis"]
        }
    ],
    "Event_RemoteResponseSessionStartEvent": [
        {
            "name": "StartTimestamp",
            "type": "long",
            "description": "Timestamp when the RTR session started (epoch milliseconds)",
            "field_category": "source",
            "common_usage": ["session tracking", "timeline analysis"]
        }
    ],
    "FirewallSetRule": [
        {
            "name": "FirewallRule",
            "type": "string",
            "description": "Firewall rule name or description",
            "field_category": "source",
            "searchable": True,
            "common_usage": ["firewall analysis", "rule tracking"]
        },
        {
            "name": "FirewallRuleId",
            "type": "string",
            "description": "Unique identifier for the firewall rule",
            "field_category": "source",
            "searchable": True,
            "common_usage": ["rule correlation", "change tracking"]
        }
    ],
    "InstalledBrowserExtension": [
        {
            "name": "TotalEndpoints",
            "type": "long",
            "description": "Count of endpoints with this extension installed (aggregate field)",
            "field_category": "aggregate",
            "common_usage": ["prevalence analysis", "extension tracking"]
        }
    ],
    "ScriptControlScanInfo": [
        {
            "name": "ScriptContent",
            "type": "string",
            "description": "Content of the scanned script",
            "field_category": "source",
            "searchable": True,
            "supports_regex": True,
            "common_usage": ["script analysis", "malware detection", "content inspection"]
        }
    ],
    "CriticalEnvironmentVariableChanged": [
        {
            "name": "EnvironmentVariableName",
            "type": "string",
            "description": "Name of the environment variable that was changed",
            "field_category": "source",
            "searchable": True,
            "common_usage": ["env var monitoring", "configuration change detection"]
        },
        {
            "name": "EnvironmentVariableValue",
            "type": "string",
            "description": "New value of the environment variable",
            "field_category": "source",
            "searchable": True,
            "common_usage": ["value analysis", "change tracking"]
        }
    ]
}

def add_fields_to_table(table_name: str, new_fields: list):
    """Add missing fields to a table schema file."""
    file_path = TABLES_DIR / f"{table_name}.json"
    
    if not file_path.exists():
        print(f"  ⚠️  Table {table_name}.json not found, skipping")
        return False
    
    # Read existing schema
    with open(file_path, 'r') as f:
        schema = json.load(f)
    
    # Get existing field names
    existing_fields = {col["name"] for col in schema.get("columns", [])}
    
    # Add only new fields
    added_count = 0
    for field in new_fields:
        if field["name"] not in existing_fields:
            schema["columns"].append(field)
            added_count += 1
            print(f"    ✅ Added field: {field['name']}")
        else:
            print(f"    ⏭️  Skipping {field['name']} (already exists)")
    
    if added_count > 0:
        # Update col_count if present
        if "col_count" in schema:
            schema["col_count"] = len(schema["columns"])
        
        # Write back
        with open(file_path, 'w') as f:
            json.dump(schema, f, indent=2)
        
        print(f"  ✅ Updated {table_name}.json (+{added_count} fields, total: {schema['col_count']})")
        return True
    else:
        print(f"  ℹ️  No new fields added to {table_name}.json")
        return False

def main():
    """Main execution."""
    print("🔧 Adding missing fields to CQL table schemas...\n")
    
    total_tables = 0
    total_fields = 0
    
    for table_name, fields in MISSING_FIELDS.items():
        print(f"📝 Processing {table_name}:")
        if add_fields_to_table(table_name, fields):
            total_tables += 1
            total_fields += len([f for f in fields])
        print()
    
    print(f"✨ Summary:")
    print(f"   Tables updated: {total_tables}")
    print(f"   Fields processed: {total_fields}")

if __name__ == "__main__":
    main()
