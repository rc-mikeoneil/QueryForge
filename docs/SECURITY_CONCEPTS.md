# Security Concepts Reference

**Version:** 1.0  
**Last Updated:** 2025-11-05  
**Purpose:** Document common security concepts detected by QueryForge's RAG enhancement system

## Overview

This document catalogs security concepts that the QueryForge system recognizes and can automatically expand into comprehensive queries. When a user mentions one of these concepts, the RAG enhancement system retrieves relevant documentation and generates queries that check multiple indicators.

## Network Protocols

### RDP (Remote Desktop Protocol)

**User Intent:** "RDP", "Remote Desktop", "RDP connections"

**Key Indicators:**
- **Port:** 3389 (TCP)
- **Processes:**
  - `mstsc.exe` - RDP client
  - `rdpclip.exe` - RDP clipboard integration
  - `termsrv.dll` - Terminal Services
  - `rdpinit.exe` - RDP initialization
- **Network Activity:** Outbound connections to port 3389
- **Services:** TermService, Remote Desktop Services

**Example Enhanced Query (CBC):**
```
(netconn_port:3389 OR process_name:mstsc.exe OR process_name:rdpclip.exe OR process_name:rdpinit.exe)
```

**Example Enhanced Query (KQL):**
```kql
DeviceNetworkEvents
| where RemotePort == 3389 
   or InitiatingProcessFileName in~ ("mstsc.exe", "rdpclip.exe")
```

**Detection Rationale:**
- Port 3389 alone misses local RDP activity
- Process names catch RDP client usage without network events
- Comprehensive detection for both incoming and outgoing RDP

---

### SMB (Server Message Block)

**User Intent:** "SMB", "file sharing", "SMB connections"

**Key Indicators:**
- **Ports:** 445 (SMB over TCP), 139 (NetBIOS)
- **Processes:**
  - `smbclient` - SMB client (Linux)
  - `net.exe` - Windows network utility
  - `smb.sys` - SMB driver
- **Commands:**
  - `net use`
  - `net share`
  - `copy \\`
- **Network Activity:** Connections to ports 445, 139

**Example Enhanced Query (CBC):**
```
(netconn_port:445 OR netconn_port:139 OR process_name:net.exe OR process_cmdline:"net use" OR process_cmdline:"net share")
```

**Detection Rationale:**
- Multiple ports for different SMB versions
- Command-line utilities for SMB operations
- Catches both automated and manual file sharing

---

### SSH (Secure Shell)

**User Intent:** "SSH", "SSH connections", "secure shell"

**Key Indicators:**
- **Port:** 22 (TCP)
- **Processes:**
  - `ssh.exe` - SSH client
  - `sshd` - SSH daemon
  - `putty.exe` - Popular SSH client
  - `plink.exe` - PuTTY command-line interface
- **Files:** `~/.ssh/`, `known_hosts`, `authorized_keys`

**Example Enhanced Query (CBC):**
```
(netconn_port:22 OR process_name:ssh.exe OR process_name:putty.exe OR process_name:plink.exe OR filemod_name:*\\.ssh\\*)
```

---

### DNS

**User Intent:** "DNS", "DNS queries", "name resolution"

**Key Indicators:**
- **Port:** 53 (UDP/TCP)
- **Processes:**
  - `dns.exe` - DNS client
  - `nslookup.exe` - DNS lookup utility
  - `dig` - DNS lookup tool (Linux)
- **Network Activity:** UDP/TCP port 53

**Example Enhanced Query (KQL):**
```kql
DeviceNetworkEvents
| where RemotePort == 53 or LocalPort == 53
   or InitiatingProcessFileName in~ ("nslookup.exe", "dig")
```

---

## Scripting & Execution

### PowerShell

**User Intent:** "PowerShell", "PS execution", "PowerShell commands"

**Key Indicators:**
- **Processes:**
  - `powershell.exe` - Windows PowerShell
  - `pwsh.exe` - PowerShell Core
  - `powershell_ise.exe` - PowerShell ISE
- **Command-line Flags:**
  - `-enc` / `-encodedcommand` - Base64 encoded commands
  - `-nop` / `-noprofile` - No profile loading
  - `-w hidden` - Hidden window
  - `-ep bypass` - Execution policy bypass
  - `-c` / `-command` - Execute command
- **Scripts:** `.ps1`, `.psm1` files

**Example Enhanced Query (CBC):**
```
(process_name:powershell.exe OR process_name:pwsh.exe OR process_cmdline:"-enc" OR process_cmdline:"-nop" OR process_cmdline:"bypass" OR filemod_name:*.ps1)
```

**Example Enhanced Query (Cortex):**
```xql
dataset = xdr_data
| filter actor_process_image_name ~= "powershell" 
   or actor_process_command_line contains "-enc"
   or actor_process_command_line contains "-noprofile"
```

**Detection Rationale:**
- Catches both legitimate and malicious PowerShell usage
- Suspicious flags often indicate evasion techniques
- File modifications track script creation/execution

---

### WMI (Windows Management Instrumentation)

**User Intent:** "WMI", "WMIC", "WMI execution"

**Key Indicators:**
- **Processes:**
  - `wmic.exe` - WMI command-line
  - `wmiprvse.exe` - WMI provider host
  - `scrcons.exe` - WMI script consumer
- **Commands:**
  - `wmic process call create`
  - `wmic /node:`
- **Event Logs:** WMI-Activity logs

**Example Enhanced Query (CBC):**
```
(process_name:wmic.exe OR process_name:wmiprvse.exe OR process_name:scrcons.exe OR process_cmdline:"wmic process call create")
```

**Detection Rationale:**
- WMI can execute code remotely
- Multiple processes involved in WMI operations
- Command patterns indicate potential abuse

---

### VBScript / JScript

**User Intent:** "VBScript", "JScript", "script execution"

**Key Indicators:**
- **Processes:**
  - `wscript.exe` - Windows Script Host
  - `cscript.exe` - Console Script Host
  - `mshta.exe` - HTML Application Host
- **Files:** `.vbs`, `.js`, `.hta`, `.vbe`, `.jse`

**Example Enhanced Query (KQL):**
```kql
DeviceProcessEvents
| where FileName in~ ("wscript.exe", "cscript.exe", "mshta.exe")
   or ProcessCommandLine has_any (".vbs", ".js", ".hta")
```

---

## Lateral Movement

### PSExec

**User Intent:** "PSExec", "remote execution", "PsExec"

**Key Indicators:**
- **Processes:**
  - `psexec.exe` - Sysinternals PSExec
  - `psexesvc.exe` - PSExec service
- **Services:** `PSEXESVC`
- **Network:** SMB (port 445) + named pipes
- **Command-line:** `-s`, `-u`, `-p` flags

**Example Enhanced Query (CBC):**
```
(process_name:psexec.exe OR process_name:psexesvc.exe OR parent_name:psexec.exe OR netconn_port:445 AND process_cmdline:"\\\\*")
```

**Detection Rationale:**
- PSExec leaves multiple artifacts
- Service creation + SMB connection pattern
- Can detect both official and imitation tools

---

### Remote Service Creation

**User Intent:** "remote service", "service creation", "sc.exe remote"

**Key Indicators:**
- **Processes:**
  - `sc.exe` - Service control utility
  - `services.exe` - Service control manager
- **Commands:**
  - `sc \\computer create`
  - `sc \\computer start`
- **Network:** SMB connections during service operations

**Example Enhanced Query (S1):**
```
(src.process.name = "sc.exe" AND src.process.cmdline ContainsIgnoreCase "create") 
OR (src.process.name = "sc.exe" AND src.process.cmdline ContainsIgnoreCase "\\\\")
```

---

### WinRM (Windows Remote Management)

**User Intent:** "WinRM", "remote PowerShell", "PS remoting"

**Key Indicators:**
- **Ports:** 5985 (HTTP), 5986 (HTTPS)
- **Processes:**
  - `winrs.exe` - WinRM client
  - `wsmprovhost.exe` - WS-Management provider host
- **Services:** WinRM
- **PowerShell:** `Enter-PSSession`, `Invoke-Command`

**Example Enhanced Query (CBC):**
```
(netconn_port:5985 OR netconn_port:5986 OR process_name:winrs.exe OR process_name:wsmprovhost.exe OR process_cmdline:"Enter-PSSession" OR process_cmdline:"Invoke-Command")
```

---

## Persistence Mechanisms

### Scheduled Tasks

**User Intent:** "scheduled task", "schtasks", "task creation"

**Key Indicators:**
- **Processes:**
  - `schtasks.exe` - Task scheduler utility
  - `taskeng.exe` - Task scheduler engine (legacy)
  - `taskhost.exe` / `taskhostw.exe` - Task host
- **Commands:**
  - `schtasks /create`
  - `schtasks /run`
- **Files:** `C:\Windows\System32\Tasks\*`

**Example Enhanced Query (KQL):**
```kql
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
   and ProcessCommandLine has "/create"
| union (DeviceFileEvents
   | where FolderPath startswith @"C:\Windows\System32\Tasks\"
   and ActionType == "FileCreated")
```

---

### Registry Autorun

**User Intent:** "registry persistence", "autorun", "registry run key"

**Key Indicators:**
- **Processes:**
  - `reg.exe` - Registry utility
  - `regedit.exe` - Registry editor
- **Registry Keys:**
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\...\RunOnce`
- **Commands:**
  - `reg add ... /v ... /d`

**Example Enhanced Query (CBC):**
```
(process_name:reg.exe AND process_cmdline:"CurrentVersion\\Run") 
OR regmod_name:"*\\CurrentVersion\\Run*"
```

---

### Startup Folder

**User Intent:** "startup folder", "startup persistence"

**Key Indicators:**
- **Paths:**
  - `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
  - `C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
- **File Operations:** File creation/modification in startup folders

**Example Enhanced Query (Cortex):**
```xql
dataset = xdr_data
| filter action_file_path contains "Start Menu\\Programs\\Startup"
   or action_file_path contains "Start Menu\\Programs\\StartUp"
| filter action_file_operation in ("FILE_WRITE", "FILE_CREATE")
```

---

## Credential Access

### Mimikatz

**User Intent:** "Mimikatz", "credential dumping", "sekurlsa"

**Key Indicators:**
- **Processes:**
  - `mimikatz.exe` - Original binary
  - Any renamed variant
- **Commands:**
  - `sekurlsa::logonpasswords`
  - `lsadump::sam`
  - `privilege::debug`
- **Memory Access:** `lsass.exe` process access
- **Files:** `*.kirbi` (Kerberos tickets)

**Example Enhanced Query (CBC):**
```
(process_name:mimikatz.exe OR process_cmdline:"sekurlsa" OR process_cmdline:"lsadump" OR crossproc_target:"lsass.exe" OR filemod_name:*.kirbi)
```

---

### LSASS Dumping

**User Intent:** "LSASS dump", "credential dumping", "Procdump lsass"

**Key Indicators:**
- **Processes:**
  - `procdump.exe` - Sysinternals Procdump
  - `sqldumper.exe` - SQL Server dumper (abused)
  - `comsvcs.dll` - COM+ Services (MiniDump)
- **Commands:**
  - `procdump -ma lsass.exe`
  - `rundll32 comsvcs.dll MiniDump`
  - `taskmgr.exe` (manual dump)
- **Files:** `lsass*.dmp`, `lsass*.mdmp`

**Example Enhanced Query (KQL):**
```kql
DeviceProcessEvents
| where (FileName =~ "procdump.exe" and ProcessCommandLine has "lsass")
   or (FileName =~ "rundll32.exe" and ProcessCommandLine has "comsvcs" and ProcessCommandLine has "MiniDump")
| union (DeviceFileEvents
   | where FileName has "lsass" and FileName endswith ".dmp")
```

---

## Defense Evasion

### Process Injection

**User Intent:** "process injection", "code injection"

**Key Indicators:**
- **API Calls:**
  - `CreateRemoteThread`
  - `WriteProcessMemory`
  - `VirtualAllocEx`
  - `QueueUserAPC`
- **Processes:** Cross-process operations
- **Techniques:** DLL injection, reflective DLL injection, process hollowing

**Example Enhanced Query (CBC):**
```
(crossproc_action:RemoteThreadCreate OR crossproc_action:ProcessModLoad OR process_cmdline:"VirtualAllocEx" OR process_cmdline:"WriteProcessMemory")
```

---

### Obfuscation

**User Intent:** "obfuscated", "encoded command", "obfuscation"

**Key Indicators:**
- **PowerShell:** `-encodedcommand`, Base64 strings
- **Command-line:** Excessive special characters (`^`, `"`, `` ` ``)
- **Scripts:** High entropy strings
- **XOR/ROT13:** Common encoding patterns

**Example Enhanced Query (S1):**
```
(src.process.cmdline ContainsIgnoreCase "-enc" AND src.process.cmdline ContainsIgnoreCase "powershell")
OR (src.process.cmdline ContainsIgnoreCase "cmd /c" AND LENGTH(src.process.cmdline) > 500)
```

---

### Disabling Security Tools

**User Intent:** "disable defender", "kill AV", "disable security"

**Key Indicators:**
- **Processes:**
  - `sc.exe stop` (stopping services)
  - `net stop` (stopping services)
  - `taskkill` (killing processes)
- **Commands:**
  - `Set-MpPreference -DisableRealtimeMonitoring`
  - `sc stop WinDefend`
  - `net stop "Windows Defender"`
- **Registry:**
  - Modifying Defender policies
  - Disabling Windows Firewall

**Example Enhanced Query (KQL):**
```kql
DeviceProcessEvents
| where (FileName =~ "powershell.exe" and ProcessCommandLine has "Set-MpPreference")
   or (FileName in~ ("sc.exe", "net.exe") and ProcessCommandLine has_any ("stop", "delete") 
       and ProcessCommandLine has_any ("WinDefend", "Defender", "Security"))
```

---

## Data Exfiltration

### File Compression

**User Intent:** "file compression", "zip creation", "rar files"

**Key Indicators:**
- **Processes:**
  - `7z.exe` - 7-Zip
  - `WinRAR.exe` / `rar.exe` - WinRAR
  - `tar.exe` - Tar utility
  - `compact.exe` - Windows compression
- **Files:** `.zip`, `.rar`, `.7z`, `.tar`, `.gz`
- **Commands:** Large archive creation

**Example Enhanced Query (CBC):**
```
(process_name:7z.exe OR process_name:rar.exe OR process_name:WinRAR.exe OR filemod_name:*.zip OR filemod_name:*.rar OR filemod_name:*.7z)
```

---

### Cloud Storage Upload

**User Intent:** "cloud upload", "dropbox", "OneDrive"

**Key Indicators:**
- **Processes:**
  - `Dropbox.exe`
  - `OneDrive.exe`
  - `GoogleDriveSync.exe`
  - `rclone.exe` - Command-line cloud sync
- **Network:** Connections to cloud service domains
- **Domains:** `dropbox.com`, `onedrive.live.com`, `drive.google.com`

**Example Enhanced Query (Cortex):**
```xql
dataset = xdr_data
| filter actor_process_image_name in ("Dropbox.exe", "OneDrive.exe", "rclone.exe")
   or action_remote_domain contains "dropbox.com"
   or action_remote_domain contains "onedrive.live.com"
```

---

## Usage Guidelines

### For Analysts

When investigating security incidents, use these concepts as starting points:

1. **Start Broad:** Use high-level concepts (e.g., "PowerShell") to get comprehensive queries
2. **Refine:** Add time windows, specific hosts, or additional filters
3. **Correlate:** Look for multiple concepts in sequence (e.g., PowerShell → LSASS dump → File compression)

### For Query Builders

When implementing RAG enhancement:

1. **Add Documentation:** Include these concepts in RAG corpus
2. **Provide Examples:** Show multi-indicator queries
3. **Link Concepts:** Document common attack chains
4. **Update Regularly:** Add new techniques as they emerge

### For Documentation Writers

When documenting new concepts:

1. **Include All Indicators:** Processes, ports, files, commands
2. **Provide Context:** Explain why each indicator matters
3. **Show Examples:** Include platform-specific query examples
4. **Cross-Reference:** Link related concepts

## Attack Chain Examples

### Example 1: Lateral Movement via RDP

```
Initial Access → RDP Connection → Credential Dump → Further Lateral Movement
```

**Query Sequence:**
1. RDP: Detect initial connection
2. Mimikatz/LSASS: Detect credential access
3. Additional RDP: Detect movement to other systems

### Example 2: PowerShell-Based Attack

```
Phishing → PowerShell Execution → Obfuscation → Credential Access → Exfiltration
```

**Query Sequence:**
1. PowerShell: Detect execution with suspicious flags
2. Obfuscation: High entropy or encoded commands
3. LSASS: Credential dumping
4. Compression + Upload: Data exfiltration

### Example 3: Service-Based Persistence

```
Initial Compromise → Service Creation → Scheduled Task → Registry Autorun
```

**Query Sequence:**
1. Remote Service: Detect service creation
2. Scheduled Tasks: Detect task creation
3. Registry: Detect autorun key modification

## Contributing

To add new security concepts to this document:

1. **Research:** Validate with MITRE ATT&CK, security blogs
2. **Document:** Follow the template above
3. **Test:** Verify queries work across platforms
4. **Update RAG:** Add to schema documentation for RAG retrieval

## References

- **MITRE ATT&CK:** https://attack.mitre.org/
- **LOLBAS Project:** https://lolbas-project.github.io/
- **GTFOBins:** https://gtfobins.github.io/
- **Atomic Red Team:** https://github.com/redcanaryco/atomic-red-team

---

**Document Version:** 1.0  
**Contributors:** Security Team  
**Status:** Living Document - Updates Welcome
