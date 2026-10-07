# Final Threat Hunting Report

## Project Overview

This project focused on analyzing Windows Event Log and Sysmon EVTX samples from a Blue Team perspective.

The investigation was performed entirely on macOS using Python-based EVTX parsing and command-line analysis.

The objective was to identify suspicious Windows activity, document findings, map observed behavior to MITRE ATT&CK, and practice practical threat hunting workflows without using a Windows virtual machine.

## Data Sources

The investigation used publicly available EVTX samples containing:

- Sysmon Event ID 1 - Process Creation
- Sysmon Event ID 3 - Network Connection
- Sysmon Event ID 10 - Process Access
- PowerShell Event ID 4104 - Script Block Logging

## Tools Used

- Python 3
- python-evtx
- grep
- macOS Terminal
- Visual Studio Code

## Detection Summary

### Detection 1 - Suspicious IIS Network Connections

Sysmon Event ID 3 showed the IIS worker process:

`C:\Windows\System32\inetsrv\w3wp.exe`

creating connections to:

- RDP port 3389
- SMB port 445

Observed examples:

`127.0.0.1:49947 -> 127.0.0.1:3389`

`127.0.0.1:49949 -> 127.0.0.1:445`

Repeated network activity from an IIS worker process to these services is unusual and may indicate tunneling, pivoting, or abuse of a compromised web server.

### Detection 2 - IIS Credential Discovery

Sysmon Event ID 1 showed:

`C:\Windows\System32\inetsrv\appcmd.exe`

executed with:

`appcmd.exe list vdir "." /text:password`

The process was launched through PowerShell using an encoded command.

The PowerShell command was decoded offline and showed behavior including:

- Reading payload files from Windows Temp
- XOR-based decryption
- Converting decrypted content into text
- Executing the result using `Invoke-Expression`
- Removing temporary artifacts

The resulting AppCmd execution attempted to retrieve IIS virtual directory password information.

### Detection 3 - PowerShell Credential Phishing

PowerShell Event ID 4104 revealed a script containing:

`PromptForCredential()`

The script requested user credentials through a Windows Security-style prompt.

It then accessed the password using:

`GetNetworkCredential().password`

The script collected:

- Username
- Domain
- Password

No evidence of network exfiltration or file-based credential storage was identified in the available Event ID 4104 sample.

### Detection 4 - LSASS Credential Dumping

Sysmon Event ID 10 recorded:

`mimikatz.exe`

accessing:

`C:\Windows\system32\lsass.exe`

Observed source process:

`C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe`

Granted access:

`0x00001010`

This behavior is consistent with credential dumping against LSASS memory and should be considered high severity.

## MITRE ATT&CK Mapping

| Technique | Description                                   |
| --------- | --------------------------------------------- |
| T1572     | Protocol Tunneling                            |
| T1021.001 | Remote Services: Remote Desktop Protocol      |
| T1021.002 | Remote Services: SMB/Windows Admin Shares     |
| T1059.001 | Command and Scripting Interpreter: PowerShell |
| T1027     | Obfuscated/Compressed Files and Information   |
| T1140     | Deobfuscate/Decode Files or Information       |
| T1552.001 | Unsecured Credentials: Credentials In Files   |
| T1056.002 | Input Capture: GUI Input Capture              |
| T1003.001 | OS Credential Dumping: LSASS Memory           |

## Investigation Findings

The samples demonstrated several common attacker behaviors:

- Abuse of legitimate Windows and IIS utilities
- Encoded PowerShell execution
- Payload deobfuscation
- In-memory script execution
- Credential harvesting
- Credential discovery
- LSASS process access
- Suspicious network activity involving RDP and SMB

A key lesson from the investigation was that individual Windows events become much more useful when process, command-line, network, and credential-related telemetry are analyzed together.

## Severity Assessment

Detection 1:
Medium to High

Detection 2:
High

Detection 3:
High

Detection 4:
Critical

Severity depends on the surrounding environment and additional evidence.

## Recommended Actions

Organizations should:

- Enable Sysmon logging
- Enable PowerShell Script Block Logging
- Monitor encoded PowerShell commands
- Monitor suspicious AppCmd usage
- Detect unusual network activity from web server processes
- Monitor access to LSASS
- Restrict unnecessary administrative privileges
- Use endpoint detection and response controls
- Forward Windows logs into a SIEM
- Apply network segmentation for critical systems

## Limitations

The investigation used separate public EVTX samples.

The detections should not be interpreted as one continuous real-world incident unless supported by additional correlated evidence.

Some samples contained limited telemetry, so conclusions were restricted to observable evidence.

## Conclusion

This project demonstrated a practical threat hunting workflow using Windows EVTX telemetry without requiring a Windows virtual machine.

By creating custom Python parsers and analyzing Sysmon and PowerShell logs, the investigation identified multiple suspicious behaviors related to credential access, PowerShell abuse, tunneling, and LSASS credential dumping.

The project strengthened practical skills in:

- Windows log analysis
- Sysmon investigation
- PowerShell analysis
- Threat hunting
- MITRE ATT&CK mapping
- Detection engineering fundamentals
- Blue Team incident investigation
