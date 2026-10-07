# Windows EVTX Threat Hunting Lab

Blue Team threat hunting project focused on analyzing Windows EVTX logs using macOS.

This project uses public Windows Event Log samples, Sysmon telemetry, PowerShell Script Block Logs, and custom Python parsers to identify suspicious activity.

## Objectives

- Analyze Windows EVTX files without using a Windows VM
- Practice Sysmon and PowerShell log analysis
- Identify suspicious process and network activity
- Perform threat hunting
- Map findings to MITRE ATT&CK
- Document investigation evidence

## Tools Used

- Python 3
- python-evtx
- Sysmon logs
- PowerShell Event Logs
- grep
- macOS Terminal
- Visual Studio Code

## Detection Scenarios

### 1. Suspicious IIS Network Activity

Sysmon Event ID 3 showed `w3wp.exe` connecting to:

- RDP port 3389
- SMB port 445

This activity may indicate tunneling, pivoting, or abuse of an IIS worker process.

### 2. IIS Credential Discovery

Sysmon Event ID 1 showed PowerShell launching:

`appcmd.exe list vdir "." /text:password`

The PowerShell command was Base64-decoded and showed XOR decryption and execution using `Invoke-Expression`.

### 3. PowerShell Credential Phishing

PowerShell Event ID 4104 showed a script using:

`PromptForCredential()`

The script accessed the submitted username, domain, and password.

### 4. LSASS Credential Dumping

Sysmon Event ID 10 showed:

`mimikatz.exe`

accessing:

`lsass.exe`

This behavior is consistent with LSASS credential dumping.

## MITRE ATT&CK

- T1572 - Protocol Tunneling
- T1021.001 - Remote Desktop Protocol
- T1021.002 - SMB/Windows Admin Shares
- T1059.001 - PowerShell
- T1027 - Obfuscated/Compressed Files and Information
- T1140 - Deobfuscate/Decode Files or Information
- T1552.001 - Credentials In Files
- T1056.002 - GUI Input Capture
- T1003.001 - LSASS Memory

## Repository Structure

- `detections/` - Detection analysis
- `parsed/` - Parsed EVTX output
- `reports/` - Timeline and final report
- `samples/` - EVTX samples
- `scripts/` - Python parsing scripts
- `screenshots/` - Investigation evidence

## Key Skills Demonstrated

- Windows Event Log analysis
- Sysmon analysis
- PowerShell threat hunting
- Credential access investigation
- MITRE ATT&CK mapping
- Python log parsing
- Blue Team investigation

## Disclaimer

This project was performed for educational purposes using publicly available EVTX samples.

No malicious payload was executed.
