# Methodology

## 1. Evidence Collection

Public EVTX samples were collected from the EVTX-ATTACK-SAMPLES dataset.

The samples were analyzed locally on macOS.

## 2. EVTX Parsing

The `python-evtx` library was used to read Windows Event Log files.

Custom Python scripts were created to extract important fields from:

- Sysmon Event ID 1
- Sysmon Event ID 3
- Sysmon Event ID 10
- PowerShell Event ID 4104

## 3. Event Filtering

Parsed logs were filtered using tools such as:

- grep
- head
- sort

The investigation focused on:

- Process execution
- Command-line arguments
- Network connections
- PowerShell activity
- Credential-related behavior

## 4. PowerShell Analysis

Encoded PowerShell commands were Base64-decoded using UTF-16LE.

The decoded content was analyzed as text only.

No decoded PowerShell payload was executed.

## 5. Threat Hunting

Suspicious behaviors were identified including:

- IIS worker process connecting to RDP and SMB
- Encoded PowerShell execution
- IIS credential discovery
- Credential phishing
- LSASS process access

## 6. MITRE ATT&CK Mapping

Each finding was mapped to relevant MITRE ATT&CK techniques based on available evidence.

## 7. Documentation

Each detection contains:

- Objective
- Evidence
- Analysis
- MITRE ATT&CK mapping
- Investigation steps
- Remediation