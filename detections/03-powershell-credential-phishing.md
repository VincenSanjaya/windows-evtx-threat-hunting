# PowerShell Credential Phishing via Fake Login Prompt

## Objective

Identify suspicious PowerShell activity that attempts to collect user credentials through a fake Windows Security prompt.

## Data Source

PowerShell Script Block Logging

Event ID:

4104

## Observed Function

Invoke-LoginPrompt

## Suspicious Behavior

The script used:

PromptForCredential()

to display a Windows Security credential prompt.

The script then retrieved the entered password using:

GetNetworkCredential().password

The collected credential object included:

- UserName
- Domain
- Password

## Analysis

The PowerShell script presents a credential prompt that appears to imitate a legitimate Windows Security login dialog.

After the user enters credentials, the script accesses the plaintext password stored in the credential object.

The script also validates submitted credentials and repeatedly prompts the user when authentication fails.

This behavior is consistent with credential phishing or credential harvesting through PowerShell.

## Key Indicators

Function:

Invoke-LoginPrompt

Credential prompt:

PromptForCredential

Password extraction:

GetNetworkCredential().password

Credential fields:

UserName
Domain
Password

## MITRE ATT&CK

T1059.001 - Command and Scripting Interpreter: PowerShell

T1056.002 - Input Capture: GUI Input Capture

## Investigation Steps

Review the complete PowerShell script block.

Identify the process that launched PowerShell.

Review other Event ID 4104 records near the same timestamp.

Search for credential-related PowerShell functions.

Check whether the script stores or transmits harvested credentials.

Review network activity after credential collection.

## Remediation

Restrict unnecessary PowerShell execution.

Enable PowerShell Script Block Logging.

Monitor suspicious use of PromptForCredential.

Monitor PowerShell scripts that access GetNetworkCredential().password.

Use application control where appropriate.

Educate users about unexpected credential prompts.

## Evidence

parsed/powershell-4104.txt