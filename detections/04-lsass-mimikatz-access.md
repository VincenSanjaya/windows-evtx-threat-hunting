# LSASS Process Access by Mimikatz

## Objective

Identify suspicious access to the LSASS process that may indicate credential dumping.

## Data Source

Windows Sysmon Event Log

Event ID:

10 - Process Access

## Source Process

C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe

## Target Process

C:\Windows\system32\lsass.exe

## Granted Access

0x00001010

## Analysis

Sysmon Event ID 10 recorded mimikatz.exe accessing lsass.exe.

LSASS stores sensitive authentication material in memory and is a common target for credential dumping tools.

The source process is explicitly identified as Mimikatz, making this event highly suspicious.

The call trace also references mimikatz.exe together with Windows system libraries such as ntdll.dll and KERNELBASE.dll.

## Assessment

This event is consistent with credential dumping activity targeting LSASS memory.

Because the observed source process is Mimikatz and the target is LSASS, this event should be treated as high severity.

## MITRE ATT&CK

T1003.001 - OS Credential Dumping: LSASS Memory

## Investigation Steps

Review process creation events for mimikatz.exe.

Identify the user account that launched the process.

Review command-line arguments used by Mimikatz.

Search for additional Sysmon Event ID 10 events targeting lsass.exe.

Review authentication events after the credential access.

Search for lateral movement using potentially compromised credentials.

## Remediation

Terminate unauthorized credential dumping tools.

Isolate the affected host if compromise is suspected.

Reset credentials that may have been exposed.

Restrict administrative privileges.

Enable endpoint protection for credential dumping behavior.

Consider enabling Windows Credential Guard where supported.

Monitor suspicious access to lsass.exe.

## Evidence

parsed/lsass-process-access.txt
