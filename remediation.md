# Remediation Recommendations

## PowerShell Security

Enable PowerShell Script Block Logging.

Monitor suspicious PowerShell arguments such as:

- `-enc`
- `Invoke-Expression`
- credential-related commands

Use application control where appropriate.

## IIS Security

Monitor unusual activity from `w3wp.exe`.

Restrict unnecessary network access from IIS servers to:

- RDP
- SMB
- administrative services

Apply least privilege to IIS application pool accounts.

Protect sensitive IIS configuration files.

## Credential Protection

Monitor access to `lsass.exe`.

Use endpoint protection capable of detecting credential dumping.

Enable Windows Credential Guard where supported.

Limit administrative privileges.

Reset potentially compromised credentials after confirmed credential access.

## Network Security

Use network segmentation.

Restrict unnecessary RDP and SMB connections.

Monitor unexpected traffic from web servers.

## Logging and Monitoring

Enable and centralize:

- Sysmon logs
- Windows Security logs
- PowerShell Script Block Logging
- IIS logs

Forward logs to a SIEM for centralized detection and investigation.
