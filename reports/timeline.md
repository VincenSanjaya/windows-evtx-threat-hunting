# Threat Hunting Timeline

## 2019-09-03 11:04:07 UTC

Sysmon Event ID 3 recorded:

Process:
C:\Windows\System32\inetsrv\w3wp.exe

User:
IIS APPPOOL\DefaultAppPool

Connection:

127.0.0.1:49947 -> 127.0.0.1:3389

This indicates the IIS worker process communicating with the local RDP service.

---

## 2019-09-03 11:04:56 UTC

A second connection from w3wp.exe to RDP port 3389 was observed.

127.0.0.1:49948 -> 127.0.0.1:3389

The repeated behavior increases suspicion of tunneling or local service access through the IIS process.

---

## 2019-09-03 11:33:24 UTC

w3wp.exe connected to SMB port 445.

127.0.0.1:49949 -> 127.0.0.1:445

---

## 2019-09-03 11:34:37 UTC

Another SMB connection was observed.

127.0.0.1:49950 -> 127.0.0.1:445

This shows repeated access to sensitive Windows services from the IIS worker process.

---

# Credential Discovery Activity

A separate Sysmon Event ID 1 sample showed PowerShell launching:

C:\Windows\System32\inetsrv\appcmd.exe

Command:

appcmd.exe list vdir "." /text:password

The PowerShell process used the `-enc` argument.

After decoding the PowerShell command, the script was observed:

- Reading encrypted payload files from C:\Windows\Temp
- XOR-decrypting the file contents
- Converting the decrypted payload to text
- Executing the payload using Invoke-Expression
- Removing temporary files after execution
- Launching AppCmd to retrieve IIS password information

# Investigation Summary

The observed activity demonstrates multiple suspicious behaviors:

- IIS worker process accessing RDP and SMB services
- Encoded PowerShell execution
- XOR-based payload decryption
- In-memory execution using Invoke-Expression
- Temporary artifact cleanup
- IIS credential discovery using AppCmd

These behaviors indicate possible compromise of an IIS server and attempted credential access or post-exploitation activity.
