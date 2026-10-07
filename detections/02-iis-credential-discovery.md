## Encoded PowerShell Analysis

The PowerShell parent process used the `-enc` argument.

After decoding the Base64 content as UTF-16LE, the script was observed performing the following actions:

1. Accessing two files from:

   C:\Windows\Temp\6jrxk3\

2. Reading the files as raw bytes.

3. Using a hard-coded key to XOR-decrypt the file contents.

4. Converting the decrypted data into UTF-8 strings.

5. Combining the decrypted module and application code.

6. Executing the resulting code using:

   Invoke-Expression (`iex`)

7. Removing one of the temporary files after execution.

## Suspicious Behavior

The following behaviors increase the severity of this event:

- Encoded PowerShell execution
- Payload storage in Windows Temp
- XOR-based payload decryption
- In-memory execution using Invoke-Expression
- Cleanup of temporary artifacts
- Execution of appcmd.exe to retrieve IIS credentials

## Assessment

This activity is highly suspicious.

The event indicates that PowerShell was used to decode and execute an obfuscated payload in memory.

The resulting execution chain also included AppCmd.exe retrieving IIS virtual directory password information.

This behavior is consistent with credential discovery combined with PowerShell-based execution and defense evasion techniques.

## MITRE ATT&CK Mapping

T1059.001 - Command and Scripting Interpreter: PowerShell

T1027 - Obfuscated/Compressed Files and Information

T1140 - Deobfuscate/Decode Files or Information

T1055 or other in-memory execution techniques may require additional evidence before attribution.

T1552.001 - Unsecured Credentials: Credentials In Files
