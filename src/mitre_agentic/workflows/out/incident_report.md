# Executive Incident Report

## Title
Suspicious Activity Detected Involving WINWORD.EXE and Powershell

## Executive Summary
An EDR alert indicated that WINWORD.EXE spawned powershell.exe with an encoded command, suggesting potential malicious activity. Following this, rundll32.exe executed a suspicious DLL entrypoint, and a scheduled task was created for persistence. Additionally, network connections to an unfamiliar external IP were observed, indicating possible command and control activity. Immediate investigation and remediation actions are recommended to mitigate potential threats.

## Likely Attack Flow
- WINWORD.EXE initiated a process to execute powershell.exe with an encoded command.
- Powershell executed potentially malicious scripts or commands.
- Rundll32.exe was triggered to execute a suspicious DLL, indicating further exploitation.
- A scheduled task was created to ensure persistence of the malicious activity.
- Network connections were established to an unfamiliar external IP, suggesting command and control communication.

## Mapped Techniques
- T1059.001 PowerShell (Execution)
- T1218 System Binary Proxy Execution (Defense Evasion)
- T1053.005 Scheduled Task (Execution, Persistence, Privilege Escalation)
- T1071.001 Web Protocols (Command And Control)

## Notable Groups and Software
- Groups associated with PowerShell usage include WIRTE, APT42, APT5, Blue Mockingbird, APT39.
- Groups associated with System Binary Proxy Execution include Lazarus Group and Volt Typhoon.
- Groups associated with Scheduled Task creation include APT3, Cobalt Group, Silence, Chimera, Patchwork.
- Groups associated with Web Protocols for command and control include Rancor, Metador, RedEcho, BITTER, Moonstone Sleet.

## Detection Recommendations
- Implement monitoring for unusual process spawning, particularly from WINWORD.EXE and powershell.exe.
- Enhance logging and alerting for scheduled task creations and rundll32.exe executions.
- Establish network traffic analysis to identify and block connections to unfamiliar external IPs.

## Immediate Actions
- Isolate affected systems to prevent further spread of potential malware.
- Conduct a thorough investigation of the processes and network connections involved.
- Review and analyze the scheduled tasks created during the incident.

## Indicators of Compromise (IOCs)
### Suspected Artifacts
- Encoded command executed by powershell.exe
- Suspicious DLL executed by rundll32.exe

### Suspicious Processes
- WINWORD.EXE
- powershell.exe
- rundll32.exe

### Suspicious Network
- Unfamiliar external IP addresses