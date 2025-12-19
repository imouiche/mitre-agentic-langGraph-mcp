# Executive Incident Report

## Title
Suspicious PowerShell and DLL Execution with Persistence and External Network Connections

## Executive Summary
An endpoint detection and response (EDR) alert identified suspicious activity involving WINWORD.EXE spawning powershell.exe with an encoded command, indicative of potential malicious script execution. Subsequently, rundll32.exe executed a suspicious DLL entrypoint, and a scheduled task was created, likely to maintain persistence. Network connections to an unfamiliar external IP address were observed, suggesting possible command and control (C2) communication. The attack techniques align with known adversary behaviors involving PowerShell execution, system binary proxy execution, scheduled tasks for persistence, and web protocols for C2. Immediate containment and investigation actions are recommended to prevent further compromise and to identify the scope of the intrusion.

## Likely Attack Flow
- WINWORD.EXE spawns powershell.exe with an encoded command to execute malicious scripts.
- Powershell executes commands potentially to download or execute additional payloads.
- Rundll32.exe runs a suspicious DLL entrypoint, possibly to evade detection via system binary proxy execution.
- A scheduled task is created to establish persistence on the system.
- The compromised host initiates network connections to an unfamiliar external IP, indicating potential command and control communication.
- Adversaries may leverage these footholds to escalate privileges or move laterally within the network.

## Mapped Techniques
- T1059.001 PowerShell (Execution)
- T1218 System Binary Proxy Execution (Defense Evasion)
- T1053.005 Scheduled Task (Execution, Persistence, Privilege Escalation)
- T1071.001 Web Protocols (Command And Control)

## Notable Groups and Software
- PowerShell (T1059.001): Groups - WIRTE, APT42, APT5, Blue Mockingbird, APT39; Software - Empire, Covenant, Pupy, Koadic, Sliver
- System Binary Proxy Execution (T1218): Groups - Lazarus Group, Volt Typhoon
- Scheduled Task (T1053.005): Groups - APT3, Cobalt Group, Silence, Chimera, Patchwork; Software - CSPY Downloader, IronNetInjector, PowerSploit, MCMD, Empire
- Web Protocols (T1071.001): Groups - Rancor, Metador, RedEcho, BITTER, Moonstone Sleet; Software - PoshC2, PcShare, Out1, Mythic, Quick Assist

## Detection Recommendations
- Monitor for encoded or obfuscated PowerShell commands, especially those spawned by WINWORD.EXE or other Office applications.
- Alert on rundll32.exe executions with non-standard DLL entrypoints or unusual command-line arguments.
- Detect creation and modification of scheduled tasks, particularly those created outside of normal maintenance windows or by uncommon users.
- Monitor outbound network connections to unfamiliar or suspicious external IP addresses, focusing on web protocols such as HTTP/HTTPS.
- Implement behavioral analytics to identify anomalous process spawning and persistence mechanisms.
- Correlate alerts across PowerShell execution, system binary proxy usage, scheduled task creation, and network activity for comprehensive detection.
- Leverage threat intelligence feeds to identify known malicious IPs and domains involved in command and control.

## Immediate Actions
- Isolate affected endpoints to prevent lateral movement and further data exfiltration.
- Collect and preserve forensic evidence including process execution logs, scheduled task configurations, and network traffic captures.
- Perform a full malware scan and endpoint investigation focusing on PowerShell scripts, DLLs loaded by rundll32.exe, and scheduled tasks.
- Block identified suspicious external IP addresses at the network perimeter.
- Review and restrict permissions for creating scheduled tasks and executing system binaries like rundll32.exe and powershell.exe.
- Update detection rules and signatures to include indicators observed in this incident.
- Notify relevant internal teams and stakeholders about the incident and ongoing response efforts.

## Indicators of Compromise (IOCs)
### Suspected Artifacts
- Encoded PowerShell command spawned by WINWORD.EXE
- Suspicious DLL loaded by rundll32.exe
- Scheduled task created for persistence

### Suspicious Processes
- WINWORD.EXE spawning powershell.exe with encoded command
- rundll32.exe executing suspicious DLL entrypoint
- powershell.exe with encoded or obfuscated command lines

### Suspicious Network
- Outbound connections to unfamiliar external IP address (specific IP unknown)

## Navigator Layer Path
../out/incident_layer.json