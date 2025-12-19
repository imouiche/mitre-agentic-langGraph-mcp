# Executive Incident Report: Suspicious Execution and Persistence via WINWORD.EXE and PowerShell

## Executive Summary

An endpoint detection and response (EDR) alert identified suspicious activity involving WINWORD.EXE spawning powershell.exe with an encoded command, followed by rundll32.exe executing a suspicious DLL entrypoint. Additionally, a scheduled task was created, likely for persistence, and network connections to an unfamiliar external IP address were observed. These behaviors indicate a potential multi-stage attack involving execution, persistence, defense evasion, and command and control on a Windows system. The attack techniques map to known adversary behaviors and malware families, suggesting a targeted intrusion attempt. Immediate containment and investigation actions are recommended to prevent further compromise and data exfiltration.

---

## Likely Attack Flow

- WINWORD.EXE spawns powershell.exe with an encoded command to execute malicious payload
- Powershell executes encoded commands to establish foothold or download additional tools
- Rundll32.exe runs with a suspicious DLL entrypoint to evade detection via system binary proxy execution
- Creation of a scheduled task to maintain persistence across reboots
- Scheduled task configured to execute malicious payload or commands periodically
- Network connections initiated to an unfamiliar external IP for command and control communication
- Potential data exfiltration or remote control established via web protocols
- Adversary leverages legitimate Windows binaries to bypass security controls
- Persistence mechanism ensures continued access despite system restarts
- Unfamiliar external IP indicates possible attacker infrastructure or staging server

---

## Mapped Techniques

- T1059.001 PowerShell (Execution)
- T1218 System Binary Proxy Execution (Defense Evasion)
- T1053.005 Scheduled Task (Execution, Persistence, Privilege Escalation)
- T1071.001 Web Protocols (Command And Control)

---

## Notable Groups and Software

- Groups associated with PowerShell execution: WIRTE, APT42, APT5, Blue Mockingbird, APT39
- Malware leveraging PowerShell: Empire, Covenant, Pupy, Koadic, Sliver
- Groups known for System Binary Proxy Execution: Lazarus Group, Volt Typhoon
- Groups using Scheduled Tasks for persistence: APT3, Cobalt Group, Silence, Chimera, Patchwork
- Software using Scheduled Tasks: CSPY Downloader, IronNetInjector, PowerSploit, MCMD, Empire
- Groups using Web Protocols for C2: Rancor, Metador, RedEcho, BITTER, Moonstone Sleet
- C2 Frameworks: PoshC2, PcShare, Out1, Mythic, Quick Assist

---

## Detection Recommendations

- Monitor for encoded PowerShell commands spawned by WINWORD.EXE and other Office applications
- Alert on rundll32.exe executions with non-standard DLL entrypoints or unusual command-line arguments
- Detect creation and modification of scheduled tasks, especially those created by non-administrative users
- Monitor outbound network connections to unfamiliar or suspicious external IP addresses using web protocols
- Implement behavioral analytics to identify system binary proxy execution patterns
- Correlate process spawning chains involving Office apps, PowerShell, and rundll32.exe
- Use endpoint detection rules to flag encoded or obfuscated PowerShell scripts
- Audit scheduled task configurations and execution history for anomalies
- Leverage network intrusion detection/prevention systems to block known malicious C2 traffic
- Enable logging of command-line arguments for critical system binaries

---

## Immediate Actions

- Isolate affected endpoints from the network to prevent lateral movement and data exfiltration
- Collect and analyze memory and disk artifacts from the impacted systems for forensic investigation
- Identify and disable suspicious scheduled tasks created during the incident timeframe
- Block network communications to the identified unfamiliar external IP addresses at the firewall
- Review and revoke any suspicious or unauthorized privileged accounts or credentials
- Deploy updated detection signatures targeting encoded PowerShell usage and rundll32 proxy execution
- Conduct a full malware scan and remediation on affected hosts
- Notify relevant internal teams and stakeholders of the incident and ongoing response
- Preserve logs and evidence for potential legal or regulatory requirements
- Plan for a comprehensive post-incident review and hardening of affected systems

---

## Indicators of Compromise (IOCs)

### Suspected Artifacts
- Encoded PowerShell command spawned by WINWORD.EXE
- Suspicious DLL loaded by rundll32.exe
- Scheduled task created for persistence

### Suspicious Processes
- WINWORD.EXE spawning powershell.exe with encoded command
- powershell.exe executing encoded commands
- rundll32.exe executing suspicious DLL

### Suspicious Network
- Network connections to unfamiliar external IP address (specific IP unknown)

---

## Navigator Layer Path

out/incident_layer.json