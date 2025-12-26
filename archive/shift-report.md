Incident Title



**Suspicious PowerShell-Initiated Process Chain Observed on Windows Endpoint**



Incident ID



SOC-LAB-EDR-001



Date / Time

2025-12-26 10:55



Analyst



Ahmad Albaige



Environment



Endpoint OS: Windows 10 (x64)



Endpoint Type: User workstation (VM)



EDR Platform: LimaCharlie



Sensor Status: Online



User Context: Standard user (interactive session)



##### Executive Summary



During routine endpoint telemetry review, a suspicious process execution chain was observed involving PowerShell spawning cmd.exe, which subsequently launched a secondary user application. While no malicious payload was identified, the execution pattern matches LOLBins-style behavior commonly associated with initial access, script abuse, or post-exploitation activity. The incident was investigated, validated, and classified as benign simulated activity within a controlled lab environment.



##### Detection Source



Telemetry Type: Endpoint process creation events



Event Type: NEW\_PROCESS



Detection Method: Manual EDR timeline review (Tree View)



Observed Process Tree

Explorer.exe

└── PowerShell.exe

    └── cmd.exe

        └── notepad.exe



##### Investigation Details

##### Initial Observation



The analyst identified a NEW\_PROCESS event where PowerShell.exe was launched from the Windows Explorer shell, indicating interactive user execution rather than a background service or scheduled task.



Process Ancestry Analysis



Using the EDR Tree View, the following execution flow was confirmed:



Explorer.exe initiated PowerShell.exe



PowerShell.exe spawned cmd.exe using command-line execution



cmd.exe launched notepad.exe as a child process



The process chain completed successfully and terminated normally



Command-line arguments confirmed intentional process chaining (cmd.exe /c notepad.exe).



Behavior Assessment



This execution pattern is considered suspicious by behavior, as it demonstrates:



Script interpreter usage



Shell-based child process spawning



Indirect execution of a secondary process



No persistence mechanisms, lateral movement, or network-based indicators were observed.



##### Impact Assessment



Malware Identified: No



Persistence Observed: No



Data Exfiltration: No



Privilege Escalation: No



Business Impact: None



##### Root Cause



The activity was generated intentionally as part of a controlled EDR lab exercise to validate endpoint visibility and process ancestry tracking.



##### Containment \& Response



No containment actions were required



Endpoint remained monitored



No isolation or remediation was necessary



##### Final Classification



Benign — Simulated Suspicious Activity

##### 

##### Lessons Learned

* 
* Endpoint telemetry provides clear visibility into parent/child process relationships
* 
* PowerShell-initiated shell execution remains a high-value signal for SOC monitoring
* 
* Tree-based visualization significantly accelerates investigation compared to flat logs
* 
* Behavioral context is critical when distinguishing malicious activity from legitimate user actions

##### 

##### Recommendations

* 
* Maintain monitoring for script-based execution chains
* 
* Consider alerting thresholds for PowerShell spawning secondary shells
* 
* Use process ancestry as a primary triage signal in endpoint investigations
