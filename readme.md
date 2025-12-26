# **EDR Process Tree Investigation**



#### Overview



This project demonstrates hands-on EDR investigation on a Windows endpoint, focusing on process ancestry analysis and identification of a suspicious execution chain.



Validate endpoint visibility and document the investigation in a SOC-ready format.



\-

#### Scenario



Telemetry was produced by a Windows workstation that showed PowerShell spawning cmd.exe, which in turn spawned a secondary process.



The behavior mimicked **LOLBins-style execution**, commonly trended within SOC environments.

Observed Process Tree

Explorer.exe

└── PowerShell.exe

└── cmd.exe

└── notepad.exe



#### Proof



EDR Tree View showing the full parent/child process chain



Command-line execution captured by endpoint telemetry



Screenshots are available in the `screenshots/` directory.







#### Documentation

A professional SOC-style incident report is included:

shift-report.md





#### Skills Demonstrated



* Endpoint telemetry analysis
* Ancestry research process
* Filtering noise and correlating events
* SOC-quality incident documentation .



 Environment Operating System: Windows 10 (x64) The EDR platform is LimaCharlie. Activity Type: Controlled lab simulation

