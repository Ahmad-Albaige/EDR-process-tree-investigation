## EDR → SIEM Process Tree Investigation



**LimaCharlie · Python · Splunk**



##### Overview

##### 

This project demonstrates an end-to-end SOC investigation workflow where raw EDR telemetry is collected, enriched with Python, and ingested into a SIEM (Splunk) for analysis.



The focus is on detecting and understanding PowerShell-based process execution chains, a technique commonly investigated in SOC environments due to its frequent abuse by attackers



##### Architecture

* Windows 10 VM
* LimaCharlie EDR Sensor
* Raw EDR JSON Events
* Python Enrichment Script
* Enriched Log File (UTF-8)
* Splunk Universal Forwarder
* Splunk Enterprise (Ubuntu vm)



##### Lab Environment



**Endpoint**

* Windows 10 VM
* LimaCharlie Sensor installed
* Splunk Universal Forwarder installed
* Python 3.14



**SIEM**

Splunk Enterprise (Ubuntu VM)



##### What the Project Does?



1. **Collects EDR process creation events from LimaCharlie**
2. **Parses raw JSON telemetry using Python**
3. **Builds parent → child process relationships**
4. **Filters noise (e.g. Splunk internal processes)**
5. **Writes enriched events to a custom log file**
6. **Ingests enriched logs into Splunk**
7. **Searches and validates results in Splunk**



##### Example Use Case

Why this matters:
- PowerShell spawning secondary interpreters is frequently abused to evade simple signature-based detection.
- Parent-child relationships provide stronger detection context than single-event alerts.



Observed behavior:



Explorer.exe

&nbsp;└─ PowerShell.exe

&nbsp;   └─ python.exe





This type of execution chain is high-risk in real environments and often associated with:



**Initial access**

**Script-based payload execution**

**Living-off-the-land techniques**



Python Enrichment Output (Example)

{

&nbsp; "event\_type": "powershell\_process\_chain",

&nbsp; "parent\_process": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\PowerShell.exe",

&nbsp; "child\_process": "C:\\\\Program Files\\\\Python314\\\\python.exe",

&nbsp; "timestamp": "2025-12-26T13:10:41Z",

&nbsp; "source": "limacharlie\_edr",

&nbsp; "user": null

}



Splunk Ingestion

Log File

C:\\Logs\\edr\_enriched.log



Sourcetype

edr:enriched:powershell



Splunk Search (spl)

index=main sourcetype=edr:enriched:powershell


## Analyst Takeaways
- Demonstrates how raw EDR telemetry can be transformed into investigation-ready context.
- Shows the value of parent-child process analysis over standalone process alerts.
- Mirrors real SOC workflows: collect → enrich → ingest → investigate.


