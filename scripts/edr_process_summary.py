import json
from datetime import datetime

LOG_FILE = r"C:\Logs\edr_enriched.log"
with open(r"C:\Users\employee01\python-lab\edr_events.json", "r", encoding="utf-8") as f:

    events = json.load(f)

print("Writing enriched PowerShell process events to log file...\n")

# Open the Splunk-monitored log file in APPEND mode
with open(LOG_FILE, "a", encoding="utf-8") as logfile:
    for entry in events:
        # Filter: process creation only
        if entry.get("routing", {}).get("event_type") != "NEW_PROCESS":
            continue

        event = entry.get("event", {})
        parent = event.get("PARENT", {})

        child_path = event.get("FILE_PATH")
        parent_path = parent.get("FILE_PATH")

        if (not parent_path) or (not child_path):
            continue

        parent_lc = parent_path.lower()
        child_lc = child_path.lower()

        # Keep only PowerShell-related events
        if ("powershell" not in parent_lc) and ("powershell" not in child_lc):
            continue

        # Exclude Splunk helper noise
        if "splunk-powershell.exe" in child_lc:
            continue

        # Build ONE clean event (this is what Splunk will index)
        enriched_event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "parent_process": parent_path,
            "child_process": child_path,
            "user": event.get("USER_NAME"),
            "source": "limacharlie_edr",
            "event_type": "powershell_process_chain"
        }

        # Write as ONE JSON line
        logfile.write(json.dumps(enriched_event) + "\n")

        # Optional: also show on screen
        print(f"{parent_path}  -->  {child_path}")
