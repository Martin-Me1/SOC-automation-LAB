# 🛡️ SOC AUTOMATION LAB

![SOAR](https://img.shields.io/badge/SOAR-Shuffle-blue)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh-yellow)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-T1003-red)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen)

---

## Architecture

The goal was to detect credential dumping in real-time and automate incident response actions. This includes alert triage, threat intelligence enrichment, and active blocking of malicious sources.

The detection starts at the endpoint and flows through Wazuh, Shuffle, VirusTotal, and TheHive. Each system plays a distinct role in visibility, automation, and triage.

---

## Startup Flow

Mimikatz Execution → Wazuh Alert → Shuffle Webhook Trigger →  
Regex Extraction (SHA256) → VirusTotal Reputation Check →  
Alert to TheHive → Email Analyst → Wazuh IP Block

---

## File Structure

```text
mimikatz-detection-response/
├── wazuh/
│   ├── local_rules.xml
│   └── ossec.conf
├── shuffle/
│   └── workflow_export.json
├── thehive/
│   └── alert_payload.json
├── mimikatz_demo/
│   └── run_mimikatz.ps1
├── screenshots/
│   └── *.png
└── README.md
```

---

## Key Components

- `local_rules.xml`: Wazuh rule to detect Mimikatz using original filename metadata
- `ossec.conf`: Configured to collect Sysmon event logs from EventChannel
- `workflow_export.json`: Shuffle automation extracting SHA256 and sending alerts
- `alert_payload.json`: Alert body for TheHive using dynamic inputs from execution
- `run_mimikatz.ps1`: PowerShell script to simulate an attack for testing

---

## Example Wazuh Rule

```xml
<rule id="100002" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
  <description>Mimikatz Usage Detected</description>
  <mitre>
    <id>T1003</id>
  </mitre>
</rule>
```

---

## Example Alert Body (TheHive)

```json
{
  "title": "Mimikatz Detected",
  "description": "Mimikatz detected on host: {{ exec.all_fields.data.win.system.computer }}",
  "summary": "PID: {{ exec.all_fields.data.win.system.processID }} | Cmd: {{ exec.all_fields.data.win.eventdata.commandLine }}",
  "severity": 2,
  "tlp": 2,
  "pap": 2,
  "tags": ["T1003", "Mimikatz"],
  "source": "Wazuh",
  "status": "New"
}
```
