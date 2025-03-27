**#SOC automation LAB**

**##Objective**
Design and implement a real time detection and automated response workflow for credential dumping attacks using open source tools. The goal was to detect Mimikatz activity on a Windows host, test reputation via VirusTotal, and from thehive escalate it to a SOC analyst via email, and optionally trigger a firewall block through Wazuh — all orchestrated using Shuffle automation.

**###Skills Learned```**

- Built and automated a complete detection and response pipeline using Shuffle, Wazuh, and TheHive
- Wrote custom detection rules in Wazuh to identify Mimikatz execution using binary metadata
- Used regular expressions and JSON parsing to extract and enrich alert data
- Worked with public threat intelligence APIs (VirusTotal) for automated reputation checks
- Created actionable SOC alerts and notifications based on MITRE ATT&CK techniques
- Performed live testing and validation using real attack tools in a controlled cloud lab

**### Tools Used:**
Shuffle, Wazuh, DigitalOcean (CSP), Sysmon, Mimikatz, TheHive, VirusTotal

- Shuffle (SOAR platform) for automation workflows and integrations
- Wazuh (SIEM + Host-based IDS) for rule creation, alerting, and active response
- DigitalOcean for cloud infrastructure (Wazuh, TheHive, VM agents)
- Sysmon for detailed Windows system logging
- Mimikatz to simulate credential dumping behavior
- TheHive for alert intake and SOC triage
- VirusTotal API for hash enrichment
- SquareX (disposable email) to simulate SOC notifications

**1. Initial Setup**
Set up a cloud server using DigitalOcean and installed Wazuh and TheHive. Deployed a Windows 10 VM with Sysmon and Mimikatz for simulating attacker behavior.

**2. Writing Custom Wazuh Rules**
Created a custom rule in local_rules.xml to detect Mimikatz using the originalFileName field:

<rule id="100002" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
  <options>no_full_log</options>
  <description>Mimikatz Usage Detected</description>
  <mitre>
    <id>T1003</id>
  </mitre>
</rule>

This targets the actual metadata in the binary rather than just the file name. I renamed mimikatz.exe to thisissupersafe.exe and it still triggered the alert.

**3. Feeding in Sysmon Data**
Configured ossec.conf to enable Sysmon log collection:

<localfile>
  <location>EventChannel</location>
  <log_format>eventchannel</log_format>
</localfile>

This allowed Wazuh to collect detailed logs about process execution, which was key for tracking attacker behavior.

**4. Expanding Visibility**
Added the following index pattern to Kibana to make sure nothing was missed:

wazuh-archives-*

This ensures visibility into full archived traffic including rule matches and raw event content.

**5. Connecting Shuffle with Webhooks**
Generated a webhook in Shuffle and added it to Wazuh’s ossec.conf:

<integration>
  <name>shuffle</name>
  <hook_url>https://shuffle_url/webhook</hook_url>
  <level>15</level>
  <rule_id>100002</rule_id>
</integration>

This was configured to only send high-level alerts (15) tied to our Mimikatz rule.

**6. Live Alert Testing**
Executed Mimikatz on the Windows VM:

.\mimikatz.exe "privilege::debug" "log" "sekurlsa::logonpasswords" "exit"

Confirmed the alert hit Wazuh, triggered the webhook, and was received by Shuffle.

**7. Building the Automation Workflow**
Designed a modular workflow:

Mimikatz alert hits Shuffle

Regex captures SHA256 hash

VirusTotal checks reputation

If malicious, an alert is created in TheHive

Optional email is sent to the SOC analyst

**8. Hash Extraction with Regex**
Used this regex in Shuffle's Regex Capture Group node:

SHA256=([0-9A-Fa-f]{64})

It successfully isolated the SHA256 hash from the Wazuh event logs.

**9. VirusTotal Integration**
Queried the hash using VirusTotal’s API:

GET https://www.virustotal.com/api/v3/files/{sha256_hash}
Authorization: Bearer <API_KEY>

Received enriched results, including whether the hash was flagged as malicious.

**10. Creating Rich Alerts in TheHive**
Used Shuffle to push alerts into TheHive using the following body:

{
  "title": "Mimikatz Detected",
  "description": "Mimikatz detected on host: {{ exec.all_fields.data.win.system.computer }} by user: {{ exec.all_fields.data.win.eventdata.user }}",
  "summary": "Process ID: {{ exec.all_fields.data.win.system.processID }}\nCommand Line: {{ exec.all_fields.data.win.eventdata.commandLine }}",
  "tags": ["T1003"],
  "severity": 2,
  "tlp": 2,
  "pap": 2,
  "source": "Wazuh",
  "sourceRef": "100002",
  "type": "external",
  "status": "New"
}

**11. Firewall Rule Update for Testing**
Opened up port 9000 on DigitalOcean firewall to allow Shuffle to send alerts to TheHive:

Port: 9000
Protocol: TCP
Sources: All IPv4

**12. Email Integration with Shuffle**
Used Shuffle’s email app to send alerts:

{
  "to": "analyst@squarex.email",
  "subject": "Mimikatz Detected",
  "body": "Alert received for host {{ computer }} at {{ timestamp }}."
}

Used SquareX disposable email to simulate SOC notifications.

**13. Kicking Off Active Response**
Used Shuffle to call Wazuh’s API and trigger a firewall drop:

curl -X POST https://<wazuh_ip>:55000/active-response/run \
  -H "Authorization: Bearer <jwt_token>" \
  -d '{"command":"firewalldrop","arguments":["<malicious_ip>"]}'

Tested it by pinging the blocked IP before and after the command — confirmed it was dropped.

**14. Analyst-Driven Blocking with User Input**
Added a user prompt step in Shuffle that asked:

Would you like to block the source IP {{ malicious_ip }}?

If the analyst approved, the IP was added to the blocklist using Wazuh’s API.

Conclusion:
I had a lot of fun with this one, the project tied together real time detection, enrichment, alerting, and response into one clean automation flow. The configuration with Wazuh and Shuffle gave me solid insight into building a practical SOC pipeline, and the final result was flexible enough to extend further for future use cases.

