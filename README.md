# azure-sentinel-soc-lab
Cloud-native SIEM engineering project utilizing Microsoft Sentinel to ingest Linux syslog telemetry, map persistent brute-force infrastructure, and deploy proactive threat intelligence watchlists.

# Cloud SIEM Engineering: End-to-End Threat Detection & Infrastructure Mapping in Microsoft Sentinel

## 📑 Executive Summary
This project demonstrates the deployment of an enterprise-grade cloud Security Operations Center (SOC) framework leveraging **Microsoft Sentinel (SIEM)**. The objective was to expose a vulnerable public-facing Linux asset (`vm1`), analyze real-time malicious ingestion metrics via **Kusto Query Language (KQL)**, enrich localized alerts with open-source threat intelligence (OSINT), map adversary infrastructure via global BGP routing topologies, and build custom watchlists to minimize corporate risk.

---

## 🏗️ Architectural Framework & Skillsets
* **Cloud Infrastructure:** Microsoft Azure (Virtual Machines, Network Security Groups, Log Analytics Workspaces)
* **SIEM Analytics:** Microsoft Sentinel
* **Query & Scripting Languages:** Kusto Query Language (KQL), PowerShell (Raw TCP Network Sockets)
* **Core Domains:** Open Source Intelligence (OSINT), Border Gateway Protocol (BGP) Topology, Digital Forensics & Incident Response (DFIR), Defensive Architecture (Whitelisting/Hardening)

---

## 🛠️ Phase-by-Phase Technical Walkthrough

### Phase 1: Environment Provisioning & Logging Ingestion Pipelines
* Provisioned an unhardened Linux Virtual Machine (`vm1`) exposed to the public internet via an open **SSH (Port 22)** configuration to serve as an authentic honeypot hone.
* Established an Azure Log Analytics Workspace (`soc-log-workspace`) and onboarded **Microsoft Sentinel**.
* Configured native security logs forwarding policies to stream operating-system level authentication and access logs directly into the centralized SIEM datastore.
* 

### Phase 2: Threat Emulation (Controlled Baselines)
To validate ingestion health and establish a verified baseline, an adversarial simulation was executed locally from an administrative workspace using raw Windows PowerShell network sockets:
```powershell
New-Object System.Net.Sockets.TcpClient("YOUR_VM_IP", 22)

This simulated attack bypassed application layer errors to guarantee that a transport-layer cryptographic handshake was successfully cataloged inside the sshd daemon logging tables.

### Phase 3: Live Incident Triage & KQL Analysis
Within minutes of activation, automated global botnets initiated brute-force credential-stuffing campaigns against vm1. Custom KQL correlation analytics were built to parse and map the traffic spikes:
<img width="1127" height="827" alt="195 178 110 217" src="https://github.com/user-attachments/assets/ebe0c65a-9f8b-4fc4-a56f-cd4b85744627" />


Code snippet
Syslog
| where ProcessName == "sshd"
| where SyslogMessage has "Failed password" or SyslogMessage has "invalid user"
| extend AttackingIP = extract(@"from ([0-9.]+)", 1, SyslogMessage)
| summarize AttemptCount = count() by AttackingIP, Computer
| top 10 by AttemptCount
High-Severity Incidents were automatically triggered within Sentinel as external nodes concurrently hammered system accounts (root, admin).

### Phase 4: OSINT Enrichment & BGP Routing Deep-Dives
Pivoting on a highly active attacking entity signature (195.178.110.217), external Open Source Intelligence (OSINT) tools were introduced to reconstruct the threat actor's profile:

AbuseIPDB Lookup: Confirmed a 100% Abuse Confidence Score with thousands of historical global abuse records, resolving to a hosting center in Amsterdam, Netherlands.
<img width="827" height="797" alt="AbuseIPDB" src="https://github.com/user-attachments/assets/95210fbe-e7ad-4770-a756-6aecc180c289" />

Hurricane Electric BGP Toolkit: Escalated the triage to network infrastructure routing layers. Discovered that the target IP lies within the 195.178.110.0/24 subnet managed under Autonomous System Number AS48090.
<img width="1526" height="922" alt="image" src="https://github.com/user-attachments/assets/aa823566-7a0d-4c08-8c30-3165e78350ef" />

Operational Insight: While geolocated to Andorra by internal SIEM maps and Amsterdam by active proxies, the regional registry allocation (RIPE NCC) traced back to Bulgaria (BG) under a United Kingdom ASN registration. This layout highlights classic adversary proxy/VPS chaining used to obfuscate operational origins.

<img width="1312" height="305" alt="image" src="https://github.com/user-attachments/assets/217ddc41-3c3e-4d76-8591-0ca3d666a77f" />


Phase 5: Operationalizing Threat Intelligence via Sentinel Watchlists
To optimize analytical detection over static, processing-heavy query logic, a custom threat intelligence Watchlist (KnownMaliciousHostingIPs) was engineered into the SIEM database.
<img width="1240" height="807" alt="sentinel-watchlist-correlation" src="https://github.com/user-attachments/assets/3a144b67-cce1-4620-a1b5-9ea608c30861" />


By parsing incoming streams dynamically against the watchlist array using structured sub-second relational lookups, high-fidelity security alerts were achieved:

Code snippet
let MaliciousThreatIntel = _GetWatchlist('KnownMaliciousHostingIPs') | project IpAddress;
Syslog
| where ProcessName == "sshd"
| extend AttackingIP = extract(@"from ([0-9.]+)", 1, SyslogMessage)
| where AttackingIP in (MaliciousThreatIntel)
| project TimeGenerated, Computer, AttackingIP, SyslogMessage
Phase 6: Perimeter Containment & Remediation
Following data collection, incident response remediation protocols were deployed:

Navigated to the cloud fabric boundary at the Azure Network Security Group (NSG) level.

Reconfigured the perimeter rule for Port 22 from Any to IP Addresses, explicitly whitelisting only the administrator's trusted public workstation.

Effectively dropped all unauthorized global scanner probes at the cloud edge before reaching the internal OS platform layer.

📈 Analytical Conclusion & Strategic Takeaways
Automated Exploitation Scale: Threat actors programmatically harvest internet-facing subnets within minutes of creation; perimeter defense-in-depth is mandatory.

Telemetry Optimization: Leveraging native tools like Sentinel Watchlists cuts down CPU overhead during multi-gigabyte log cross-correlations.

The Analyst Mindset: True threat detection requires moving beyond a simple IP alert; pivoting to subnets, ASNs, and BGP peering networks reveals the true scale of adversarial operations.


---

### 🖼️ Recommended Image Mapping Sequence
To match the high quality of your write-up, upload your screenshots into an `images` directory in the repository and embed them into the Markdown text using the following format:

1. **Initial Shell Failures/Validation:** Reference `image_499d06.png` or your working PowerShell TCP handshake to demonstrate the initial validation phase.
2. **The Sentinel Incident Board:** Embed `image_4a09c6.png` or `image_f9c07e.png` to display active incident lists.
3. **The Investigation Panel:** Use `image_fa3823.png` to document the visual alert spike timeline.
4. **OSINT Verification:** Place `image_fa432a.png` (AbuseIPDB 100% rating) to highlight the threat classification phase.
5. **BGP/Network Topology:** Embed `image_faa583.png` or `image_faa8e2.png` to highlight structural network footprinting capabilities.
6. **Watchlist Validation:** Conclude with `image_fabbc9.png` to show the successful live KQL execution against your custom threat-intel matrix.

Name your files clearly (e.g., `sentinel-triage.png`, `bgp-routing.png`) so your repository looks
