# ☁️ Azure Sentinel SOC Lab

> **Enterprise cloud SIEM project demonstrating end-to-end threat detection, investigation, threat intelligence enrichment, and incident response using Microsoft Sentinel.**

---

## 📖 Overview

This project demonstrates the deployment of a cloud-native Security Operations Center (SOC) using **Microsoft Azure** and **Microsoft Sentinel**.

A deliberately exposed Linux virtual machine was deployed to simulate a vulnerable internet-facing asset. After enabling centralized log collection, the environment attracted real-world brute-force attacks from automated threat actors within minutes.

Using Microsoft Sentinel and Kusto Query Language (KQL), authentication failures were investigated, malicious infrastructure was enriched with OSINT, mapped to Autonomous Systems (ASNs), and operationalized through custom Sentinel Watchlists before hardening the environment.

---

## 🎯 Project Objectives

* Deploy a cloud-based SIEM solution
* Collect Linux Syslog telemetry
* Detect SSH brute-force attacks
* Investigate attacker infrastructure
* Enrich alerts with OSINT intelligence
* Build custom Sentinel Watchlists
* Harden cloud perimeter security

---

## 🏗️ Architecture

```text
                 Internet
                     │
        Automated SSH Attackers
                     │
                     ▼
           Azure Linux VM (vm1)
                     │
                 Syslog Agent
                     │
                     ▼
        Log Analytics Workspace
                     │
                     ▼
          Microsoft Sentinel
                     │
      ┌──────────────┴──────────────┐
      │                             │
 KQL Detection               Watchlists
      │                             │
      └──────────────┬──────────────┘
                     │
                     ▼
        Threat Investigation
                     │
                     ▼
      OSINT + ASN/BGP Enrichment
                     │
                     ▼
      Security Hardening (NSG)
```

---

# 🛠️ Technologies Used

| Category             | Technology                     |
| -------------------- | ------------------------------ |
| Cloud Platform       | Microsoft Azure                |
| SIEM                 | Microsoft Sentinel             |
| Log Collection       | Azure Log Analytics            |
| Operating System     | Ubuntu Linux                   |
| Query Language       | Kusto Query Language (KQL)     |
| Scripting            | PowerShell                     |
| Threat Intelligence  | AbuseIPDB                      |
| Network Intelligence | Hurricane Electric BGP Toolkit |
| Networking           | Network Security Groups (NSG)  |

---

# 📌 Phase 1 – Environment Deployment

Resources deployed:

* Azure Resource Group
* Ubuntu Linux Virtual Machine (`vm1`)
* Public IP Address
* Network Security Group
* Log Analytics Workspace
* Microsoft Sentinel

The VM was intentionally configured with an unrestricted inbound SSH rule to attract internet-wide scanning activity and generate authentic security telemetry.

---

# 📌 Phase 2 – Connectivity Validation

Before monitoring production traffic, SSH connectivity was validated using a raw TCP connection from PowerShell.

```powershell
New-Object System.Net.Sockets.TcpClient("YOUR_VM_IP",22)
```

This confirmed successful communication over TCP port 22 and verified that authentication events were being ingested into Sentinel.

---

# 📌 Phase 3 – Detecting SSH Brute Force Activity

Within minutes, automated internet scanners began attempting SSH logins against the Linux VM.

The following KQL query identified the most active attacking IP addresses.

```kql
Syslog
| where ProcessName == "sshd"
| where SyslogMessage has "Failed password"
    or SyslogMessage has "invalid user"
| extend AttackingIP = extract(@"from ([0-9.]+)",1,SyslogMessage)
| summarize Attempts=count() by AttackingIP, Computer
| top 10 by Attempts
```
<img width="1000" height="700" alt="195 178 110 217" src="https://github.com/user-attachments/assets/9978f98b-3d31-4958-ac46-13954e77ef7f" />
---

# 📌 Phase 4 – Threat Intelligence Enrichment

One particularly active attacker was selected for further investigation.
<img width="1000" height="700" alt="sentinel-incident-triage" src="https://github.com/user-attachments/assets/5a5d3916-860e-44d1-9533-a323991f4f11" />


**Observed IP**

```
195.178.110.217
```

Using AbuseIPDB:

* Abuse Confidence Score: **100%**
* Report Count: **8,500+**
* ISP: **TECHOFF SRV LIMITED**

The IP had extensive historical abuse records associated with brute-force attacks.
<img width="827" height="797" alt="AbuseIPDB" src="https://github.com/user-attachments/assets/e65c9006-64a1-4df6-a8d6-156a021a1149" />


---

# 📌 Phase 5 – Infrastructure Mapping

Rather than stopping at the individual IP address, the investigation expanded to the underlying network infrastructure.

Using the Hurricane Electric BGP Toolkit:

| Property     | Value               |
| ------------ | ------------------- |
| ASN          | AS48090             |
| Organization | TECHOFF SRV LIMITED |
| Prefix       | 195.178.110.0/24    |
| Registry     | RIPE NCC            |

This demonstrates how analysts can pivot from a single indicator to the broader hosting infrastructure responsible for malicious activity.

---

# 📌 Phase 6 – Sentinel Watchlists

To improve detection efficiency, malicious infrastructure was operationalized through a custom Sentinel Watchlist.
<img width="1240" height="807" alt="sentinel-watchlist-correlation" src="https://github.com/user-attachments/assets/da9ee895-0cd2-41d9-825b-bd4728dcd6aa" />


```kql
let MaliciousThreatIntel =
_GetWatchlist('KnownMaliciousHostingIPs')
| project IpAddress;

Syslog
| where ProcessName == "sshd"
| extend AttackingIP = extract(@"from ([0-9.]+)",1,SyslogMessage)
| where AttackingIP in (MaliciousThreatIntel)
| project TimeGenerated,
          Computer,
          AttackingIP,
          SyslogMessage
```

Watchlists provide lightweight, reusable threat intelligence without requiring complex KQL joins for every query.

---

# 📌 Phase 7 – Incident Response

After sufficient evidence had been collected, the exposed SSH service was secured.

Network Security Group rules were updated to:

* Remove unrestricted inbound SSH access
* Allow only the administrator's trusted public IP
* Block all other inbound SSH connections

This immediately reduced the attack surface and prevented further brute-force attempts.

---

# 📊 Key Findings

* Internet-facing SSH services are discovered by attackers within minutes.
* Microsoft Sentinel provides rapid visibility into authentication attacks.
* KQL enables powerful log analysis with minimal overhead.
* OSINT significantly improves investigation context.
* ASN and BGP analysis reveals attacker infrastructure beyond individual IP addresses.
* Sentinel Watchlists improve detection efficiency and scalability.
* Network Security Groups provide effective perimeter containment.

---

# 🧠 Skills Demonstrated

* Cloud Security Engineering
* SIEM Administration
* Microsoft Sentinel
* Azure Log Analytics
* Kusto Query Language (KQL)
* Threat Hunting
* Digital Forensics
* Incident Response
* Open Source Intelligence (OSINT)
* Threat Intelligence
* Network Security
* Infrastructure Mapping
* Linux Administration
* Security Monitoring

---

# 🚀 Future Improvements

* Deploy Sentinel Analytics Rules
* Configure Automated Incident Creation
* Integrate Microsoft Defender for Cloud
* Create MITRE ATT&CK mappings
* Add Logic Apps for automated response
* Integrate Threat Intelligence feeds
* Build Sentinel Workbooks for visualization
* Monitor multiple Azure virtual machines

---

## 📚 References

* Microsoft Sentinel
* Azure Log Analytics
* Kusto Query Language (KQL)
* AbuseIPDB
* Hurricane Electric BGP Toolkit

---

## 👤 Author

**Karol**

Cybersecurity Graduate | Cloud Security | SIEM | Threat Hunting | Digital Forensics

---

*This project was created for educational purposes to demonstrate cloud security monitoring, threat detection, and incident response using Microsoft Sentinel.*
