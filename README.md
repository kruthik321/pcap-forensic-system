# 🛡️ Automated PCAP Forensic Analysis and Reporting System

**Course:** Information Security Lab — Mini Project  
**Academic Year:** 2026  

---

## 👥 Team Details

| Sl. No. | Student Name | Roll No. | Assigned Component |
|:---:|:---|:---:|:---|
| 1 | **Riya Kushwah** | **58** | **Module 4 (PCAP to SQLite):** Relational schema design, SQLite indexing, interactive SQL query runner & DB export. |
| 2 | **Rahee Pradeep Phapale** | **42** | **Module 4 (PCAP to XML):** SHA-256 Chain of Custody hashing, RFC-compliant hierarchical XML (PDML) export & report design. |
| 3 | **Kruthik Shetty** | **59** | **Module 7 (Traffic Analysis):** PyShark/Scapy dissection engine, algorithmic threat detection rules & visual analytics. |

---

## 🎯 Syllabus Modules Implemented

This project fully implements two mandatory modules from the Information Security Lab syllabus:
1. **Module 4: PCAP Analysis**
   * **PCAP to SQLite:** Dissects raw packet captures and inserts them into an indexed relational SQLite database (`packets.db`) with tables for packets, bidirectional flows, alerts, and evidence metadata. Features an immutable read-only SQL exploration console.
   * **PCAP to XML:** Serializes packet trees and forensic findings into structured, well-formed Forensic XML.
2. **Module 7: Traffic Analysis (Wireshark / PyShark)**
   * Deep packet inspection of packet layers (Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP).
   * Algorithmic intrusion detection for **Port Scanning (Nmap SYN/Connect)**, **DoS / SYN Floods**, **Cleartext Passwords**, **SQL Injection**, **XSS**, and **DNS Tunneling**.

---

## 🏗️ System Architecture

```
                                  EVIDENCE INGESTION (.pcap / .pcapng)
                                                   │
                                      [SHA-256 Hash Integrity]
                                                   │
                                     [PyShark / Scapy Dissector]
                                                   │
                    ┌──────────────────────────────┴──────────────────────────────┐
                    ▼                                                             ▼
        [Module 4: PCAP to SQLite]                                    [Module 4: PCAP to XML]
        • packets table                                               • RFC/PDML hierarchical XML
        • network_flows table                                         • Chain of Custody headers
        • security_alerts table                                       • Downloadable evidence.xml
                    │                                                             │
                    └──────────────────────────────┬──────────────────────────────┘
                                                   ▼
                                  [Module 7: Threat & Traffic Engine]
                                  • Port Scans & SYN Floods
                                  • Cleartext Credential Harvest
                                  • Web Attacks (SQLi / XSS)
                                                   │
                                                   ▼
                                     [Interactive Web Dashboard]
                                     • Plotly Protocol Analytics
                                     • Custom SQL Console
                                     • PDF / HTML Forensic Report
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
* Python 3.10+ (Installed on Windows)
* Wireshark / TShark (Optional, for PyShark dissection engine; native Scapy fallback is included)

### 2. Installation
Open PowerShell in this directory:
```powershell
pip install -r requirements.txt
```

### 3. Launch the Web Dashboard
## 🌐 Live Application
Access the deployed PCAP Forensic Analysis System here:

**Public Demo:** https://pcap-forensic-system.streamlit.app

## 💻 Run Locally

Double-click `run_dashboard.bat` **OR** run:
```powershell
streamlit run app.py
```
Open your browser at: **`http://localhost:8501`**

---

## 🧪 Testing with Pre-loaded Sample Captures

Pre-built realistic attack PCAPs are provided in `sample_pcaps/`:
1. `sample_port_scan.pcap` — Probing 16 common ports from an attacker IP. Triggers the **Stealth Port Scan** alert.
2. `sample_web_attacks.pcap` — HTTP requests with SQLi payloads, XSS `<script>` tags, directory traversal `../../etc/passwd`, and cleartext credentials.
3. `sample_benign_traffic.pcap` — Baseline clean traffic containing DNS, ICMP ping, and standard HTTP requests.

---

## 📚 References & Academic Literature
1. **Pilli, E. S., Joshi, R. C., & Niyogi, R. (2010).** *Network forensic frameworks: Survey and research challenges.* Digital Investigation (Elsevier), 7(1-2), 14-27.
2. **Kent, K., Chevalier, S., Grance, T., & Dang, H. (2006).** *Guide to Integrating Forensic Techniques into Incident Response.* NIST Special Publication 800-86.
3. **Cohen, M. (2008).** *PyFlag - An advanced network forensic framework.* Digital Investigation, 5, S112-S120.
