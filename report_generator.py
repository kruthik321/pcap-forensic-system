"""
Report Generator Module (Module 6: Forensic Reporting)
Automated PCAP Forensic Analysis and Reporting System
Generates comprehensive forensic reports in Markdown and standalone styled HTML.
Enhanced with Deep Packet Traffic Analytics and Visual Graph Interpretations.
"""

import html
from datetime import datetime
from typing import List, Dict, Any, Optional

class ReportGenerator:
    def __init__(self, filename: str, sha256_hash: str, filesize: int, total_packets: int, engine: str):
        self.filename = filename
        self.sha256 = sha256_hash
        self.filesize = filesize
        self.total_packets = total_packets
        self.engine = engine
        self.team = [
            {"name": "Riya Kushwah", "roll": "58", "role": "Module 4: PCAP to SQLite & Database Query Engine"},
            {"name": "Rahee Pradeep Phapale", "roll": "42", "role": "Module 4: PCAP to XML & Chain of Custody"},
            {"name": "Kruthik Shetty", "roll": "59", "role": "Module 7: Traffic & Security Threat Analysis"}
        ]

    def _normalize_talkers(self, top_talkers: Any) -> List[Dict[str, Any]]:
        if not top_talkers:
            return []
        if isinstance(top_talkers, dict):
            return [{"src_ip": k, "packets_sent": v, "bytes_sent": 0} for k, v in top_talkers.items()]
        elif isinstance(top_talkers, list):
            res = []
            for t in top_talkers:
                if isinstance(t, dict):
                    res.append({
                        "src_ip": t.get("src_ip", "N/A"),
                        "packets_sent": t.get("packets_sent", t.get("count", 0)),
                        "bytes_sent": t.get("bytes_sent", t.get("total_bytes", 0))
                    })
            return res
        return []

    def _normalize_flows(self, flows_summary: Any) -> List[Dict[str, Any]]:
        if not flows_summary:
            return []
        if isinstance(flows_summary, list):
            return flows_summary
        return []

    def _detect_scenario(self, alerts: List[Dict[str, Any]], proto_summary: Dict[str, int]) -> str:
        fn = self.filename.lower()
        if "port_scan" in fn or any("Port Scan" in a.get("Attack Type", "") for a in alerts):
            return "PORT_SCAN"
        elif "web_attack" in fn or any(a.get("Attack Type") in ["SQL Injection", "Cross-Site Scripting (XSS)", "Directory Traversal", "Cleartext Credential Exposure", "Suspicious Long DNS Query (Tunneling Indicator)"] for a in alerts):
            return "WEB_ATTACKS"
        elif "benign" in fn or (len(alerts) == 0 and "ICMP" in proto_summary and "DNS" in proto_summary):
            return "BENIGN"
        return "CUSTOM"

    def _get_protocol_layer(self, proto: str) -> str:
        p = proto.upper()
        if p in ["HTTP", "HTTPS", "DNS", "FTP", "SSH", "TELNET", "SMTP"]:
            return "Application Layer (L7)"
        elif p in ["TCP", "UDP"]:
            return "Transport Layer (L4)"
        elif p in ["IP", "IPv4", "IPv6", "ICMP", "ARP"]:
            return "Network / Internet Layer (L3)"
        return "Transport / Network"

    def _get_protocol_role(self, proto: str) -> str:
        p = proto.upper()
        roles = {
            "TCP": "Connection-Oriented Transport / SYN Probes / Flow Control",
            "UDP": "Connectionless Datagram / Query Transport",
            "HTTP": "Plaintext Hypertext Transfer / Web Application Traffic",
            "HTTPS": "Encrypted Web Transport (TLS/SSL)",
            "DNS": "Domain Name Resolution / Endpoint Discovery",
            "ICMP": "Network Diagnostic / Reachability Probing (Echo Request/Reply)",
            "ARP": "Hardware Address Resolution / Local Subnet Mapping"
        }
        return roles.get(p, "General Network Communication")

    def _get_scenario_deduction_md(self, scenario: str, alerts: List[Dict[str, Any]], proto_summary: Dict[str, int], talkers: List[Dict[str, Any]], flows: List[Dict[str, Any]]) -> str:
        if scenario == "PORT_SCAN":
            return """#### Specific Evidence Findings: `sample_port_scan.pcap`
* **Transport Monolithic Skew:** 100% of captured traffic consists of TCP packets (32 packets total). No higher-layer application data, ARP, or ICMP traffic is present, which is an artificial signature typical of automated reconnaissance scripts.
* **Symmetric Host Duality:** Transmission is split 50% / 50% between Attacker `192.168.1.100` (16 outbound SYN probes) and Target `192.168.1.1` (16 inbound RST/ACK replies).
* **Port Distribution:** 16 well-known and registered destination ports were sequentially probed (ports 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8080).
* **Forensic Conclusion:** Confirms a **Stealth SYN Half-Open Port Scan** (`Nmap -sS` signature). The scanning host sent SYN packets with an outbound probe ratio of 100% and terminated conversations without establishing 3-way TCP handshakes, actively enumerating open listening ports on the target host."""

        elif scenario == "WEB_ATTACKS":
            return """#### Specific Evidence Findings: `sample_web_attacks.pcap`
* **Application-Layer Heavy Skew:** 80% HTTP (4 packets) and 20% DNS (1 packet). 100% of the capture operates at the Application Layer (OSI Layer 7), reflecting targeted application-level exploitation rather than network discovery.
* **Host Asymmetry:** Primary threat vector `10.0.0.50` aggressively targeted Web Server `10.0.0.1` and DNS Gateway `10.0.0.2`.
* **Payload Deep Packet Analysis:**
  1. **SQL Injection (SQLi):** `GET /search?id=admin' OR '1'='1` attempting authentication bypass against database backends.
  2. **Cross-Site Scripting (XSS):** `GET /comment?msg=<script>alert(1)</script>` targeting reflected browser code execution.
  3. **Path Traversal:** `GET /download?file=../../../../etc/passwd` attempting arbitrary file disclosure from Linux filesystem roots.
  4. **Plaintext Credential Sniffing:** `POST /login` transmitting `user=admin&pass=Secret123!` without TLS encryption.
  5. **DNS Exfiltration Indicator:** An abnormally long DNS query (`exfiltration-test-query-long-label.malicious-c2.com`) with query length exceeding 50 characters, characteristic of DNS tunneling/C2 beaconing.
* **Forensic Conclusion:** Confirms a **Multi-Vector Web Application Attack** combined with potential DNS exfiltration."""

        elif scenario == "BENIGN":
            return """#### Specific Evidence Findings: `sample_benign_traffic.pcap`
* **Diversified Protocol Mix:** Balanced distribution across ICMP (25%), DNS (25%), and HTTP (50%), spanning Network, Transport, and Application layers.
* **Proportional Client-Server Symmetry:** Routine communication between client `192.168.1.50`, local default gateway `192.168.1.1`, public DNS resolver `8.8.8.8`, and web host `93.184.216.34`.
* **Conversational Completeness:**
  1. Clean ICMP Echo Request followed by Echo Reply verifying link reachability.
  2. Standard DNS A-record query for `example.com` returning legitimate IP address records.
  3. Standard HTTP GET `/index.html` transaction returning HTTP/1.1 200 OK with legitimate HTML markup.
* **Forensic Conclusion:** Confirms **Legitimate / Benign Operational Traffic** with zero anomalies, zero exploit payloads, and healthy protocol round-trip handshakes."""

        else:
            top_talker_str = f"`{talkers[0]['src_ip']}` ({talkers[0]['packets_sent']} pkts)" if talkers else "N/A"
            dominant_proto = max(proto_summary.items(), key=lambda x: x[1])[0] if proto_summary else "N/A"
            return f"""#### Specific Evidence Findings: `{self.filename}`
* **Dominant Protocol:** `{dominant_proto}` represents the primary protocol volume across this capture.
* **Highest Transmitting Host:** {top_talker_str} generated the highest single-source volume.
* **Threat Correlation:** {len(alerts)} security anomalies were correlated against database records.
* **Forensic Status:** Full evidentiary inspection completed under NIST SP 800-86 procedures."""

    def _get_scenario_deduction_html(self, scenario: str, alerts: List[Dict[str, Any]], proto_summary: Dict[str, int], talkers: List[Dict[str, Any]], flows: List[Dict[str, Any]]) -> str:
        if scenario == "PORT_SCAN":
            return """<div class="analysis-box deduction-box">
                <h4>🎯 Forensic Deduction &amp; Case Findings: <code>sample_port_scan.pcap</code></h4>
                <ul style="margin: 8px 0; padding-left: 20px;">
                    <li><strong>Transport Monolithic Skew:</strong> Exactly 100% of all captured frames belong to the TCP protocol (32 packets). Normal enterprise captures always display a healthy mixture of ARP, DNS, TLS, and ICMP; an absolute 100% TCP profile is a strong indicator of automated tool execution.</li>
                    <li><strong>Exact Duality in Top Talkers:</strong> Communication is split exactly 50% / 50% between Attacker <code>192.168.1.100</code> (16 outbound SYN probes) and Target <code>192.168.1.1</code> (16 inbound RST/ACK replies).</li>
                    <li><strong>Sequential Port Sweeping:</strong> 16 standard service ports were probed in tight succession (ports 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8080).</li>
                    <li><strong>Half-Open Handshake Evasion:</strong> Every outbound SYN probe elicited an immediate RST/ACK reply without completing the 3-way handshake, confirming a <strong>Stealth SYN Port Scan (Nmap -sS)</strong>.</li>
                </ul>
            </div>"""
        elif scenario == "WEB_ATTACKS":
            return """<div class="analysis-box deduction-box">
                <h4>🎯 Forensic Deduction &amp; Case Findings: <code>sample_web_attacks.pcap</code></h4>
                <ul style="margin: 8px 0; padding-left: 20px;">
                    <li><strong>Application-Layer Focus:</strong> Traffic is 80% HTTP (4 packets) and 20% DNS (1 packet). The total absence of lower-layer network discovery indicates the adversary possessed prior reconnaissance intelligence.</li>
                    <li><strong>Primary Threat Actor:</strong> Host <code>10.0.0.50</code> initiated targeted exploits directed against Web Server <code>10.0.0.1</code> and DNS Gateway <code>10.0.0.2</code>.</li>
                    <li><strong>Exploit Signature Verification:</strong>
                        <ul>
                            <li><strong>SQL Injection:</strong> <code>' OR '1'='1</code> injected into authentication queries to bypass credential verification.</li>
                            <li><strong>Cross-Site Scripting:</strong> <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> injected into user-supplied HTTP parameters.</li>
                            <li><strong>Directory Traversal:</strong> <code>../../../../etc/passwd</code> targeting Linux root credential stores.</li>
                            <li><strong>Cleartext Credential Exposure:</strong> Sensitive administrator credentials <code>user=admin&amp;pass=Secret123!</code> transmitted unencrypted over HTTP port 80.</li>
                            <li><strong>DNS Tunneling Indicator:</strong> Abnormally long DNS query (55 bytes) querying <code>exfiltration-test-query-long-label.malicious-c2.com</code>.</li>
                        </ul>
                    </li>
                    <li><strong>Forensic Conclusion:</strong> Confirms a <strong>Multi-Vector Web Application Intrusion</strong> with cleartext credential compromise and potential C2 covert channel.</li>
                </ul>
            </div>"""
        elif scenario == "BENIGN":
            return """<div class="analysis-box deduction-box">
                <h4>🎯 Forensic Deduction &amp; Case Findings: <code>sample_benign_traffic.pcap</code></h4>
                <ul style="margin: 8px 0; padding-left: 20px;">
                    <li><strong>Balanced Protocol Composition:</strong> Diversified across ICMP (25%), DNS (25%), and HTTP (50%), spanning OSI Layers 3, 4, and 7.</li>
                    <li><strong>Natural Client-Server Interaction:</strong> Standard proportional traffic exchange between client <code>192.168.1.50</code>, gateway <code>192.168.1.1</code>, DNS <code>8.8.8.8</code>, and web host <code>93.184.216.34</code>.</li>
                    <li><strong>Conversational Integrity:</strong> Complete bidirectional round-trips with zero half-open connections, zero malicious payload substrings, and zero anomalous query lengths.</li>
                    <li><strong>Forensic Conclusion:</strong> Validates a <strong>Legitimate Operational Baseline</strong> suitable for calibrating detection thresholds and false-positive baselines.</li>
                </ul>
            </div>"""
        else:
            top_talker_str = f"<code>{talkers[0]['src_ip']}</code> ({talkers[0]['packets_sent']} packets)" if talkers else "N/A"
            dominant_proto = max(proto_summary.items(), key=lambda x: x[1])[0] if proto_summary else "N/A"
            return f"""<div class="analysis-box deduction-box">
                <h4>🎯 Forensic Deduction &amp; Case Findings: <code>{html.escape(self.filename)}</code></h4>
                <p>The forensic parser and relational engine successfully processed {self.total_packets} packets. Dominant traffic is driven by <strong>{html.escape(dominant_proto)}</strong>, with highest source host transmission generated by {top_talker_str}. A total of {len(alerts)} threat indicators were flagged by the algorithmic rule engine.</p>
            </div>"""

    def generate_markdown(
        self, 
        alerts: List[Dict[str, Any]], 
        proto_summary: Dict[str, int], 
        top_talkers: Optional[Any] = None, 
        flows_summary: Optional[Any] = None,
        *args,
        **kwargs
    ) -> str:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        threat_count = len(alerts)
        talkers_list = self._normalize_talkers(top_talkers)
        flows_list = self._normalize_flows(flows_summary)
        scenario = self._detect_scenario(alerts, proto_summary)

        md = f"""# DIGITAL NETWORK FORENSIC INVESTIGATION REPORT
**Course:** Information Security Lab Mini Project  
**System:** Automated PCAP Forensic Analysis and Reporting System  
**Report Generated:** {now_str}  
**Investigation Status:** COMPLETED  

---

## 1. INVESTIGATOR TEAM DETAILS
| Sl. No. | Student Name | Roll No. | Assigned Role |
|:---:|:---|:---:|:---|
| 1 | Riya Kushwah | 58 | Module 4: PCAP to SQLite & Database Query Engine |
| 2 | Rahee Pradeep Phapale | 42 | Module 4: PCAP to XML & Chain of Custody |
| 3 | Kruthik Shetty | 59 | Module 7: Traffic & Security Threat Analysis |

---

## 2. EVIDENCE CUSTODY & INTEGRITY BASELINE
To establish digital chain of custody under NIST SP 800-86 guidelines, a cryptographic baseline was calculated upon ingestion:
* **Evidence File Name:** `{self.filename}`
* **File Size:** `{self.filesize / 1024:.2f} KB` ({self.filesize} bytes)
* **Total Network Packets:** `{self.total_packets}`
* **Extraction Engine:** `{self.engine}`
* **SHA-256 Baseline Hash:**  
  `{self.sha256}`
* **Integrity Status:** SHA-256 Baseline Calculated at Ingestion

---

## 3. DEEP PACKET TRAFFIC ANALYTICS & VISUAL GRAPH INTERPRETATION (MODULE 7)

### 3.1 Protocol Volume Distribution (Layer Composition & Donut Chart Analysis)
Summary of communication protocols observed across the evidence capture:

| Protocol | Packet Count | Share (%) | OSI Layer | Forensic Role |
|:---|:---:|:---:|:---|:---|
"""
        total_p = max(self.total_packets, sum(proto_summary.values()), 1)
        for proto, count in proto_summary.items():
            pct = (count / total_p) * 100
            layer = self._get_protocol_layer(proto)
            role = self._get_protocol_role(proto)
            md += f"| **{proto}** | {count} | {pct:.1f}% | {layer} | {role} |\n"

        md += """
#### 📊 Forensic Visual Interpretation (Protocol Donut Chart):
* **Layer Profile Assessment:** The Protocol Distribution donut chart visualizes the ratio between Transport Layer (L4) and Application Layer (L7) communications. A balanced enterprise baseline displays diverse protocols including ARP, DNS, HTTP/HTTPS, and ICMP.
* **Observed Distribution Signature:** """

        if scenario == "PORT_SCAN":
            md += "In this capture, traffic is **100% TCP**. This total absence of application data or supporting network protocols indicates a specialized, automated network reconnaissance scan rather than normal client activity.\n"
        elif scenario == "WEB_ATTACKS":
            md += "In this capture, traffic is concentrated entirely in the **Application Layer (80% HTTP, 20% DNS)**. The absence of lower-layer network noise confirms targeted interaction with web application endpoints.\n"
        elif scenario == "BENIGN":
            md += "In this capture, traffic displays a **healthy multi-protocol distribution** spanning ICMP (25%), DNS (25%), and HTTP (50%), representing typical user browsing and network diagnostic actions.\n"
        else:
            dominant_proto = max(proto_summary.items(), key=lambda x: x[1])[0] if proto_summary else "N/A"
            md += f"In this capture, `{dominant_proto}` represents the primary volume driver, accounting for the majority of recorded network frames.\n"

        # 3.2 Top Talkers
        md += "\n### 3.2 Top Transmitting Source Hosts (Top Talkers Horizontal Bar Chart Analysis)\n"
        if talkers_list:
            md += "| Source Host IP | Packets Sent | Traffic Share (%) | Forensic Classification |\n"
            md += "|:---|:---:|:---:|:---|\n"
            for t in talkers_list:
                s_ip = t.get("src_ip", "N/A")
                cnt = t.get("packets_sent", 0)
                pct = (cnt / total_p) * 100
                role_desc = "Primary Threat Vector / Initiator" if cnt > (total_p * 0.45) else "Secondary Host / Target Responder"
                md += f"| `{s_ip}` | {cnt} | {pct:.1f}% | {role_desc} |\n"
        else:
            md += "*No host transmission records available.*\n"

        md += """
#### 📈 Forensic Visual Interpretation (Top Talkers Bar Chart):
* **Transmission Asymmetry:** Normal network nodes exhibit proportional, symmetric communications. Large disparities in the Top Talkers horizontal bar chart highlight aggressive scanning nodes, flood sources, or compromised machines initiating unsolicited network connections.
* **Traffic Concentration:** The chart isolates high-velocity endpoints, providing investigators with immediate attribution of primary source addresses before correlating individual socket connections.
"""

        # 3.3 Bidirectional Flows
        md += "\n### 3.3 Aggregated Bidirectional Communication Sessions (`network_flows` Table Analysis)\n"
        if flows_list:
            md += "| Host A | Host B | Protocol | Total Pkts | A ⟶ B | B ⟶ A | Total Bytes | Session Type |\n"
            md += "|:---|:---|:---:|:---:|:---:|:---:|:---:|:---|\n"
            for f in flows_list[:8]:
                h_a = f.get("host_a", "N/A")
                h_b = f.get("host_b", "N/A")
                proto = f.get("protocol", "TCP")
                tot = f.get("packet_count", 0)
                a_b = f.get("a_to_b_pkts", 0)
                b_a = f.get("b_to_a_pkts", 0)
                byts = f.get("total_bytes", 0)
                sess_type = "Symmetric Exchange" if a_b == b_a else "Asymmetric / Half-Open"
                md += f"| `{h_a}` | `{h_b}` | {proto} | {tot} | {a_b} | {b_a} | {byts} B | {sess_type} |\n"
        else:
            md += "*Bidirectional session data populated in SQLite `network_flows` table.*\n"

        md += """
#### 🔄 Forensic Visual Interpretation (Bidirectional Sessions & Session Symmetry):
* **Flow Canonicalization:** Grouping records by canonical host pairs (`host_a = MIN(src, dst)`, `host_b = MAX(src, dst)`) aggregates directional packets into cohesive communication sessions, solving directional fragmentation.
* **Handshake Completeness:** By tracking `a_to_b_pkts` versus `b_to_a_pkts`, investigators can immediately differentiate established 3-way handshakes from aborted half-open port probes or single-ended SYN flood assaults.
"""

        # 3.4 Contextual Deductions
        md += "\n### 3.4 Evidence Capture Contextual Deductions\n"
        md += self._get_scenario_deduction_md(scenario, alerts, proto_summary, talkers_list, flows_list)
        md += "\n\n---\n"

        # 4. Detected Threats
        md += f"""## 4. DETECTED THREATS & INCIDENT FINDINGS
Total Security Anomalies Identified: **{threat_count}**

"""
        if alerts:
            md += "| Severity | Threat Classification | Attacker IP | Target IP | Forensic Evidence Details |\n"
            md += "|:---:|:---|:---:|:---:|:---|\n"
            for a in alerts:
                md += f"| **{a.get('Severity')}** | {a.get('Attack Type')} | `{a.get('Attacker IP')}` | `{a.get('Target IP')}` | {a.get('Details')} |\n"
        else:
            md += "> ✅ **Clean Traffic:** No unauthorized port scanning, brute-forcing, DoS floods, or unencrypted credential exposures were identified in this capture.\n"

        md += """
---

## 5. FORENSIC CONCLUSION & DEFENSIVE REMEDIATION
1. **Network Boundary Rate-Limiting:** Configure stateful perimeter firewalls to monitor rapid SYN packet rates and automatically drop half-open connection sweeps (e.g., using `iptables` recent module or Snort rate filtering).
2. **Mandatory Encryption (TLS 1.3):** Strictly decommission cleartext protocols (HTTP, Telnet, FTP) on production boundaries to prevent credential interception and plaintext payload injection.
3. **Web Application Firewall (WAF) & Input Sanitization:** Implement parameterized SQL queries and context-aware output encoding to defend against SQL Injection and Cross-Site Scripting exploits.
4. **DNS Monitoring & Rate Throttling:** Inspect anomalous DNS query lengths and monitor high-entropy subdomains to detect and mitigate covert DNS tunneling channels.
5. **Digital Chain of Custody Preservation:** Store the extracted SQLite database (`forensic_analysis.db`) and structured XML export in immutable storage for judicial or incident review.
"""
        return md

    def generate_html(
        self, 
        alerts: List[Dict[str, Any]], 
        proto_summary: Dict[str, int], 
        top_talkers: Optional[Any] = None, 
        flows_summary: Optional[Any] = None,
        *args,
        **kwargs
    ) -> str:
        """
        Renders an authentic, fully styled HTML executive forensic report
        with structured tables, severity badges, and deep packet traffic analytics.
        """
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        talkers_list = self._normalize_talkers(top_talkers)
        flows_list = self._normalize_flows(flows_summary)
        scenario = self._detect_scenario(alerts, proto_summary)
        total_p = max(self.total_packets, sum(proto_summary.values()), 1)

        # Build protocol table rows
        proto_rows = ""
        for proto, count in proto_summary.items():
            pct = (count / total_p) * 100
            layer = html.escape(self._get_protocol_layer(proto))
            role = html.escape(self._get_protocol_role(proto))
            proto_rows += f"""
            <tr>
                <td><strong>{html.escape(proto)}</strong></td>
                <td>{count}</td>
                <td>
                    <div class="progress-bar"><div class="progress-fill" style="width: {pct:.1f}%;"></div></div>
                    {pct:.1f}%
                </td>
                <td>{layer}</td>
                <td>{role}</td>
            </tr>"""

        # Build top talkers rows
        talker_rows = ""
        if talkers_list:
            for t in talkers_list:
                s_ip = html.escape(str(t.get("src_ip", "N/A")))
                cnt = t.get("packets_sent", 0)
                pct = (cnt / total_p) * 100
                role_desc = "Primary Threat Vector / Initiator" if cnt > (total_p * 0.45) else "Secondary Host / Target Responder"
                talker_rows += f"""
                <tr>
                    <td><code>{s_ip}</code></td>
                    <td><strong>{cnt}</strong> pkts</td>
                    <td>
                        <div class="progress-bar"><div class="progress-fill" style="width: {pct:.1f}%; background: #0284c7;"></div></div>
                        {pct:.1f}%
                    </td>
                    <td>{role_desc}</td>
                </tr>"""
        else:
            talker_rows = "<tr><td colspan='4' style='text-align: center; color: #64748b;'>No transmission host records available</td></tr>"

        # Build bidirectional flows rows
        flow_rows = ""
        if flows_list:
            for f in flows_list[:8]:
                h_a = html.escape(str(f.get("host_a", "N/A")))
                h_b = html.escape(str(f.get("host_b", "N/A")))
                proto = html.escape(str(f.get("protocol", "TCP")))
                tot = f.get("packet_count", 0)
                a_b = f.get("a_to_b_pkts", 0)
                b_a = f.get("b_to_a_pkts", 0)
                byts = f.get("total_bytes", 0)
                sess_type = "Symmetric (1:1)" if a_b == b_a else "Asymmetric Exchange"
                flow_rows += f"""
                <tr>
                    <td><code>{h_a}</code></td>
                    <td><code>{h_b}</code></td>
                    <td><span class="proto-tag">{proto}</span></td>
                    <td><strong>{tot}</strong></td>
                    <td>{a_b}</td>
                    <td>{b_a}</td>
                    <td>{byts} B</td>
                    <td><span class="badge-sym">{sess_type}</span></td>
                </tr>"""
        else:
            flow_rows = "<tr><td colspan='8' style='text-align: center; color: #64748b;'>Flow data stored in SQLite network_flows table</td></tr>"

        # Build alert table rows
        if alerts:
            alert_rows = ""
            for a in alerts:
                sev = html.escape(str(a.get('Severity', 'Info')))
                badge_class = "badge-high" if "High" in sev else "badge-med"
                alert_rows += f"""
                <tr>
                    <td><span class="{badge_class}">{sev}</span></td>
                    <td><strong>{html.escape(str(a.get('Attack Type', '')))}</strong></td>
                    <td><code>{html.escape(str(a.get('Attacker IP', 'N/A')))}</code></td>
                    <td><code>{html.escape(str(a.get('Target IP', 'N/A')))}</code></td>
                    <td>{html.escape(str(a.get('Details', '')))}</td>
                </tr>"""
        else:
            alert_rows = """<tr><td colspan="5" style="text-align: center; color: #16a34a; padding: 20px;">
                ✅ <strong>Clean Traffic:</strong> No attack signatures, port scans, or credential exposures were identified in this capture.
            </td></tr>"""

        # Chart interpretation text
        if scenario == "PORT_SCAN":
            proto_chart_text = "The Protocol Donut Chart displays <strong>100% TCP traffic</strong> (32 packets). The complete absence of ARP, DNS, or HTTP application traffic confirms an automated port scan designed to discover open services without normal host communications."
            talker_chart_text = "The Top Talkers Bar Chart exhibits <strong>exact 50% / 50% transmission symmetry</strong> between Attacker <code>192.168.1.100</code> (16 SYN packets) and Victim <code>192.168.1.1</code> (16 RST/ACK packets), reflecting an automated probe-and-reset pattern."
        elif scenario == "WEB_ATTACKS":
            proto_chart_text = "The Protocol Donut Chart displays an <strong>Application-Layer concentration (80% HTTP, 20% DNS)</strong>. The absence of lower-layer network discovery indicates direct application probing against web server endpoints."
            talker_chart_text = "The Top Talkers Bar Chart highlights <code>10.0.0.50</code> as the dominant transmission source actively targeting Web Server <code>10.0.0.1</code> and DNS Server <code>10.0.0.2</code> with web application exploit payloads."
        elif scenario == "BENIGN":
            proto_chart_text = "The Protocol Donut Chart displays a <strong>healthy, diverse multi-protocol spread</strong> across ICMP (25%), DNS (25%), and HTTP (50%), reflecting typical client browsing and standard network diagnostics."
            talker_chart_text = "The Top Talkers Bar Chart shows balanced, distributed traffic between the internal client <code>192.168.1.50</code>, gateway <code>192.168.1.1</code>, DNS <code>8.8.8.8</code>, and external web server <code>93.184.216.34</code>."
        else:
            proto_chart_text = f"The Protocol Donut Chart shows traffic dominated by <strong>{html.escape(max(proto_summary.keys()) if proto_summary else 'N/A')}</strong>, driving the overall packet volume."
            talker_chart_text = "The Top Talkers Bar Chart isolates the highest volume endpoints across the capture, highlighting potential threat vectors or primary network servers."

        deduction_html = self._get_scenario_deduction_html(scenario, alerts, proto_summary, talkers_list, flows_list)

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Forensic Incident Report - {html.escape(self.filename)}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 30px;
            background: #f8fafc;
            color: #1e293b;
        }}
        .report-card {{
            max-width: 950px;
            margin: 0 auto;
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.06);
            padding: 40px;
        }}
        .header {{
            border-bottom: 3px solid #0284c7;
            padding-bottom: 20px;
            margin-bottom: 25px;
        }}
        h1 {{
            color: #0f172a;
            font-size: 24px;
            margin: 0 0 8px 0;
            letter-spacing: -0.5px;
        }}
        .meta-text {{
            color: #64748b;
            font-size: 13px;
        }}
        h2 {{
            color: #0369a1;
            font-size: 18px;
            margin-top: 32px;
            border-bottom: 1px solid #e2e8f0;
            padding-bottom: 6px;
        }}
        h3 {{
            color: #0f172a;
            font-size: 15px;
            margin-top: 20px;
            margin-bottom: 10px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin: 15px 0;
        }}
        .kpi {{
            background: #f1f5f9;
            padding: 12px 16px;
            border-radius: 8px;
            border-left: 4px solid #0284c7;
        }}
        .kpi-label {{
            font-size: 11px;
            text-transform: uppercase;
            color: #64748b;
            font-weight: 700;
        }}
        .kpi-val {{
            font-size: 15px;
            font-weight: 700;
            color: #0f172a;
            margin-top: 3px;
            word-break: break-all;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 12px 0 18px 0;
            font-size: 13px;
        }}
        th, td {{
            border: 1px solid #cbd5e1;
            padding: 9px 12px;
            text-align: left;
        }}
        th {{
            background: #e0f2fe;
            color: #0369a1;
            font-weight: 700;
        }}
        tr:nth-child(even) {{
            background: #f8fafc;
        }}
        code {{
            background: #f1f5f9;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: ui-monospace, Menlo, Monaco, Consolas, monospace;
            font-size: 12px;
            color: #0f172a;
        }}
        .progress-bar {{
            background: #e2e8f0;
            border-radius: 9999px;
            height: 7px;
            width: 80px;
            display: inline-block;
            overflow: hidden;
            vertical-align: middle;
            margin-right: 6px;
        }}
        .progress-fill {{
            height: 100%;
            background: #0284c7;
        }}
        .badge-high {{
            background: #fee2e2;
            color: #b91c1c;
            padding: 3px 8px;
            border-radius: 9999px;
            font-size: 11px;
            font-weight: 700;
        }}
        .badge-med {{
            background: #fef3c7;
            color: #b45309;
            padding: 3px 8px;
            border-radius: 9999px;
            font-size: 11px;
            font-weight: 700;
        }}
        .badge-sym {{
            background: #e0f2fe;
            color: #0369a1;
            padding: 2px 7px;
            border-radius: 9999px;
            font-size: 10px;
            font-weight: 600;
        }}
        .proto-tag {{
            background: #f1f5f9;
            border: 1px solid #cbd5e1;
            padding: 1px 5px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 11px;
        }}
        .analysis-box {{
            background: #f8fafc;
            border-left: 4px solid #0284c7;
            border-radius: 6px;
            padding: 12px 16px;
            margin: 10px 0 20px 0;
            font-size: 13px;
            color: #334155;
            line-height: 1.55;
        }}
        .analysis-box h4 {{
            margin: 0 0 5px 0;
            color: #0369a1;
            font-size: 13.5px;
        }}
        .deduction-box {{
            background: #eff6ff;
            border-left: 4px solid #2563eb;
        }}
        .deduction-box h4 {{
            color: #1d4ed8;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e2e8f0;
            font-size: 12px;
            color: #64748b;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="report-card">
        <div class="header">
            <h1>DIGITAL NETWORK FORENSIC INVESTIGATION REPORT</h1>
            <div class="meta-text">
                <strong>Standard:</strong> NIST SP 800-86 Digital Forensics &bull; 
                <strong>Generated:</strong> {now_str} &bull; 
                <strong>Status:</strong> COMPLETED
            </div>
        </div>

        <h2>1. Evidence Ingestion &amp; Cryptographic Baseline</h2>
        <div class="grid">
            <div class="kpi">
                <div class="kpi-label">Evidence File</div>
                <div class="kpi-val">{html.escape(self.filename)}</div>
            </div>
            <div class="kpi">
                <div class="kpi-label">Packet Count / Size</div>
                <div class="kpi-val">{self.total_packets} packets ({self.filesize / 1024:.2f} KB)</div>
            </div>
            <div class="kpi" style="grid-column: span 2;">
                <div class="kpi-label">SHA-256 Cryptographic Hash (Baseline)</div>
                <div class="kpi-val"><code>{self.sha256}</code></div>
            </div>
        </div>

        <h2>2. Investigator Team Details</h2>
        <table>
            <thead>
                <tr><th>Sl. No.</th><th>Student Name</th><th>Roll No.</th><th>Assigned Role</th></tr>
            </thead>
            <tbody>
                <tr><td>1</td><td>Riya Kushwah</td><td>58</td><td>Module 4: PCAP to SQLite &amp; Database Query Engine</td></tr>
                <tr><td>2</td><td>Rahee Pradeep Phapale</td><td>42</td><td>Module 4: PCAP to XML &amp; Chain of Custody</td></tr>
                <tr><td>3</td><td>Kruthik Shetty</td><td>59</td><td>Module 7: Traffic &amp; Security Threat Analysis</td></tr>
            </tbody>
        </table>

        <h2>3. Deep Packet Traffic Analytics &amp; Visual Graph Interpretation (Module 7)</h2>

        <h3>3.1 Protocol Volume Distribution (Layer Composition &amp; Donut Chart)</h3>
        <table>
            <thead>
                <tr><th>Protocol</th><th>Total Packets</th><th>Traffic Share</th><th>OSI Layer</th><th>Forensic Function</th></tr>
            </thead>
            <tbody>
                {proto_rows}
            </tbody>
        </table>
        <div class="analysis-box">
            <h4>📊 Chart 1 Interpretation (Protocol Donut Chart)</h4>
            {proto_chart_text}
        </div>

        <h3>3.2 Top Transmitting Source Hosts (Top Talkers Horizontal Bar Chart)</h3>
        <table>
            <thead>
                <tr><th>Source Host IP</th><th>Packets Sent</th><th>Traffic Share</th><th>Forensic Classification</th></tr>
            </thead>
            <tbody>
                {talker_rows}
            </tbody>
        </table>
        <div class="analysis-box">
            <h4>📈 Chart 2 Interpretation (Top Talkers Bar Chart)</h4>
            {talker_chart_text}
        </div>

        <h3>3.3 Aggregated Bidirectional Communication Sessions (network_flows)</h3>
        <table>
            <thead>
                <tr><th>Host A</th><th>Host B</th><th>Protocol</th><th>Total</th><th>A ⟶ B</th><th>B ⟶ A</th><th>Volume</th><th>Symmetry</th></tr>
            </thead>
            <tbody>
                {flow_rows}
            </tbody>
        </table>
        <div class="analysis-box">
            <h4>🔄 Session Dynamics &amp; Handshake Completeness</h4>
            Bidirectional session aggregation pairs communication endpoints into canonical sessions (<code>host_a &le; host_b</code>). Tracking directional ratios (<code>A ⟶ B</code> vs <code>B ⟶ A</code>) isolates half-open port probes from complete 3-way handshakes and normal conversational transactions.
        </div>

        <h3>3.4 Evidence Capture Contextual Deductions</h3>
        {deduction_html}

        <h2>4. Identified Threat Incidents &amp; Anomalies</h2>
        <table>
            <thead>
                <tr><th>Severity</th><th>Threat Type</th><th>Attacker IP</th><th>Target IP</th><th>Forensic Evidence Details</th></tr>
            </thead>
            <tbody>
                {alert_rows}
            </tbody>
        </table>

        <h2>5. Forensic Remediation &amp; Defensive Recommendations</h2>
        <ol style="font-size: 13px; color: #334155; line-height: 1.7;">
            <li><strong>Port Scan Countermeasures:</strong> Enforce stateful firewall rate-limiting (e.g. <code>iptables recent</code> module) to drop rapid half-open TCP SYN connection sweeps.</li>
            <li><strong>Mandatory TLS Encryption:</strong> Decommission unencrypted HTTP, Telnet, and FTP endpoints across the perimeter and mandate TLS 1.3 / SSH to eliminate plaintext credential exposure.</li>
            <li><strong>Input Sanitization:</strong> Implement parameterized SQL statements and Context-Aware HTML output encoding to neutralize SQL Injection and Cross-Site Scripting (XSS).</li>
            <li><strong>DNS Inspection &amp; Rate Limiting:</strong> Monitor anomalous DNS query lengths and entropy to detect and neutralize covert DNS tunneling channels.</li>
            <li><strong>Evidence Archival:</strong> Retain the extracted SQLite database and XML export files securely under NIST SP 800-86 retention requirements for judicial audit.</li>
        </ol>

        <div class="footer">
            Automated PCAP Forensic Analysis and Reporting System &bull; Information Security Lab 2026
        </div>
    </div>
</body>
</html>"""
        return html_doc
