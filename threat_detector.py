"""
Threat Detector Module (Module 7: Traffic & Security Analysis)
Automated PCAP Forensic Analysis and Reporting System
Implements heuristic and signature-based rules to detect intrusions and anomalies.
"""

import re
from datetime import datetime
from typing import List, Dict, Any

class ThreatDetector:
    def __init__(self):
        # Web Attack RegEx Signatures
        self.sqli_pattern = re.compile(
            r"(\bUNION\b.*\bSELECT\b|'\s*OR\s*['\d]=['\d]|--|/\*|\bWAITFOR\s+DELAY\b)", 
            re.IGNORECASE
        )
        self.xss_pattern = re.compile(
            r"(<script.*?>|%3Cscript.*?%3E|javascript:|onerror\s*=|onload\s*=)", 
            re.IGNORECASE
        )
        self.lfi_pattern = re.compile(
            r"(\.\./\.\./|etc/passwd|win\.ini|boot\.ini)", 
            re.IGNORECASE
        )

    def analyze(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alerts = []
        alerts.extend(self._detect_port_scans(packets))
        alerts.extend(self._detect_syn_flood(packets))
        alerts.extend(self._detect_payload_attacks(packets))
        alerts.extend(self._detect_dns_tunneling(packets))
        return alerts

    def _is_syn_only(self, flags: str) -> bool:
        """Checks if TCP flags indicate a SYN packet without ACK."""
        f = flags.upper()
        if f == "S" or f == "0X0002" or f == "0X02":
            return True
        return ("SYN" in f or "S" in f) and ("ACK" not in f and "A" not in f)

    def _is_fin_only(self, flags: str) -> bool:
        """Checks if TCP flags indicate a FIN packet without ACK."""
        f = flags.upper()
        if f == "F" or f == "0X0001" or f == "0X01":
            return True
        return ("FIN" in f or "F" in f) and ("ACK" not in f and "A" not in f)

    def _detect_port_scans(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detects reconnaissance port scanning by inspecting outbound probe packets
        from a source IP to target IP, analyzing unique destination ports, outbound flags,
        and scan timeframe.
        """
        alerts = []
        host_target_probes = {}

        for p in packets:
            src = p.get("src_ip", "N/A")
            dst = p.get("dst_ip", "N/A")
            dport = p.get("dst_port", 0)
            flags = str(p.get("tcp_flags", ""))
            ts = p.get("timestamp", "")

            if src != "N/A" and dst != "N/A" and dport > 0:
                key = (src, dst)
                if key not in host_target_probes:
                    host_target_probes[key] = {
                        "ports": set(),
                        "outbound_flags": [],
                        "timestamps": []
                    }
                host_target_probes[key]["ports"].add(dport)
                host_target_probes[key]["outbound_flags"].append(flags)
                if ts:
                    host_target_probes[key]["timestamps"].append(ts)

        for (src, dst), data in host_target_probes.items():
            unique_ports = len(data["ports"])
            if unique_ports >= 10:
                # Classify based on the outbound probe packets sent by the source host
                syn_count = sum(1 for f in data["outbound_flags"] if self._is_syn_only(f))
                fin_count = sum(1 for f in data["outbound_flags"] if self._is_fin_only(f))
                total_probes = len(data["outbound_flags"])

                if syn_count / total_probes >= 0.7:
                    scan_type = "Stealth SYN Port Scan (Nmap -sS)"
                    mechanism = "Outbound probes utilized half-open SYN packets without completing the 3-way handshake."
                elif fin_count / total_probes >= 0.7:
                    scan_type = "FIN Stealth Scan (Nmap -sF)"
                    mechanism = "Outbound probes utilized FIN packets to elicit RST responses from closed ports."
                else:
                    scan_type = "TCP Connect / General Port Scan"
                    mechanism = "Multiple destination ports systematically probed across target host."

                # Calculate scan timeframe if timestamps available
                time_info = ""
                if data["timestamps"]:
                    try:
                        t_start = datetime.fromisoformat(data["timestamps"][0])
                        t_end = datetime.fromisoformat(data["timestamps"][-1])
                        delta = (t_end - t_start).total_seconds()
                        if delta > 0:
                            time_info = f" within {delta:.2f} seconds ({unique_ports / delta:.1f} ports/sec)"
                    except Exception:
                        pass

                alerts.append({
                    "Severity": "🔴 High",
                    "Attack Type": scan_type,
                    "Attacker IP": src,
                    "Target IP": dst,
                    "Details": f"Probed {unique_ports} distinct destination ports{time_info}. {mechanism}"
                })
        return alerts

    def _detect_syn_flood(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Heuristic detection for potential DoS / SYN flood attempts.
        Flags sources transmitting high volumes of SYN-only packets to a destination.
        """
        alerts = []
        target_syn_counts = {}

        for p in packets:
            src = p.get("src_ip", "N/A")
            dst = p.get("dst_ip", "N/A")
            flags = str(p.get("tcp_flags", ""))
            
            if self._is_syn_only(flags) and src != "N/A" and dst != "N/A":
                key = (src, dst)
                target_syn_counts[key] = target_syn_counts.get(key, 0) + 1

        for (src, dst), count in target_syn_counts.items():
            if count >= 40:
                alerts.append({
                    "Severity": "🔴 High",
                    "Attack Type": "DoS / TCP SYN Flood Indicator",
                    "Attacker IP": src,
                    "Target IP": dst,
                    "Details": f"Transmitted {count} incomplete SYN connection attempts to target without completing handshakes."
                })
        return alerts

    def _detect_payload_attacks(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Inspects decoded application payloads for credentials and web attack signatures."""
        alerts = []
        for p in packets:
            payload = p.get("payload_preview", "")
            if not payload:
                continue

            src = p.get("src_ip", "N/A")
            dst = p.get("dst_ip", "N/A")
            pid = p.get("packet_num", 0)

            # 1. Plaintext credential detection (HTTP POST / FTP / Telnet)
            if any(k in payload.lower() for k in ["password=", "pass=", "pwd=", "authorization: basic"]):
                alerts.append({
                    "Severity": "🟡 Medium",
                    "Attack Type": "Unencrypted Cleartext Credential Exposure",
                    "Attacker IP": src,
                    "Target IP": dst,
                    "Details": f"Packet #{pid} contains unencrypted credentials or authentication headers transmitted over cleartext."
                })

            # 2. SQL Injection
            if self.sqli_pattern.search(payload):
                alerts.append({
                    "Severity": "🔴 High",
                    "Attack Type": "Web Attack: SQL Injection (SQLi)",
                    "Attacker IP": src,
                    "Target IP": dst,
                    "Details": f"Packet #{pid} contains SQL injection signatures attempting database manipulation."
                })

            # 3. Cross-Site Scripting (XSS)
            if self.xss_pattern.search(payload):
                alerts.append({
                    "Severity": "🟡 Medium",
                    "Attack Type": "Web Attack: Cross-Site Scripting (XSS)",
                    "Attacker IP": src,
                    "Target IP": dst,
                    "Details": f"Packet #{pid} contains script tags or Javascript execution vectors."
                })

            # 4. Directory Traversal
            if self.lfi_pattern.search(payload):
                alerts.append({
                    "Severity": "🔴 High",
                    "Attack Type": "Web Attack: Directory / Path Traversal",
                    "Attacker IP": src,
                    "Target IP": dst,
                    "Details": f"Packet #{pid} attempted relative path traversal to access sensitive system files."
                })

        return alerts

    def _detect_dns_tunneling(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identifies suspicious high-entropy or unusually long DNS queries as tunneling indicators."""
        alerts = []
        for p in packets:
            if p.get("protocol") == "DNS":
                info = p.get("info", "")
                if len(info) > 60:
                    alerts.append({
                        "Severity": "🟡 Medium",
                        "Attack Type": "Suspicious Long DNS Query (Potential Tunneling Indicator)",
                        "Attacker IP": p.get("src_ip", "N/A"),
                        "Target IP": p.get("dst_ip", "N/A"),
                        "Details": f"Anomalously long DNS query detected ({len(info)} characters). Typical indicator of DNS tunneling or DGA botnet communication."
                    })
        return alerts
