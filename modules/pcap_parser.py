"""
PCAP Parser Module (Module 7 & Module 4)
Automated PCAP Forensic Analysis and Reporting System
Uses PyShark with automatic Scapy fallback for maximum reliability across systems.
"""

import os
from typing import List, Dict, Any, Tuple
from datetime import datetime

class PCAPParser:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path

    def parse(self) -> Tuple[List[Dict[str, Any]], str]:
        """
        Parses the PCAP file. Tries PyShark first; falls back to Scapy if TShark is unavailable.
        Returns (packet_list, engine_used).
        """
        try:
            import pyshark
            pyshark.tshark.tshark.get_process_path()  # Rapid pre-check: verify TShark binary actually exists on system
            packets = self._parse_with_pyshark()
            if packets:
                return packets, "PyShark (TShark Engine)"
        except Exception:
            pass

        # Fallback to Scapy (Pure Python, highly dependable)
        packets = self._parse_with_scapy()
        return packets, "Scapy Engine (Pure Python)"

    def _normalize_tcp_flags(self, flags_val) -> str:
        """Converts raw or hex flags to standard letter representation (S, SA, RA, etc.)."""
        if not flags_val:
            return ""
        s = str(flags_val).strip()
        try:
            val = int(s, 16) if (s.startswith("0x") or s.startswith("0X")) else (int(s) if s.isdigit() else None)
            if val is not None:
                flag_str = ""
                if val & 0x01: flag_str += "F"  # FIN
                if val & 0x02: flag_str += "S"  # SYN
                if val & 0x04: flag_str += "R"  # RST
                if val & 0x08: flag_str += "P"  # PSH
                if val & 0x10: flag_str += "A"  # ACK
                if val & 0x20: flag_str += "U"  # URG
                return flag_str
        except Exception:
            pass
        return s.upper()

    def _parse_with_pyshark(self) -> List[Dict[str, Any]]:
        import pyshark
        cap = pyshark.FileCapture(self.pcap_path, keep_packets=False)
        parsed = []

        for idx, pkt in enumerate(cap, start=1):
            try:
                timestamp = str(pkt.sniff_time)
                proto = pkt.highest_layer
                src_ip = pkt.ip.src if hasattr(pkt, 'ip') else (pkt.ipv6.src if hasattr(pkt, 'ipv6') else "N/A")
                dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else (pkt.ipv6.dst if hasattr(pkt, 'ipv6') else "N/A")
                
                src_port = 0
                dst_port = 0
                tcp_flags = ""
                
                if hasattr(pkt, 'transport_layer') and pkt.transport_layer:
                    trans = pkt[pkt.transport_layer]
                    src_port = int(trans.srcport) if hasattr(trans, 'srcport') else 0
                    dst_port = int(trans.dstport) if hasattr(trans, 'dstport') else 0
                    if hasattr(trans, 'flags'):
                        tcp_flags = self._normalize_tcp_flags(trans.flags)

                length = int(pkt.length)
                info = f"{proto} ({length} bytes)"

                # Enhanced payload extraction for PyShark
                payload_preview = ""
                if hasattr(pkt, 'http'):
                    # HTTP layer payload extraction
                    if hasattr(pkt.http, 'file_data'):
                        payload_preview = str(pkt.http.file_data)[:200]
                    elif hasattr(pkt.http, 'request_uri'):
                        method = pkt.http.request_method if hasattr(pkt.http, 'request_method') else "GET"
                        payload_preview = f"{method} {pkt.http.request_uri}"
                elif hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'payload') and pkt.tcp.payload is not None:
                    try:
                        raw = bytes.fromhex(pkt.tcp.payload.replace(':', ''))
                        payload_preview = raw.decode('latin1', errors='ignore')[:200]
                    except Exception:
                        pass
                elif hasattr(pkt, 'data') and hasattr(pkt.data, 'data') and pkt.data.data is not None:
                    try:
                        raw = bytes.fromhex(pkt.data.data.replace(':', ''))
                        payload_preview = raw.decode('latin1', errors='ignore')[:200]
                    except Exception:
                        pass

                parsed.append({
                    "packet_num": idx,
                    "timestamp": timestamp,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": proto,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "length": length,
                    "tcp_flags": tcp_flags,
                    "payload_preview": payload_preview,
                    "info": info
                })
            except Exception:
                continue

        cap.close()
        return parsed

    def _parse_with_scapy(self) -> List[Dict[str, Any]]:
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, DNS

        scapy_packets = rdpcap(self.pcap_path)
        parsed = []

        for idx, pkt in enumerate(scapy_packets, start=1):
            timestamp = datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            length = len(pkt)
            src_ip = "N/A"
            dst_ip = "N/A"
            proto = "ETHERNET"
            src_port = 0
            dst_port = 0
            tcp_flags = ""
            payload_preview = ""
            info = ""

            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                proto = "IP"
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
                proto = "IPv6"
            elif pkt.haslayer(ARP):
                src_ip = pkt[ARP].psrc
                dst_ip = pkt[ARP].pdst
                proto = "ARP"
                info = f"ARP Who has {dst_ip}? Tell {src_ip}"

            if pkt.haslayer(TCP):
                proto = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                tcp_flags = self._normalize_tcp_flags(pkt[TCP].flags)
                info = f"TCP {src_port} -> {dst_port} [{tcp_flags}]"
                if dst_port == 80 or src_port == 80:
                    proto = "HTTP"
            elif pkt.haslayer(UDP):
                proto = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                info = f"UDP {src_port} -> {dst_port}"
                if dst_port == 53 or src_port == 53 or pkt.haslayer(DNS):
                    proto = "DNS"
                    if pkt.haslayer(DNS) and pkt[DNS].qd:
                        qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore') if hasattr(pkt[DNS].qd.qname, 'decode') else str(pkt[DNS].qd.qname)
                        info = f"DNS Query: {qname}"
            elif pkt.haslayer(ICMP):
                proto = "ICMP"
                info = f"ICMP Type {pkt[ICMP].type}"

            if pkt.haslayer(Raw):
                try:
                    raw_bytes = pkt[Raw].load
                    decoded = raw_bytes.decode('latin1', errors='ignore')
                    payload_preview = decoded[:200]
                    if not info:
                        info = f"Payload: {decoded[:30]}..."
                except Exception:
                    pass

            if not info:
                info = f"{proto} packet ({length} bytes)"

            parsed.append({
                "packet_num": idx,
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto,
                "src_port": src_port,
                "dst_port": dst_port,
                "length": length,
                "tcp_flags": tcp_flags,
                "payload_preview": payload_preview,
                "info": info
            })

        return parsed
