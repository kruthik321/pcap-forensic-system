"""
XML Exporter Module (Module 4: PCAP to XML)
Automated PCAP Forensic Analysis and Reporting System
Converts raw packet captures into structured, schema-compliant Forensic XML.
"""

import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime
from typing import List, Dict, Any

class XMLExporter:
    def __init__(self, filename: str, sha256_hash: str):
        self.filename = filename
        self.sha256_hash = sha256_hash

    def generate_forensic_xml(self, packets: List[Dict[str, Any]], alerts: List[Dict[str, Any]], output_filepath: str) -> str:
        """
        Builds a comprehensive, standardized Forensic XML document 
        containing Evidence Metadata, Packet Hierarchy, and Security Findings.
        """
        root = ET.Element("ForensicPacketCapture")
        root.set("version", "1.0")
        root.set("schema", "Structured-Forensic-XML-v1.0")
        root.set("generatedAt", datetime.now().isoformat())

        # 1. Chain of Custody & Metadata Header
        meta_elem = ET.SubElement(root, "ChainOfCustody")
        ET.SubElement(meta_elem, "EvidenceFilename").text = self.filename
        ET.SubElement(meta_elem, "SHA256BaselineHash").text = self.sha256_hash
        ET.SubElement(meta_elem, "TotalPacketsRecorded").text = str(len(packets))
        ET.SubElement(meta_elem, "IntegrityStatus").text = "SHA-256 Calculated at Ingestion"

        # 2. Packet Records (Hierarchical XML)
        packets_container = ET.SubElement(root, "PacketRecords")
        for pkt in packets:
            p_elem = ET.SubElement(packets_container, "Packet", id=str(pkt.get("packet_num", 0)))
            ET.SubElement(p_elem, "Timestamp").text = str(pkt.get("timestamp", ""))
            
            # Network Layer
            net_elem = ET.SubElement(p_elem, "NetworkLayer")
            ET.SubElement(net_elem, "SourceAddress").text = str(pkt.get("src_ip", "N/A"))
            ET.SubElement(net_elem, "DestinationAddress").text = str(pkt.get("dst_ip", "N/A"))
            ET.SubElement(net_elem, "Protocol").text = str(pkt.get("protocol", "UNKNOWN"))

            # Transport Layer
            trans_elem = ET.SubElement(p_elem, "TransportLayer")
            ET.SubElement(trans_elem, "SourcePort").text = str(pkt.get("src_port", 0))
            ET.SubElement(trans_elem, "DestinationPort").text = str(pkt.get("dst_port", 0))
            if pkt.get("tcp_flags"):
                ET.SubElement(trans_elem, "TCPFlags").text = str(pkt.get("tcp_flags"))

            # Frame & Info
            frame_elem = ET.SubElement(p_elem, "FrameDetails")
            ET.SubElement(frame_elem, "LengthBytes").text = str(pkt.get("length", 0))
            ET.SubElement(frame_elem, "Summary").text = str(pkt.get("info", ""))

            # Payload (if captured)
            if pkt.get("payload_preview"):
                ET.SubElement(p_elem, "PayloadData").text = str(pkt.get("payload_preview"))

        # 3. Security Findings & Alerts
        alerts_container = ET.SubElement(root, "ForensicFindings")
        for alert in alerts:
            a_elem = ET.SubElement(alerts_container, "Alert")
            ET.SubElement(a_elem, "Severity").text = alert.get("Severity", "Info")
            ET.SubElement(a_elem, "ThreatClassification").text = alert.get("Attack Type", "")
            ET.SubElement(a_elem, "AttackerHost").text = alert.get("Attacker IP", "")
            ET.SubElement(a_elem, "TargetHost").text = alert.get("Target IP", "")
            ET.SubElement(a_elem, "Description").text = alert.get("Details", "")

        # Pretty-print XML string
        xml_bytes = ET.tostring(root, encoding="utf-8")
        parsed_dom = minidom.parseString(xml_bytes)
        pretty_xml = parsed_dom.toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")

        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(pretty_xml)

        return pretty_xml
