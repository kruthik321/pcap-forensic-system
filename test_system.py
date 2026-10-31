"""
Automated unit verification for the PCAP Forensic Analysis System.
Tests ingestion, SQLite persistence, read-only SQL enforcement,
bidirectional flows, XML generation, and threat analysis.
"""

import os
import sys
import tempfile
import hashlib

# Ensure utf-8 encoding on Windows console
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.pcap_parser import PCAPParser
from modules.database_manager import DatabaseManager
from modules.xml_exporter import XMLExporter
from modules.threat_detector import ThreatDetector
from modules.report_generator import ReportGenerator

def run_tests():
    sample_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_pcaps")
    port_scan_pcap = os.path.join(sample_dir, "sample_port_scan.pcap")
    web_attack_pcap = os.path.join(sample_dir, "sample_web_attacks.pcap")
    benign_pcap = os.path.join(sample_dir, "sample_benign_traffic.pcap")

    assert os.path.exists(port_scan_pcap), "Port scan PCAP missing"
    assert os.path.exists(web_attack_pcap), "Web attack PCAP missing"
    assert os.path.exists(benign_pcap), "Benign PCAP missing"

    temp_dir = tempfile.gettempdir()
    db_path = os.path.join(temp_dir, "test_forensics.db")
    xml_path = os.path.join(temp_dir, "test_evidence.xml")

    print("[1/6] Testing Parser on sample_port_scan.pcap...")
    parser = PCAPParser(port_scan_pcap)
    packets, engine = parser.parse()
    print(f"      Parsed {len(packets)} packets using engine: {engine}")
    assert len(packets) == 32, f"Expected 32 packets, got {len(packets)}"

    print("[2/6] Testing SQLite Database Manager & Bidirectional Flows...")
    db = DatabaseManager(db_path)
    db.clear_existing_data()
    db.insert_packets_batch(packets)
    db.populate_network_flows()

    df_packets = db.get_packets_df()
    assert len(df_packets) == len(packets), "Row count mismatch in SQLite!"
    
    # Verify Bidirectional Flow Aggregation
    df_flows = db.execute_custom_sql("SELECT * FROM network_flows")
    print(f"      Aggregated {len(df_flows)} bidirectional flow sessions.")
    assert len(df_flows) > 0, "No bidirectional flows found!"
    # Check that flow contains a_to_b and b_to_a counts
    assert "a_to_b_pkts" in df_flows.columns and "b_to_a_pkts" in df_flows.columns, "Bidirectional columns missing!"

    print("[3/6] Testing SQL Console Security (Read-Only Enforcement)...")
    try:
        db.execute_custom_sql("DROP TABLE packets")
        assert False, "CRITICAL: DROP TABLE was not blocked!"
    except ValueError as e:
        print(f"      Successfully blocked DROP statement: {e}")
        assert "Violation" in str(e)

    try:
        db.execute_custom_sql("DELETE FROM packets WHERE id = 1")
        assert False, "CRITICAL: DELETE statement was not blocked!"
    except ValueError as e:
        print(f"      Successfully blocked DELETE statement: {e}")
        assert "Violation" in str(e)

    print("[4/6] Testing Threat Detector (Port Scan Classification)...")
    detector = ThreatDetector()
    alerts = detector.analyze(packets)
    print(f"      Detected {len(alerts)} alerts.")
    for a in alerts:
        print(f"      - [{a['Severity']}] {a['Attack Type']}: {a['Details']}")
    
    # Must specifically classify as Stealth SYN Port Scan
    assert any("Stealth SYN Port Scan" in a['Attack Type'] for a in alerts), "Stealth SYN scan classification failed!"

    print("[5/6] Testing Benign Traffic (False Positive Verification)...")
    benign_parser = PCAPParser(benign_pcap)
    benign_pkts, _ = benign_parser.parse()
    benign_alerts = detector.analyze(benign_pkts)
    print(f"      Benign traffic alert count: {len(benign_alerts)}")
    assert len(benign_alerts) == 0, f"False positives detected on benign traffic: {benign_alerts}"

    print("[6/6] Testing Web Attacks & HTML Report Rendering...")
    web_parser = PCAPParser(web_attack_pcap)
    web_pkts, _ = web_parser.parse()
    web_alerts = detector.analyze(web_pkts)
    print(f"      Detected {len(web_alerts)} web attack alerts:")
    for a in web_alerts:
        print(f"      - [{a['Severity']}] {a['Attack Type']}")
    
    assert any("SQL Injection" in a['Attack Type'] for a in web_alerts), "SQLi alert missing!"
    assert any("Cross-Site Scripting" in a['Attack Type'] for a in web_alerts), "XSS alert missing!"
    assert any("Directory" in a['Attack Type'] for a in web_alerts), "Directory traversal missing!"
    assert any("Credential Exposure" in a['Attack Type'] for a in web_alerts), "Credential exposure missing!"

    # Test HTML Report
    rep_gen = ReportGenerator("sample_web_attacks.pcap", "test_hash", 1024, len(web_pkts), "Scapy")
    html_rep = rep_gen.generate_html(web_alerts, {"HTTP": 4, "DNS": 1})
    assert "<!DOCTYPE html>" in html_rep, "HTML doctype missing!"
    assert "<table" in html_rep, "HTML table missing!"
    assert "<pre style=" not in html_rep, "Markdown raw pre tag found in HTML report!"
    print(f"      Rendered formatted HTML report ({len(html_rep)} characters).")

    # Test XML Export
    exporter = XMLExporter("sample_web_attacks.pcap", "test_hash")
    xml_out = exporter.generate_forensic_xml(web_pkts, web_alerts, xml_path)
    assert os.path.exists(xml_path), "XML export missing!"
    assert 'schema="Structured-Forensic-XML-v1.0"' in xml_out, "XML schema label missing!"
    assert 'SHA-256 Calculated at Ingestion' in xml_out, "XML baseline label missing!"

    print("\n✅ ALL 6 AUDIT FIXES AND SYSTEM TESTS PASSED PERFECTLY!")

if __name__ == "__main__":
    run_tests()
