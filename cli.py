"""
Terminal CLI Mode for Automated PCAP Forensic Analysis System
Run directly inside Windows Terminal / PowerShell / Command Prompt.

Usage:
    python cli.py sample_pcaps/sample_port_scan.pcap
    python cli.py sample_pcaps/sample_web_attacks.pcap
    python cli.py --list-samples
"""

import os
import sys
import argparse
import hashlib
from datetime import datetime

# Enable UTF-8 console output for Windows Terminal
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.pcap_parser import PCAPParser
from modules.database_manager import DatabaseManager
from modules.xml_exporter import XMLExporter
from modules.threat_detector import ThreatDetector
from modules.report_generator import ReportGenerator

# ANSI Terminal Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = f"""{CYAN}{BOLD}
╔═══════════════════════════════════════════════════════════════════════════════╗
║          AUTOMATED PCAP FORENSIC INVESTIGATION SYSTEM (CLI TERMINAL)         ║
║          Information Security Lab Project | Modules 4 & 7                     ║
║          Team: Riya Kushwah (58), Rahee Phapale (42), Kruthik Shetty (59)     ║
╚═══════════════════════════════════════════════════════════════════════════════╝{RESET}
"""

def print_header(title):
    print(f"\n{CYAN}{BOLD}▶ {title}{RESET}")
    print(f"{CYAN}{'─' * 70}{RESET}")

def run_cli(pcap_path):
    print(BANNER)
    if not os.path.exists(pcap_path):
        print(f"{RED}[ERROR] File not found: {pcap_path}{RESET}")
        return

    # 1. Hashing
    print_header("1. EVIDENCE INGESTION & CHAIN OF CUSTODY (NIST SP 800-86)")
    with open(pcap_path, "rb") as f:
        file_bytes = f.read()
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    filesize_kb = len(file_bytes) / 1024
    filename = os.path.basename(pcap_path)

    print(f"  • Target File    : {BOLD}{filename}{RESET}")
    print(f"  • File Size      : {filesize_kb:.2f} KB ({len(file_bytes)} bytes)")
    print(f"  • SHA-256 Hash   : {GREEN}{sha256}{RESET}")
    print(f"  • Integrity      : {GREEN}Baseline Hash Recorded Successfully{RESET}")

    # 2. Parsing
    print_header("2. PACKET EXTRACTION & DISSECTION (MODULE 7)")
    print(f"  Parsing packets via PyShark/Scapy dual-engine...")
    parser = PCAPParser(pcap_path)
    packets, engine = parser.parse()
    print(f"  • Engine Used    : {BOLD}{engine}{RESET}")
    print(f"  • Total Packets  : {BOLD}{len(packets)}{RESET}")

    # 3. Database Persistence
    print_header("3. PCAP TO SQLITE RELATIONAL PERSISTENCE (MODULE 4)")
    db_out = os.path.splitext(pcap_path)[0] + "_forensics.db"
    db = DatabaseManager(db_out)
    db.clear_existing_data()
    db.insert_packets_batch(packets)
    db.populate_network_flows()
    db.insert_evidence_meta(filename, sha256, len(file_bytes), len(packets), datetime.now().isoformat())
    print(f"  • SQLite Output  : {GREEN}{db_out}{RESET}")
    print(f"  • Tables Created : packets, network_flows, security_alerts, evidence_meta")
    
    # Show Protocol Breakdown
    proto_df = db.get_protocol_distribution()
    print("\n  [Protocol Breakdown]")
    for _, row in proto_df.iterrows():
        print(f"    - {row['protocol']:<10} : {row['count']:>4} packets ({row['total_bytes']:>6} bytes)")

    # Show Bidirectional Flows
    flows_df = db.execute_custom_sql("SELECT host_a, host_b, protocol, packet_count, a_to_b_pkts, b_to_a_pkts FROM network_flows LIMIT 5")
    print("\n  [Bidirectional Communication Sessions (Top 5)]")
    print(f"    {'Host A':<15} {'Host B':<15} {'Proto':<6} {'Total':<6} {'A->B':<6} {'B->A':<6}")
    print(f"    {'-'*15} {'-'*15} {'-'*6} {'-'*6} {'-'*6} {'-'*6}")
    for _, f in flows_df.iterrows():
        print(f"    {f['host_a']:<15} {f['host_b']:<15} {f['protocol']:<6} {f['packet_count']:<6} {f['a_to_b_pkts']:<6} {f['b_to_a_pkts']:<6}")

    # 4. Threat Detection
    print_header("4. ALGORITHMIC THREAT & ANOMALY DETECTION (MODULE 7)")
    detector = ThreatDetector()
    alerts = detector.analyze(packets)

    if alerts:
        print(f"  {RED}{BOLD}⚠️  {len(alerts)} THREAT ANOMALIES IDENTIFIED:{RESET}\n")
        for i, a in enumerate(alerts, 1):
            sev_color = RED if "High" in a['Severity'] else YELLOW
            print(f"  [{sev_color}{a['Severity']}{RESET}] Alert #{i}: {BOLD}{a['Attack Type']}{RESET}")
            print(f"      Attacker: {CYAN}{a['Attacker IP']}{RESET} ⟶ Target: {CYAN}{a['Target IP']}{RESET}")
            print(f"      Details : {a['Details']}\n")
            db.insert_alert(a['Severity'], a['Attack Type'], a['Attacker IP'], a['Target IP'], a['Details'], datetime.now().isoformat())
    else:
        print(f"  {GREEN}✅ Clean Traffic: No unauthorized port scans, floods, or attack signatures detected.{RESET}")

    # 5. XML Evidence Export
    print_header("5. PCAP TO XML STANDARDIZED EVIDENCE (MODULE 4)")
    xml_out = os.path.splitext(pcap_path)[0] + "_evidence.xml"
    exporter = XMLExporter(filename, sha256)
    exporter.generate_forensic_xml(packets, alerts, xml_out)
    print(f"  • XML Output     : {GREEN}{xml_out}{RESET} ({os.path.getsize(xml_out)/1024:.2f} KB)")
    print(f"  • Schema         : Structured-Forensic-XML-v1.0 (Well-Formed)")

    # 6. Forensic Report
    print_header("6. EXECUTIVE FORENSIC AUDIT REPORT (NIST SP 800-86)")
    rep_gen = ReportGenerator(filename, sha256, len(file_bytes), len(packets), engine)
    proto_dict = dict(zip(proto_df['protocol'], proto_df['count']))
    top_talkers_df = db.get_top_talkers(limit=6)
    top_talkers_list = top_talkers_df.to_dict(orient="records") if not top_talkers_df.empty else []
    flows_list = flows_df.to_dict(orient="records") if not flows_df.empty else []

    html_out = os.path.splitext(pcap_path)[0] + "_report.html"
    with open(html_out, "w", encoding="utf-8") as f_rep:
        f_rep.write(rep_gen.generate_html(alerts, proto_dict, top_talkers=top_talkers_list, flows_summary=flows_list))
    print(f"  • HTML Report    : {GREEN}{html_out}{RESET}")
    print(f"  • Status         : Investigation Complete & Archived")
    print(f"\n{GREEN}{BOLD}✔ Done! All forensic modules executed successfully.{RESET}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Terminal CLI for PCAP Forensic System")
    parser.add_argument("pcap", nargs="?", help="Path to .pcap or .pcapng file")
    parser.add_argument("--list-samples", action="store_true", help="List pre-loaded sample PCAPs")

    args = parser.parse_args()
    sample_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_pcaps")

    if args.list_samples:
        print(f"\n{CYAN}Available Pre-loaded Samples in {sample_dir}:{RESET}")
        for s in os.listdir(sample_dir):
            if s.endswith((".pcap", ".pcapng")):
                print(f"  • {s}")
        print()
    elif args.pcap:
        run_cli(args.pcap)
    else:
        # Default to sample_port_scan.pcap if no arg passed
        default_sample = os.path.join(sample_dir, "sample_port_scan.pcap")
        if os.path.exists(default_sample):
            print(f"{YELLOW}[INFO] No capture path specified. Running on default: {default_sample}{RESET}")
            run_cli(default_sample)
        else:
            parser.print_help()
