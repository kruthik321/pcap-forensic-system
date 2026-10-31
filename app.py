import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import hashlib
import os
import re
import sys
import tempfile
import importlib
import time
import json
from datetime import datetime

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import modules.pcap_parser
import modules.database_manager
import modules.xml_exporter
import modules.threat_detector
import modules.report_generator

# Force module reloads to prevent stale Streamlit cache
importlib.reload(modules.pcap_parser)
importlib.reload(modules.database_manager)
importlib.reload(modules.xml_exporter)
importlib.reload(modules.threat_detector)
importlib.reload(modules.report_generator)

from modules.pcap_parser import PCAPParser
from modules.database_manager import DatabaseManager
from modules.xml_exporter import XMLExporter
from modules.threat_detector import ThreatDetector
from modules.report_generator import ReportGenerator

# Page styling & configuration
st.set_page_config(
    page_title="PCAP Forensic Analysis & Threat Intel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ----------------- FUTURISTIC CYBER DARK CSS ----------------- #
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Outfit:wght@300;400;600;700;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Outfit', sans-serif;
    }

    code, pre, .stCodeBlock {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Main Container Background */
    .stApp {
        background: radial-gradient(circle at 10% 20%, #0b0f19 0%, #07090e 90%);
        color: #f3f4f6;
    }

    /* Cyber Glowing Header */
    .cyber-header {
        font-family: 'Outfit', sans-serif;
        font-size: 2.3rem;
        font-weight: 800;
        background: linear-gradient(135deg, #00f2fe 0%, #4facfe 40%, #00ff87 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-shadow: 0 0 25px rgba(0, 242, 254, 0.25);
        margin-bottom: 0.2rem;
        letter-spacing: -0.5px;
    }

    .cyber-sub {
        font-size: 0.95rem;
        color: #94a3b8;
        margin-bottom: 1.5rem;
        display: flex;
        align-items: center;
        gap: 10px;
    }

    /* Pulsing Status Pill */
    .pulse-dot {
        display: inline-block;
        width: 10px;
        height: 10px;
        background: #00ff87;
        border-radius: 50%;
        box-shadow: 0 0 10px #00ff87;
        animation: pulse 1.8s infinite;
    }
    @keyframes pulse {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 135, 0.7); }
        70% { transform: scale(1.1); box-shadow: 0 0 0 8px rgba(0, 255, 135, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 135, 0); }
    }

    /* Glassmorphism KPI Metric Cards */
    .metric-glass {
        background: rgba(17, 24, 39, 0.7);
        border: 1px solid rgba(0, 242, 254, 0.25);
        border-radius: 14px;
        padding: 1.2rem;
        backdrop-filter: blur(12px);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.45);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-glass:hover {
        transform: translateY(-2px);
        border-color: #00f2fe;
        box-shadow: 0 12px 36px 0 rgba(0, 242, 254, 0.15);
    }
    .metric-title {
        color: #94a3b8;
        font-size: 0.82rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .metric-val {
        color: #f8fafc;
        font-size: 1.85rem;
        font-weight: 700;
        margin-top: 0.3rem;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #0d121f !important;
        border-right: 1px solid rgba(0, 242, 254, 0.15);
    }

    /* Alert Glass Cards */
    .alert-card-red {
        background: rgba(239, 68, 68, 0.08);
        border: 1px solid rgba(239, 68, 68, 0.4);
        border-left: 5px solid #ef4444;
        border-radius: 10px;
        padding: 1rem;
        margin-bottom: 0.8rem;
    }
    .alert-card-amber {
        background: rgba(245, 158, 11, 0.08);
        border: 1px solid rgba(245, 158, 11, 0.4);
        border-left: 5px solid #f59e0b;
        border-radius: 10px;
        padding: 1rem;
        margin-bottom: 0.8rem;
    }

    /* Buttons Styling */
    .stButton>button {
        border-radius: 8px !important;
        font-weight: 600 !important;
        letter-spacing: 0.5px !important;
        transition: all 0.3s ease !important;
    }
</style>
""", unsafe_allow_html=True)

# ----------------- SESSION STATE ----------------- #
if "analyzed" not in st.session_state:
    st.session_state.analyzed = False
if "db_manager" not in st.session_state:
    st.session_state.db_manager = None
if "packets_data" not in st.session_state:
    st.session_state.packets_data = []
if "alerts_data" not in st.session_state:
    st.session_state.alerts_data = []
if "xml_content" not in st.session_state:
    st.session_state.xml_content = ""
if "meta_info" not in st.session_state:
    st.session_state.meta_info = {}

TEMP_DIR = tempfile.gettempdir()
DB_FILE = os.path.join(TEMP_DIR, "forensic_analysis.db")
XML_FILE = os.path.join(TEMP_DIR, "forensic_export.xml")

# ----------------- SIDEBAR: EVIDENCE INGESTION ----------------- #
st.sidebar.markdown("""
<div style="display: flex; align-items: center; gap: 12px; margin-bottom: 10px;">
    <div style="font-size: 2.2rem;">⚡</div>
    <div>
        <div style="font-weight: 800; font-size: 1.25rem; color: #00f2fe; letter-spacing: -0.5px;">CYBER FORENSICS</div>
        <div style="font-size: 0.75rem; color: #64748b; font-family: 'JetBrains Mono', monospace;">SOC TERMINAL v2.4</div>
    </div>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown('<span class="pulse-dot"></span> <span style="font-size: 0.8rem; color: #10b981; font-weight: 600; font-family: monospace;">STATION: ONLINE // NIST SP 800-86</span>', unsafe_allow_html=True)
st.sidebar.divider()

st.sidebar.subheader("1. Ingest Capture Artifact")
upload_mode = st.sidebar.radio("Data Source:", ["Use Pre-loaded Sample Capture", "Upload PCAP File"])

sample_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_pcaps")
os.makedirs(sample_dir, exist_ok=True)

selected_file_path = None
file_bytes = None
original_filename = ""

if upload_mode == "Upload PCAP File":
    uploaded = st.sidebar.file_uploader("Upload .pcap / .pcapng file", type=["pcap", "pcapng"])
    if uploaded is not None:
        file_bytes = uploaded.read()
        # Sanitize uploaded filename to prevent directory traversal
        clean_name = os.path.basename(uploaded.name)
        clean_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', clean_name)
        original_filename = clean_name
        temp_path = os.path.join(TEMP_DIR, clean_name)
        with open(temp_path, "wb") as f:
            f.write(file_bytes)
        selected_file_path = temp_path
else:
    sample_files = [f for f in os.listdir(sample_dir) if f.endswith(('.pcap', '.pcapng'))]
    if sample_files:
        chosen_sample = st.sidebar.selectbox("Choose Attack/Traffic Sample:", sample_files)
        selected_file_path = os.path.join(sample_dir, chosen_sample)
        original_filename = chosen_sample
        with open(selected_file_path, "rb") as f:
            file_bytes = f.read()

# Evidence Cryptographic Hashing
if file_bytes and selected_file_path:
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    filesize_kb = len(file_bytes) / 1024

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🔐 Chain of Custody")
    st.sidebar.markdown(f"""
    <div style="background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(0, 242, 254, 0.2); border-radius: 8px; padding: 10px; font-size: 0.82rem; font-family: 'JetBrains Mono', monospace;">
        <span style="color: #64748b;">FILE:</span> <span style="color: #38bdf8;">{original_filename}</span><br>
        <span style="color: #64748b;">SIZE:</span> <span style="color: #f1f5f9;">{filesize_kb:.2f} KB</span><br>
        <span style="color: #64748b;">SHA-256 BASELINE:</span><br>
        <span style="color: #00ff87; font-size: 0.72rem; word-break: break-all;">{sha256_hash}</span>
    </div>
    """, unsafe_allow_html=True)

    if st.sidebar.button("🚀 INITIATE FORENSIC SCAN", type="primary", use_container_width=True):
        with st.spinner("Decoding binary frames, populating SQLite & evaluating heuristic threat signatures..."):
            parser = PCAPParser(selected_file_path)
            packets, engine = parser.parse()

            # Initialize SQLite DB
            db = DatabaseManager(DB_FILE)
            db.clear_existing_data()
            db.insert_packets_batch(packets)
            db.populate_network_flows()

            # Run Threat Detector
            detector = ThreatDetector()
            alerts = detector.analyze(packets)
            for a in alerts:
                db.insert_alert(
                    severity=a.get("Severity", "Info"),
                    attack_type=a.get("Attack Type", "Unknown"),
                    src_ip=a.get("Attacker IP", "N/A"),
                    dst_ip=a.get("Target IP", "N/A"),
                    details=a.get("Details", ""),
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )

            # Insert metadata
            db.insert_evidence_meta(
                filename=original_filename,
                sha256=sha256_hash,
                filesize=len(file_bytes),
                total_packets=len(packets),
                timestamp=datetime.now().isoformat()
            )

            # XML Export
            exporter = XMLExporter(original_filename, sha256_hash)
            xml_str = exporter.generate_forensic_xml(packets, alerts, XML_FILE)

            # Store state
            st.session_state.analyzed = True
            st.session_state.db_manager = db
            st.session_state.packets_data = packets
            st.session_state.alerts_data = alerts
            st.session_state.xml_content = xml_str
            st.session_state.meta_info = {
                "filename": original_filename,
                "filepath": selected_file_path,
                "sha256": sha256_hash,
                "filesize": len(file_bytes),
                "total_packets": len(packets),
                "engine": engine
            }
            st.rerun()

    # Genuine Hash Re-Verification Button (Addresses Issue 2)
    if st.session_state.analyzed and "filepath" in st.session_state.meta_info:
        st.sidebar.markdown("---")
        st.sidebar.markdown("### 🔍 Evidence Verification")
        if st.sidebar.button("Re-verify File Integrity", use_container_width=True):
            try:
                with open(st.session_state.meta_info["filepath"], "rb") as f_check:
                    curr_hash = hashlib.sha256(f_check.read()).hexdigest()
                baseline = st.session_state.meta_info["sha256"]
                if curr_hash == baseline:
                    st.sidebar.success("✅ Integrity Confirmed: Current file SHA-256 matches baseline recorded at ingestion.")
                else:
                    st.sidebar.error("❌ Integrity Alert: File hash has changed relative to baseline!")
            except Exception as e:
                st.sidebar.warning(f"Verification error: {e}")

st.sidebar.divider()
st.sidebar.markdown("""
<div style="font-size: 0.8rem; color: #64748b;">
    <b style="color: #94a3b8;">INVESTIGATION CREW:</b><br>
    ⚡ Riya Kushwah (Roll 58)<br>
    ⚡ Rahee Phapale (Roll 42)<br>
    ⚡ Kruthik Shetty (Roll 59)
</div>
""", unsafe_allow_html=True)

# ----------------- MAIN CONTENT AREA ----------------- #

st.markdown('<div class="cyber-header">AUTOMATED PCAP FORENSIC INVESTIGATION SYSTEM</div>', unsafe_allow_html=True)
st.markdown("""
<div class="cyber-sub">
    <span><b>MODULE 4:</b> PCAP to SQLite & XML</span> • 
    <span><b>MODULE 7:</b> Traffic Analysis (Wireshark/PyShark)</span> • 
    <span style="color: #00f2fe; font-family: monospace;">[DEFENSE CONSOLE ACTIVE]</span>
</div>
""", unsafe_allow_html=True)

if not st.session_state.analyzed:
    st.info("💡 **Ready for Analysis:** Select a pre-loaded attack sample from the sidebar and click **'INITIATE FORENSIC SCAN'**.")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        <div class="metric-glass">
            <div style="font-size: 1.5rem; margin-bottom: 5px;">🗄️</div>
            <div class="metric-title">Module 4: PCAP to SQLite</div>
            <p style="color: #cbd5e1; font-size: 0.88rem; margin-top: 8px;">
                Converts raw binary captures into structured SQLite tables with B-Tree indexes for instantaneous SQL queries and timeline reconstruction.
            </p>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div class="metric-glass">
            <div style="font-size: 1.5rem; margin-bottom: 5px;">📄</div>
            <div class="metric-title">Module 4: PCAP to XML</div>
            <p style="color: #cbd5e1; font-size: 0.88rem; margin-top: 8px;">
                Produces structured hierarchical Forensic XML preserving chain of custody metadata and standardized multi-tool SIEM exchange.
            </p>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown("""
        <div class="metric-glass">
            <div style="font-size: 1.5rem; margin-bottom: 5px;">🚨</div>
            <div class="metric-title">Module 7: Traffic & Threat Intel</div>
            <p style="color: #cbd5e1; font-size: 0.88rem; margin-top: 8px;">
                Inspects protocol flags, frequencies, and payloads to identify Stealth Port Scans, SYN Floods, unencrypted passwords, and web attack signatures.
            </p>
        </div>
        """, unsafe_allow_html=True)
    st.stop()

# Load data from state
meta = st.session_state.meta_info
db = st.session_state.db_manager
df_packets = db.get_packets_df(limit=5000)
alerts = st.session_state.alerts_data

# Cyber KPI Ribbon
k1, k2, k3, k4 = st.columns(4)
with k1:
    st.markdown(f"""
    <div class="metric-glass">
        <div class="metric-title">📦 Total Packets Inspected</div>
        <div class="metric-val" style="color: #38bdf8;">{meta['total_packets']:,}</div>
    </div>
    """, unsafe_allow_html=True)

with k2:
    proto_count = df_packets["protocol"].nunique() if not df_packets.empty else 0
    st.markdown(f"""
    <div class="metric-glass">
        <div class="metric-title">🌐 Protocols Carved</div>
        <div class="metric-val" style="color: #a855f7;">{proto_count}</div>
    </div>
    """, unsafe_allow_html=True)

with k3:
    threat_color = "#ef4444" if alerts else "#10b981"
    threat_text = f"{len(alerts)} ALERTS" if alerts else "CLEAN"
    st.markdown(f"""
    <div class="metric-glass">
        <div class="metric-title">🚨 Threat Level</div>
        <div class="metric-val" style="color: {threat_color};">{threat_text}</div>
    </div>
    """, unsafe_allow_html=True)

with k4:
    st.markdown(f"""
    <div class="metric-glass">
        <div class="metric-title">⚙️ Dissection Engine</div>
        <div class="metric-val" style="color: #00ff87; font-size: 1.45rem;">{meta.get('engine', 'Scapy').split()[0]}</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Cyber Navigation Tabs
tab_traffic, tab_sqlite, tab_xml, tab_threats, tab_report = st.tabs([
    "📊 Traffic Analytics (Module 7)",
    "🗄️ SQLite Explorer (Module 4)",
    "📄 XML Evidence (Module 4)",
    "🚨 Incident Threats & Alerts",
    "📑 Forensic Investigation Report"
])

CYBER_COLORS = ["#00f2fe", "#a855f7", "#00ff87", "#f43f5e", "#f59e0b", "#38bdf8", "#e11d48"]

# ----------------- TAB 1: TRAFFIC ANALYSIS ----------------- #
with tab_traffic:
    st.subheader("Deep Packet Traffic Analytics (Module 7)")
    
    if not df_packets.empty:
        col_c1, col_c2 = st.columns(2)
        
        with col_c1:
            proto_df = db.get_protocol_distribution()
            fig_proto = px.pie(
                proto_df, 
                names="protocol", 
                values="count", 
                title="Protocol Volume Distribution",
                hole=0.45,
                color_discrete_sequence=CYBER_COLORS,
                template="plotly_dark"
            )
            fig_proto.update_layout(
                paper_bgcolor="rgba(17, 24, 39, 0.4)",
                plot_bgcolor="rgba(17, 24, 39, 0.4)",
                font=dict(family="Outfit, sans-serif", color="#f8fafc")
            )
            st.plotly_chart(fig_proto, use_container_width=True)

        with col_c2:
            top_senders = db.get_top_talkers(limit=6)
            fig_talkers = px.bar(
                top_senders,
                x="src_ip",
                y="packets_sent",
                title="Top Transmitting Source Hosts (Top Talkers)",
                labels={"src_ip": "Source IP", "packets_sent": "Packets Sent"},
                color="packets_sent",
                color_continuous_scale="Teal",
                template="plotly_dark"
            )
            fig_talkers.update_layout(
                paper_bgcolor="rgba(17, 24, 39, 0.4)",
                plot_bgcolor="rgba(17, 24, 39, 0.4)",
                font=dict(family="Outfit, sans-serif", color="#f8fafc")
            )
            st.plotly_chart(fig_talkers, use_container_width=True)

        # True Bidirectional Flows Table (Addresses Issue 4)
        st.subheader("Aggregated Bidirectional Sessions (`network_flows`)")
        st.caption("Packets grouped by canonical host pairs, tracking total packets, bytes, and directional volume.")
        flows_df = db.execute_custom_sql("""
            SELECT host_a, host_b, protocol, packet_count, a_to_b_pkts, b_to_a_pkts, total_bytes, first_seen, last_seen 
            FROM network_flows 
            ORDER BY packet_count DESC LIMIT 20
        """)
        st.dataframe(flows_df, use_container_width=True, height=260)
    else:
        st.warning("No packet records found in this capture.")

# ----------------- TAB 2: SQLITE EXPLORER ----------------- #
with tab_sqlite:
    st.subheader("Relational Database Explorer (PCAP to SQLite)")
    st.caption("Packets converted and indexed into SQLite for relational queries, timeline correlation, and evidence extraction.")

    f_col1, f_col2, f_col3 = st.columns(3)
    proto_filter = f_col1.multiselect("Filter Protocol:", options=df_packets["protocol"].unique().tolist())
    ip_search = f_col2.text_input("Search Host IP:")
    port_search = f_col3.text_input("Filter Port:")

    filtered_df = df_packets.copy()
    if proto_filter:
        filtered_df = filtered_df[filtered_df["protocol"].isin(proto_filter)]
    if ip_search:
        filtered_df = filtered_df[(filtered_df["src_ip"].str.contains(ip_search, na=False)) | (filtered_df["dst_ip"].str.contains(ip_search, na=False))]
    if port_search and port_search.isdigit():
        p_val = int(port_search)
        filtered_df = filtered_df[(filtered_df["src_port"] == p_val) | (filtered_df["dst_port"] == p_val)]

    st.dataframe(
        filtered_df[["packet_num", "timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "length", "tcp_flags", "info"]],
        use_container_width=True,
        height=320
    )

    st.divider()

    # ----------------- ADVANCED FORENSIC SQL CONSOLE ----------------- #
    st.markdown("""
    <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 10px; padding: 14px 20px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center;">
        <div>
            <span style="color: #38bdf8; font-weight: 700; font-size: 1.15rem; letter-spacing: 0.5px;">⚡ ADVANCED FORENSIC SQL TERMINAL</span>
            <div style="color: #94a3b8; font-size: 0.85rem; margin-top: 2px;">
                Engine: <code>SQLite 3 (Indexed)</code> &bull; Driver URI: <code>file:forensic.db?mode=ro</code> &bull; Standard: <code>NIST SP 800-86 Immutable</code>
            </div>
        </div>
        <div style="display: flex; gap: 8px;">
            <span style="background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid #10b981; padding: 4px 10px; border-radius: 9999px; font-size: 0.75rem; font-weight: 700;">
                ● READ-ONLY ENFORCED
            </span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 1. Interactive Database Schema & Index Registry
    with st.expander("🔍 Interactive Database Schema & B-Tree Index Registry (Module 4)", expanded=False):
        tab_schema_tbl, tab_schema_idx = st.tabs(["📋 Tables & Columns", "⚡ B-Tree Indexes (Query Optimization)"])
        
        with tab_schema_tbl:
            s_c1, s_c2 = st.columns(2)
            with s_c1:
                st.markdown("""
                **1. `packets` Table (Raw Network Frames):**
                * `packet_num` (INTEGER) - Frame arrival sequence
                * `timestamp` (TEXT) - Packet capture timestamp
                * `src_ip`, `dst_ip` (TEXT) - Endpoint IP addresses
                * `protocol` (TEXT) - Protocol name (TCP, UDP, HTTP, DNS, ICMP)
                * `src_port`, `dst_port` (INTEGER) - Transport port numbers
                * `length` (INTEGER) - Frame size in bytes
                * `tcp_flags` (TEXT) - Normalized TCP control flags (S, A, R, F, etc.)
                * `payload_preview` (TEXT) - Extracted application payload string
                * `info` (TEXT) - Summary / query diagnostic string
                """)
                st.markdown("""
                **2. `network_flows` Table (True Bidirectional Sessions):**
                * `host_a`, `host_b` (TEXT) - Canonical host pair (`host_a <= host_b`)
                * `protocol` (TEXT) - Transport protocol
                * `packet_count`, `total_bytes` (INTEGER) - Volume aggregations
                * `a_to_b_pkts`, `b_to_a_pkts` (INTEGER) - Directional symmetry counts
                * `first_seen`, `last_seen` (TEXT) - Session temporal boundaries
                """)
            with s_c2:
                st.markdown("""
                **3. `security_alerts` Table (Algorithmic Detections):**
                * `id` (INTEGER PRIMARY KEY)
                * `timestamp` (TEXT) - Incident detection timestamp
                * `severity` (TEXT) - Threat severity (High / Medium / Low)
                * `attack_type` (TEXT) - Attack classification
                * `src_ip`, `dst_ip` (TEXT) - Attacker & target addresses
                * `details` (TEXT) - Evidentiary findings & metrics
                * `packet_ref` (INTEGER) - Foreign key reference to `packets.packet_num`
                """)
                st.markdown("""
                **4. `evidence_meta` Table (Digital Custody Baseline):**
                * `filename` (TEXT) - Evidence capture name
                * `sha256` (TEXT) - Ingestion baseline cryptographic hash
                * `filesize_bytes` (INTEGER) - Byte size
                * `total_packets` (INTEGER) - Packet count
                * `analyzed_at` (TEXT) - Forensic session timestamp
                """)
        
        with tab_schema_idx:
            st.markdown("""
            **Active Forensic Indexes (B-Tree Data Structures):**  
            Module 4 provisions dedicated B-Tree indexes to accelerate forensic time-series reconstruction and filter queries across large PCAP databases without linear table scans.
            """)
            try:
                indexes_df = db.execute_custom_sql("SELECT name as index_name, tbl_name as target_table, sql as definition FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL")
                st.dataframe(indexes_df, use_container_width=True)
            except Exception as e:
                st.caption(f"Index query note: {e}")

    # 2. Categorized Forensic Preset Library
    FORENSIC_PRESETS = {
        "🎯 Reconnaissance & Port Scanning": {
            "Half-Open SYN Scan Probes (High Port Count)": (
                "SELECT src_ip, dst_ip, COUNT(DISTINCT dst_port) as scanned_ports, "
                "MIN(timestamp) as first_probe, MAX(timestamp) as last_probe "
                "FROM packets WHERE tcp_flags LIKE '%S%' AND tcp_flags NOT LIKE '%A%' "
                "GROUP BY src_ip, dst_ip HAVING scanned_ports >= 5"
            ),
            "Port Scan Response Audit (RST-ACK Distribution)": (
                "SELECT src_ip, dst_ip, dst_port, tcp_flags, COUNT(*) as reply_count "
                "FROM packets WHERE tcp_flags LIKE '%R%' OR tcp_flags LIKE '%RA%' "
                "GROUP BY src_ip, dst_ip, dst_port ORDER BY reply_count DESC LIMIT 20"
            ),
            "Targeted Destination Ports & Identified Services": (
                "SELECT dst_port, COUNT(*) as hit_count, "
                "CASE "
                "  WHEN dst_port = 21 THEN 'FTP' "
                "  WHEN dst_port = 22 THEN 'SSH' "
                "  WHEN dst_port = 23 THEN 'Telnet' "
                "  WHEN dst_port = 25 THEN 'SMTP' "
                "  WHEN dst_port = 53 THEN 'DNS' "
                "  WHEN dst_port = 80 THEN 'HTTP' "
                "  WHEN dst_port = 443 THEN 'HTTPS' "
                "  WHEN dst_port = 445 THEN 'SMB' "
                "  WHEN dst_port = 1433 THEN 'MSSQL' "
                "  WHEN dst_port = 3306 THEN 'MySQL' "
                "  WHEN dst_port = 3389 THEN 'RDP' "
                "  ELSE 'Other / Dynamic' "
                "END as service_name "
                "FROM packets WHERE dst_port > 0 GROUP BY dst_port ORDER BY hit_count DESC LIMIT 15"
            )
        },
        "🕷️ Web Exploits & Payload Carving": {
            "SQL Injection Attack Signatures (SQLi)": (
                "SELECT packet_num, timestamp, src_ip, dst_ip, payload_preview "
                "FROM packets WHERE payload_preview LIKE '%UNION%' OR payload_preview LIKE '%OR 1=1%' "
                "OR payload_preview LIKE '%'' OR ''1''=''1%' OR payload_preview LIKE '%SELECT%' LIMIT 20"
            ),
            "Cross-Site Scripting (XSS) Payloads": (
                "SELECT packet_num, timestamp, src_ip, dst_ip, payload_preview "
                "FROM packets WHERE payload_preview LIKE '%<script%' OR payload_preview LIKE '%alert(%' "
                "OR payload_preview LIKE '%javascript:%' LIMIT 20"
            ),
            "Directory & Path Traversal Exploits": (
                "SELECT packet_num, timestamp, src_ip, dst_ip, payload_preview "
                "FROM packets WHERE payload_preview LIKE '%../%' OR payload_preview LIKE '%etc/passwd%' "
                "OR payload_preview LIKE '%win.ini%' LIMIT 20"
            ),
            "Plaintext Credential Sniffing": (
                "SELECT packet_num, timestamp, src_ip, dst_ip, protocol, payload_preview "
                "FROM packets WHERE payload_preview LIKE '%user=%' OR payload_preview LIKE '%pass=%' "
                "OR payload_preview LIKE '%password%' OR payload_preview LIKE '%login%' LIMIT 20"
            )
        },
        "🌐 DNS Intelligence & Exfiltration": {
            "Suspicious Long DNS Queries (>65 Bytes)": (
                "SELECT packet_num, timestamp, src_ip, dst_ip, length, info "
                "FROM packets WHERE protocol = 'DNS' AND length > 65 ORDER BY length DESC"
            ),
            "DNS Name Resolution Inventory": (
                "SELECT packet_num, timestamp, src_ip, dst_ip, info "
                "FROM packets WHERE protocol = 'DNS' LIMIT 25"
            )
        },
        "🔄 Flows, Sessions & Bandwidth": {
            "Top Bidirectional Sessions by Volume": (
                "SELECT host_a, host_b, protocol, packet_count, total_bytes, "
                "a_to_b_pkts, b_to_a_pkts, first_seen, last_seen "
                "FROM network_flows ORDER BY total_bytes DESC LIMIT 15"
            ),
            "Session Directional Symmetry Analysis": (
                "SELECT host_a, host_b, protocol, packet_count, "
                "ROUND(100.0 * a_to_b_pkts / packet_count, 1) as a_to_b_pct, "
                "ROUND(100.0 * b_to_a_pkts / packet_count, 1) as b_to_a_pct, "
                "CASE WHEN a_to_b_pkts = b_to_a_pkts THEN 'Symmetric (1:1)' ELSE 'Asymmetric (Probing/One-Way)' END as flow_nature "
                "FROM network_flows ORDER BY packet_count DESC LIMIT 15"
            ),
            "Top Transmitting Source Talkers with Packet Sizing": (
                "SELECT src_ip, COUNT(*) as packets_sent, SUM(length) as total_bytes, "
                "ROUND(AVG(length), 1) as avg_packet_bytes "
                "FROM packets WHERE src_ip != 'N/A' "
                "GROUP BY src_ip ORDER BY packets_sent DESC LIMIT 10"
            )
        },
        "🚨 Correlated Incident Forensics": {
            "Security Alerts JOINed with Packet Payloads": (
                "SELECT a.id as alert_id, a.severity, a.attack_type, a.src_ip as attacker_ip, "
                "a.dst_ip as victim_ip, a.details, p.packet_num, p.protocol, p.tcp_flags, p.payload_preview "
                "FROM security_alerts a "
                "LEFT JOIN packets p ON a.src_ip = p.src_ip AND a.dst_ip = p.dst_ip "
                "GROUP BY a.id LIMIT 25"
            ),
            "Incident Threat Counts by Target Host": (
                "SELECT dst_ip as target_ip, COUNT(*) as incident_count, "
                "GROUP_CONCAT(DISTINCT attack_type) as attack_vectors "
                "FROM security_alerts GROUP BY dst_ip"
            )
        },
        "🛡️ Tampering Defense Simulation": {
            "Simulate DROP TABLE Tampering (Should be Blocked)": (
                "DROP TABLE packets"
            ),
            "Simulate DELETE Evidence Tampering (Should be Blocked)": (
                "DELETE FROM security_alerts WHERE severity = 'High'"
            ),
            "Simulate UPDATE Payload Tampering (Should be Blocked)": (
                "UPDATE packets SET payload_preview = 'TAMPERED' WHERE packet_num = 1"
            )
        }
    }

    if "current_sql" not in st.session_state:
        st.session_state["current_sql"] = "SELECT protocol, COUNT(*) as count, SUM(length) as total_bytes FROM packets GROUP BY protocol ORDER BY count DESC"
    if "sql_history" not in st.session_state:
        st.session_state["sql_history"] = []

    # Two column layout: Presets Library on Left, Query Editor on Right
    c_preset, c_editor = st.columns([1, 2])
    
    with c_preset:
        st.markdown("**📚 Forensic Query Library**")
        sel_cat = st.selectbox("1. Category:", list(FORENSIC_PRESETS.keys()))
        sel_query_name = st.selectbox("2. Forensic Preset:", list(FORENSIC_PRESETS[sel_cat].keys()))
        if st.button("📥 Load Preset into Editor", use_container_width=True):
            st.session_state["current_sql"] = FORENSIC_PRESETS[sel_cat][sel_query_name]
            st.rerun()

    with c_editor:
        st.markdown("**✍️ Interactive SQL Query Editor**")
        user_sql = st.text_area(
            "SQL Statement (Read-Only Mode):", 
            value=st.session_state.get("current_sql", ""), 
            height=125,
            help="Type arbitrary read-only SQL statements. Prohibited keywords (DROP, DELETE, UPDATE, INSERT, ALTER) are automatically rejected."
        )
        
        # Command Action Bar
        act_c1, act_c2, act_c3 = st.columns([1.2, 1.2, 1.3])
        with act_c1:
            btn_exec = st.button("▶ EXECUTE QUERY", type="primary", use_container_width=True)
        with act_c2:
            btn_plan = st.button("🔍 EXPLAIN PLAN", use_container_width=True)
        with act_c3:
            btn_tamper = st.button("🛡️ TEST TAMPER GUARD", use_container_width=True)

    # 3. Execution & Profiling Engine
    query_to_run = None
    is_explain_plan = False

    if btn_tamper:
        query_to_run = "DROP TABLE packets"
    elif btn_plan:
        query_to_run = user_sql
        is_explain_plan = True
    elif btn_exec:
        query_to_run = user_sql

    if query_to_run:
        clean_target = query_to_run.strip()
        
        # Record into history
        if clean_target and (not st.session_state["sql_history"] or st.session_state["sql_history"][-1] != clean_target):
            st.session_state["sql_history"].append(clean_target)
            if len(st.session_state["sql_history"]) > 6:
                st.session_state["sql_history"].pop(0)

        try:
            if is_explain_plan:
                if not clean_target.upper().startswith("EXPLAIN"):
                    plan_query = f"EXPLAIN QUERY PLAN {clean_target}"
                else:
                    plan_query = clean_target
                t0 = time.perf_counter()
                plan_res = db.execute_custom_sql(plan_query)
                elapsed_ms = (time.perf_counter() - t0) * 1000
                
                st.markdown(f"""
                <div style="background: rgba(14, 165, 233, 0.1); border: 1px solid #0ea5e9; border-radius: 8px; padding: 10px 14px; margin: 15px 0 10px 0; display: flex; justify-content: space-between; align-items: center;">
                    <span style="color: #38bdf8; font-weight: 700;">🔍 SQLITE QUERY EXECUTION PLAN</span>
                    <span style="color: #94a3b8; font-size: 0.82rem;">Planner Latency: <b>{elapsed_ms:.2f} ms</b> &bull; Cost-Based Optimizer</span>
                </div>
                """, unsafe_allow_html=True)
                
                st.dataframe(plan_res, use_container_width=True)
                
                # Check if index was used in detail
                details_text = " ".join(plan_res["detail"].tolist()) if "detail" in plan_res.columns else ""
                if "USING INDEX" in details_text.upper() or "USING COVERING INDEX" in details_text.upper():
                    st.success("✅ Index Acceleration Active: SQLite utilized a B-Tree index structure rather than a full-table scan.")
                else:
                    st.info("ℹ️ Table Scan: SQLite performed a sequential table scan. For large datasets, consider adding an index on the filtered column.")
            else:
                t0 = time.perf_counter()
                res_df = db.execute_custom_sql(clean_target)
                elapsed_ms = (time.perf_counter() - t0) * 1000

                # Telemetry HUD
                st.markdown(f"""
                <div style="background: rgba(17, 24, 39, 0.7); border: 1px solid rgba(0, 242, 254, 0.25); border-radius: 8px; padding: 10px 16px; margin: 15px 0 10px 0; display: flex; flex-wrap: wrap; gap: 15px; align-items: center;">
                    <div><span style="color: #64748b; font-size: 0.75rem; text-transform: uppercase;">Execution Latency:</span> <span style="color: #00ff87; font-weight: 700; font-family: monospace;">{elapsed_ms:.2f} ms</span></div>
                    <div><span style="color: #64748b; font-size: 0.75rem; text-transform: uppercase;">Records Returned:</span> <span style="color: #38bdf8; font-weight: 700; font-family: monospace;">{len(res_df)} rows</span></div>
                    <div><span style="color: #64748b; font-size: 0.75rem; text-transform: uppercase;">Integrity Guard:</span> <span style="color: #10b981; font-weight: 700;">PASSED (Zero DDL Violations)</span></div>
                    <div><span style="color: #64748b; font-size: 0.75rem; text-transform: uppercase;">Connection Mode:</span> <span style="color: #cbd5e1; font-family: monospace;">file:...db?mode=ro</span></div>
                </div>
                """, unsafe_allow_html=True)

                if res_df.empty:
                    st.info("Query executed successfully, but returned 0 rows matching the specified criteria.")
                else:
                    st.dataframe(res_df, use_container_width=True, height=280)

                    # Export Results & Auto-Visualization
                    c_exp1, c_exp2, c_plot_toggle = st.columns([1, 1, 2])
                    with c_exp1:
                        csv_data = res_df.to_csv(index=False).encode('utf-8')
                        st.download_button(
                            "📥 Download CSV",
                            data=csv_data,
                            file_name=f"query_result_{int(time.time())}.csv",
                            mime="text/csv",
                            use_container_width=True
                        )
                    with c_exp2:
                        json_data = res_df.to_json(orient="records", indent=2).encode('utf-8')
                        st.download_button(
                            "📥 Download JSON",
                            data=json_data,
                            file_name=f"query_result_{int(time.time())}.json",
                            mime="application/json",
                            use_container_width=True
                        )
                    with c_plot_toggle:
                        enable_plot = st.checkbox("📈 Auto-Visualize Query Output (Plotly Chart)", value=False)

                    # Dynamic Visualizer
                    if enable_plot and len(res_df.columns) >= 2:
                        st.markdown("<br>", unsafe_allow_html=True)
                        p_col1, p_col2, p_col3 = st.columns(3)
                        chart_type = p_col1.selectbox("Chart Type:", ["Bar Chart", "Line Chart", "Donut Chart", "Area Chart"])
                        x_col = p_col2.selectbox("X-Axis (Category):", options=res_df.columns.tolist(), index=0)
                        
                        # Find numeric column candidates for Y-axis
                        num_cols = [c for c in res_df.columns if pd.api.types.is_numeric_dtype(res_df[c])]
                        y_default_idx = res_df.columns.get_loc(num_cols[0]) if num_cols else (1 if len(res_df.columns) > 1 else 0)
                        y_col = p_col3.selectbox("Y-Axis (Metric):", options=res_df.columns.tolist(), index=y_default_idx)

                        if chart_type == "Bar Chart":
                            fig_q = px.bar(res_df, x=x_col, y=y_col, template="plotly_dark", color_discrete_sequence=["#00f2fe"])
                        elif chart_type == "Line Chart":
                            fig_q = px.line(res_df, x=x_col, y=y_col, markers=True, template="plotly_dark", color_discrete_sequence=["#00ff87"])
                        elif chart_type == "Donut Chart":
                            fig_q = px.pie(res_df, names=x_col, values=y_col, hole=0.45, template="plotly_dark", color_discrete_sequence=CYBER_COLORS)
                        else:
                            fig_q = px.area(res_df, x=x_col, y=y_col, template="plotly_dark", color_discrete_sequence=["#a855f7"])

                        fig_q.update_layout(
                            paper_bgcolor="rgba(17, 24, 39, 0.4)",
                            plot_bgcolor="rgba(17, 24, 39, 0.4)",
                            font=dict(family="Outfit, sans-serif", color="#f8fafc"),
                            title=f"Dynamic Query Plot: {x_col} vs {y_col}"
                        )
                        st.plotly_chart(fig_q, use_container_width=True)

        except ValueError as ve:
            # Styled Defense Guard Violation Alert
            st.markdown(f"""
            <div style="background: rgba(239, 68, 68, 0.15); border: 2px solid #ef4444; border-radius: 10px; padding: 16px 20px; margin-top: 15px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 1.5rem;">🛑</span>
                    <div>
                        <div style="color: #ef4444; font-weight: 800; font-size: 1.05rem; letter-spacing: 0.5px;">
                            FORENSIC READ-ONLY SECURITY GUARD TRIGGERED
                        </div>
                        <div style="color: #fca5a5; font-size: 0.88rem; margin-top: 2px;">
                            Evidence Integrity Protected: SQL statements modifying database records or schemas are strictly rejected under NIST SP 800-86 digital chain of custody guidelines.
                        </div>
                    </div>
                </div>
                <div style="background: rgba(0, 0, 0, 0.3); border-radius: 6px; padding: 10px 12px; margin-top: 10px; font-family: monospace; font-size: 0.85rem; color: #f87171;">
                    {ve}
                </div>
            </div>
            """, unsafe_allow_html=True)
        except Exception as e:
            st.error(f"SQL Syntax Error: {e}")

    # 4. Session Query History
    if st.session_state.get("sql_history"):
        with st.expander("🕒 Session Query History (Last Executed Statements)", expanded=False):
            for idx, q_hist in enumerate(reversed(st.session_state["sql_history"]), start=1):
                st.code(q_hist, language="sql")

    # 5. Database File Download Button
    if os.path.exists(DB_FILE):
        st.markdown("<br>", unsafe_allow_html=True)
        with open(DB_FILE, "rb") as f_db:
            st.download_button(
                label="💾 Download Complete SQLite Evidence Database (.db)",
                data=f_db,
                file_name=f"forensic_{meta['filename']}.db",
                mime="application/x-sqlite3",
                use_container_width=True
            )

# ----------------- TAB 3: XML EVIDENCE ----------------- #
with tab_xml:
    st.subheader("Structured XML Evidence (PCAP to XML)")
    st.caption("Hierarchical forensic XML capturing evidence chain of custody, packet layers, and findings.")

    if os.path.exists(XML_FILE):
        with open(XML_FILE, "r", encoding="utf-8") as f_xml:
            xml_text = f_xml.read()

        c1, c2 = st.columns([1, 3])
        with c1:
            st.download_button(
                label="📥 Download Evidence XML (.xml)",
                data=xml_text,
                file_name=f"evidence_{meta['filename']}.xml",
                mime="application/xml",
                type="primary",
                use_container_width=True
            )
            st.markdown(f"""
            <div style="background: rgba(17, 24, 39, 0.7); border: 1px solid rgba(0, 242, 254, 0.2); border-radius: 8px; padding: 12px; margin-top: 15px; font-family: monospace; font-size: 0.85rem;">
                <span style="color: #64748b;">FORMAT:</span> <span style="color: #38bdf8;">Structured Forensic XML</span><br>
                <span style="color: #64748b;">SIZE:</span> <span style="color: #f1f5f9;">{len(xml_text)/1024:.2f} KB</span><br>
                <span style="color: #64748b;">STATUS:</span> <span style="color: #00ff87;">WELL-FORMED XML EXPORT</span>
            </div>
            """, unsafe_allow_html=True)

        with c2:
            st.code(xml_text[:2500] + "\n\n<!-- [Truncated preview: download full file using button on the left] -->", language="xml")

# ----------------- TAB 4: THREATS & INTRUSIONS ----------------- #
with tab_threats:
    st.subheader("Incident Detection & Threat Intelligence (Module 7)")
    st.caption("Rule-based heuristic engine analyzing protocol anomalies, port distributions, and payload exploits.")

    if alerts:
        st.markdown(f'<div style="color: #ef4444; font-weight: 700; font-size: 1.1rem; margin-bottom: 15px;">⚠️ {len(alerts)} ACTIVE THREAT ANOMALIES IDENTIFIED</div>', unsafe_allow_html=True)
        for idx, alert in enumerate(alerts, start=1):
            severity = alert.get("Severity", "Info")
            is_high = "High" in severity
            card_class = "alert-card-red" if is_high else "alert-card-amber"

            st.markdown(f"""
            <div class="{card_class}">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-weight: 700; font-size: 1.05rem; color: {'#f87171' if is_high else '#fbbf24'};">
                        #{idx} {alert.get('Attack Type')}
                    </span>
                    <span style="background: {'rgba(239, 68, 68, 0.2)' if is_high else 'rgba(245, 158, 11, 0.2)'}; color: {'#f87171' if is_high else '#fbbf24'}; padding: 3px 10px; border-radius: 9999px; font-size: 0.75rem; font-weight: 700;">
                        {severity}
                    </span>
                </div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: #cbd5e1; margin-bottom: 6px;">
                    <b>ATTACKER:</b> <span style="color: #38bdf8;">{alert.get('Attacker IP')}</span> &nbsp;⟶&nbsp; 
                    <b>TARGET:</b> <span style="color: #f1f5f9;">{alert.get('Target IP')}</span>
                </div>
                <div style="color: #94a3b8; font-size: 0.88rem;">
                    {alert.get('Details')}
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid #10b981; border-radius: 10px; padding: 1.2rem; color: #10b981; font-weight: 600;">
            ✅ Clean Capture: No unauthorized port scans, SYN floods, credential harvesting, or payload injections observed.
        </div>
        """, unsafe_allow_html=True)

# ----------------- TAB 5: FORENSIC REPORT ----------------- #
with tab_report:
    st.subheader("Official Digital Forensic Audit Report")
    st.caption("Standardized investigation report formatted under NIST SP 800-86 guidelines.")

    proto_counts = df_packets["protocol"].value_counts().to_dict() if not df_packets.empty else {}
    
    # Retrieve top talkers and bidirectional flows for in-depth report analytics
    try:
        top_talkers_df = db.get_top_talkers(limit=6)
        top_talkers_list = top_talkers_df.to_dict(orient="records") if not top_talkers_df.empty else []
    except Exception:
        top_talkers_list = []

    try:
        flows_summary_df = db.execute_custom_sql("""
            SELECT host_a, host_b, protocol, packet_count, a_to_b_pkts, b_to_a_pkts, total_bytes 
            FROM network_flows 
            ORDER BY packet_count DESC LIMIT 10
        """)
        flows_summary_list = flows_summary_df.to_dict(orient="records") if not flows_summary_df.empty else []
    except Exception:
        flows_summary_list = []

    rep_gen = ReportGenerator(
        filename=meta["filename"],
        sha256_hash=meta["sha256"],
        filesize=meta["filesize"],
        total_packets=meta["total_packets"],
        engine=meta["engine"]
    )
    try:
        md_report = rep_gen.generate_markdown(alerts, proto_counts, top_talkers=top_talkers_list, flows_summary=flows_summary_list)
        html_report = rep_gen.generate_html(alerts, proto_counts, top_talkers=top_talkers_list, flows_summary=flows_summary_list)
    except TypeError:
        importlib.reload(modules.report_generator)
        from modules.report_generator import ReportGenerator as RG_Fresh
        rep_gen_fresh = RG_Fresh(
            filename=meta["filename"],
            sha256_hash=meta["sha256"],
            filesize=meta["filesize"],
            total_packets=meta["total_packets"],
            engine=meta["engine"]
        )
        md_report = rep_gen_fresh.generate_markdown(alerts, proto_counts, top_talkers=top_talkers_list, flows_summary=flows_summary_list)
        html_report = rep_gen_fresh.generate_html(alerts, proto_counts, top_talkers=top_talkers_list, flows_summary=flows_summary_list)

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        st.download_button(
            label="📑 Download Markdown Report (.md)",
            data=md_report,
            file_name=f"Forensic_Report_{meta['filename']}.md",
            mime="text/markdown",
            type="primary",
            use_container_width=True
        )
    with col_btn2:
        st.download_button(
            label="🌐 Download Printable HTML Report (.html)",
            data=html_report,
            file_name=f"Forensic_Report_{meta['filename']}.html",
            mime="text/html",
            use_container_width=True
        )

    st.divider()
    # Embed the actual rendered HTML inside an iframe for realistic, formatted presentation
    st.components.v1.html(html_report, height=850, scrolling=True)
