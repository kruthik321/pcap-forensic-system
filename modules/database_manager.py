"""
Database Manager Module (Module 4: PCAP to SQLite)
Automated PCAP Forensic Analysis and Reporting System
Provides normalized relational storage, bidirectional flow aggregation, and read-only query enforcement.
"""

import os
import re
import sqlite3
import pandas as pd
from typing import List, Dict, Any, Optional

class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_database(self) -> None:
        """Initializes forensic database tables and indexes."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            
            # Evidence Metadata Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS evidence_meta (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    filesize_bytes INTEGER,
                    total_packets INTEGER,
                    analyzed_at TEXT NOT NULL
                )
            """)

            # Packets Table (Granular packet dissections)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    packet_num INTEGER,
                    timestamp TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    length INTEGER,
                    tcp_flags TEXT,
                    payload_preview TEXT,
                    info TEXT
                )
            """)

            # Indexes for ultra-fast forensic queries and timeline reconstruction
            cur.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON packets (src_ip)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_dst_ip ON packets (dst_ip)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_protocol ON packets (protocol)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON packets (timestamp)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_dst_port ON packets (dst_port)")

            # Check for legacy schema migration
            cur.execute("PRAGMA table_info(network_flows)")
            cols = [row[1] for row in cur.fetchall()]
            if cols and "host_a" not in cols:
                cur.execute("DROP TABLE network_flows")

            # Network Flows Table (True Bidirectional Session Aggregation)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS network_flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_a TEXT,
                    host_b TEXT,
                    protocol TEXT,
                    packet_count INTEGER,
                    total_bytes INTEGER,
                    a_to_b_pkts INTEGER,
                    b_to_a_pkts INTEGER,
                    first_seen TEXT,
                    last_seen TEXT
                )
            """)

            # Security Alerts Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    severity TEXT,
                    attack_type TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    details TEXT,
                    packet_ref INTEGER
                )
            """)
            conn.commit()

    def clear_existing_data(self) -> None:
        """Cleans working tables prior to ingesting a new evidence session and ensures fresh schema."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("DROP TABLE IF EXISTS packets")
            cur.execute("DROP TABLE IF EXISTS network_flows")
            cur.execute("DROP TABLE IF EXISTS security_alerts")
            cur.execute("DROP TABLE IF EXISTS evidence_meta")
            conn.commit()
        self.init_database()

    def insert_evidence_meta(self, filename: str, sha256: str, filesize: int, total_packets: int, timestamp: str):
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO evidence_meta (filename, sha256, filesize_bytes, total_packets, analyzed_at)
                VALUES (?, ?, ?, ?, ?)
            """, (filename, sha256, filesize, total_packets, timestamp))
            conn.commit()

    def insert_packets_batch(self, packets: List[Dict[str, Any]]) -> None:
        """Batch inserts packet records for high performance."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            query = """
                INSERT INTO packets (
                    packet_num, timestamp, src_ip, dst_ip, protocol,
                    src_port, dst_port, length, tcp_flags, payload_preview, info
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            rows = [
                (
                    p.get("packet_num"),
                    p.get("timestamp"),
                    p.get("src_ip", "N/A"),
                    p.get("dst_ip", "N/A"),
                    p.get("protocol", "UNKNOWN"),
                    p.get("src_port", 0),
                    p.get("dst_port", 0),
                    p.get("length", 0),
                    p.get("tcp_flags", ""),
                    p.get("payload_preview", ""),
                    p.get("info", "")
                )
                for p in packets
            ]
            cur.executemany(query, rows)
            conn.commit()

    def populate_network_flows(self) -> None:
        """
        Aggregates packet records into true bidirectional communication flows
        by canonicalizing the endpoint pair (host_a = MIN, host_b = MAX)
        and tracking directional counts in both directions.
        """
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM network_flows")
            cur.execute("""
                INSERT INTO network_flows (
                    host_a, host_b, protocol, packet_count, total_bytes, 
                    a_to_b_pkts, b_to_a_pkts, first_seen, last_seen
                )
                SELECT 
                    CASE WHEN src_ip <= dst_ip THEN src_ip ELSE dst_ip END AS host_a,
                    CASE WHEN src_ip <= dst_ip THEN dst_ip ELSE src_ip END AS host_b,
                    protocol,
                    COUNT(*) AS packet_count,
                    SUM(length) AS total_bytes,
                    SUM(CASE WHEN src_ip <= dst_ip THEN 1 ELSE 0 END) AS a_to_b_pkts,
                    SUM(CASE WHEN src_ip > dst_ip THEN 1 ELSE 0 END) AS b_to_a_pkts,
                    MIN(timestamp) AS first_seen,
                    MAX(timestamp) AS last_seen
                FROM packets
                WHERE src_ip != 'N/A' AND dst_ip != 'N/A'
                GROUP BY host_a, host_b, protocol
            """)
            conn.commit()

    def insert_alert(self, severity: str, attack_type: str, src_ip: str, dst_ip: str, details: str, timestamp: str, packet_ref: Optional[int] = None):
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO security_alerts (timestamp, severity, attack_type, src_ip, dst_ip, details, packet_ref)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, severity, attack_type, src_ip, dst_ip, details, packet_ref))
            conn.commit()

    def get_packets_df(self, limit: int = 1000) -> pd.DataFrame:
        with self.get_connection() as conn:
            return pd.read_sql_query(f"SELECT * FROM packets LIMIT {limit}", conn)

    def execute_custom_sql(self, query: str) -> pd.DataFrame:
        """
        Executes read-only SQL queries to prevent tampering with forensic evidence.
        Enforces read-only statements via keyword rejection AND driver-level URI mode.
        """
        clean_q = query.strip()
        if not clean_q:
            return pd.DataFrame()

        # Reject any data manipulation or schema modification statements
        disallowed = ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "CREATE", "TRUNCATE", "REPLACE", "ATTACH", "DETACH"]
        first_word = clean_q.split()[0].upper()
        if first_word not in ["SELECT", "EXPLAIN", "WITH", "PRAGMA"]:
            raise ValueError(f"Forensic Read-Only Violation: Statement type '{first_word}' is prohibited. Evidence database is locked to preserve integrity.")

        for bad_word in disallowed:
            if re.search(rf"\b{bad_word}\b", clean_q, re.IGNORECASE):
                raise ValueError(f"Forensic Integrity Violation: Modification keyword '{bad_word}' is strictly prohibited in the forensic explorer.")

        # Enforce read-only at the SQLite driver connection level
        abs_path = os.path.abspath(self.db_path).replace("\\", "/")
        uri_path = f"file:{abs_path}?mode=ro"
        with sqlite3.connect(uri_path, uri=True) as ro_conn:
            return pd.read_sql_query(clean_q, ro_conn)

    def get_protocol_distribution(self) -> pd.DataFrame:
        with self.get_connection() as conn:
            return pd.read_sql_query("""
                SELECT protocol, COUNT(*) as count, SUM(length) as total_bytes
                FROM packets 
                GROUP BY protocol 
                ORDER BY count DESC
            """, conn)

    def get_top_talkers(self, limit: int = 5) -> pd.DataFrame:
        with self.get_connection() as conn:
            return pd.read_sql_query(f"""
                SELECT src_ip, COUNT(*) as packets_sent, SUM(length) as bytes_sent
                FROM packets
                WHERE src_ip != 'N/A'
                GROUP BY src_ip
                ORDER BY packets_sent DESC
                LIMIT {limit}
            """, conn)

    def get_alerts_df(self) -> pd.DataFrame:
        with self.get_connection() as conn:
            return pd.read_sql_query("SELECT * FROM security_alerts ORDER BY id ASC", conn)
