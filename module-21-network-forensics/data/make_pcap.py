#!/usr/bin/env python3
"""make_pcap.py -- craft a small BENIGN teaching capture with Scapy (no live
interface / Npcap needed). Produces DNS + an HTTP GET/200 to example.com (an
IANA-reserved test domain, no real service) plus one DGA-style NXDOMAIN lookup
so the network module has something benign-but-suspicious to hunt.

Usage:  python3 make_pcap.py capture.pcap
"""
import sys
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap

def build():
    C, S, DNS_S = "10.0.0.50", "93.184.216.34", "10.0.0.1"
    p = []
    # benign DNS query + response for example.com
    p.append(Ether()/IP(src=C, dst=DNS_S)/UDP(sport=51000, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com")))
    p.append(Ether()/IP(src=DNS_S, dst=C)/UDP(sport=53, dport=51000)/DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata=S)))
    # TCP handshake + HTTP GET / 200 OK to example.com
    p.append(Ether()/IP(src=C, dst=S)/TCP(sport=52000, dport=80, flags="S", seq=1000))
    p.append(Ether()/IP(src=S, dst=C)/TCP(sport=80, dport=52000, flags="SA", seq=5000, ack=1001))
    p.append(Ether()/IP(src=C, dst=S)/TCP(sport=52000, dport=80, flags="A", seq=1001, ack=5001))
    p.append(Ether()/IP(src=C, dst=S)/TCP(sport=52000, dport=80, flags="PA", seq=1001, ack=5001)/Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n"))
    p.append(Ether()/IP(src=S, dst=C)/TCP(sport=80, dport=52000, flags="PA", seq=5001, ack=1078)/Raw(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 12\r\n\r\nHello World!"))
    # a suspicious-looking-but-benign DGA-style DNS lookup (resolves NXDOMAIN)
    p.append(Ether()/IP(src=C, dst=DNS_S)/UDP(sport=51001, dport=53)/DNS(rd=1, qd=DNSQR(qname="kq3v9x7zpl2m8w.example.org")))
    return p

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"
    pkts = build()
    wrpcap(out, pkts)
    print("wrote %d packets -> %s" % (len(pkts), out))
