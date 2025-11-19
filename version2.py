#!/usr/bin/env python3
"""
sniff_analyze.py - Packet Sniffer with Analysis (Wireshark-Lite)

Features:
 - Live capture with optional BPF/lfilter
 - Interactive start/stop/status/detail/save/quit
 - DNS + SMTP + HTTP + TCP/UDP/ICMP analysis
 - Live feed output and pcap save support

Usage:
  sudo python3 sniff_analyze.py
  sudo python3 sniff_analyze.py --count 200 --bpf "tcp port 80" --out capture.pcap

Interactive commands:
  start, stop, status, detail N, save filename.pcap, quit
"""

import argparse
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime

from scapy.all import sniff, wrpcap, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS
from tqdm import tqdm


# ---------------------- Interactive Prompts ----------------------
def interactive_prompts():
    iface = input("Interface (blank for default): ").strip() or None
    bpf = input("BPF filter (leave blank to use simple filters): ").strip() or None
    proto = src = dst = sport = dport = None
    if not bpf:
        proto = input("Proto (tcp/udp/ip/dns) or blank: ").strip() or None
        src = input("Source IP or blank: ").strip() or None
        dst = input("Dest IP or blank: ").strip() or None
        sport = input("Source port or blank: ").strip() or None
        dport = input("Dest port or blank: ").strip() or None
    out = input("Save to pcap filename (leave blank to skip): ").strip() or None
    liveFeed = input("Live feed? (blank for no): ").strip() or None
    return iface, bpf, proto, src, dst, sport, dport, out, liveFeed


# ---------------------- Filters ----------------------
def build_lfilter(proto=None, src=None, dst=None, sport=None, dport=None):
    proto = proto.lower() if proto else None

    def lfilter(pkt):
        try:
            if IP not in pkt:
                if proto or src or dst or sport or dport:
                    return False
                return True
            ip = pkt[IP]
            if src and ip.src != src:
                return False
            if dst and ip.dst != dst:
                return False
            if proto:
                if proto == 'tcp' and TCP not in pkt:
                    return False
                if proto == 'udp' and UDP not in pkt:
                    return False
                if proto == 'ip' and IP not in pkt:
                    return False
                if proto == 'dns' and DNS not in pkt:
                    return False
                if proto == 'http' and HTTP not in pkt:
                    return False
            if sport:
                s = int(sport)
                if TCP in pkt and pkt[TCP].sport != s:
                    return False
                if UDP in pkt and pkt[UDP].sport != s:
                    return False
            if dport:
                d = int(dport)
                if TCP in pkt or UDP in pkt:
                    if TCP in pkt and pkt[TCP].dport == d:
                        return True
                    elif UDP in pkt and pkt[UDP].dport == d:
                        return True
                    else:
                        return False
                else:
                    return False
            return True
        except Exception:
            return False

    return lfilter


# ---------------------- Output Helpers ----------------------
def isHTTP(pkt):
    if TCP in pkt:
        try:
            raw = bytes(pkt[TCP].payload).decode(errors="ignore")
            return raw.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "HTTP/"))
        except Exception:
            return False
    return False


def liveOutput(number=0, pkt=None):
    if IP in pkt:
        ip = pkt[IP]
        proto = "IP"
        extra = ""
        if isHTTP(pkt):
            proto = "HTTP"
        elif TCP in pkt:
            proto = "TCP"
            extra = f"{pkt[TCP].sport}->{pkt[TCP].dport}"
        elif DNS in pkt:
            proto = "DNS"
            extra = f"{pkt[UDP].sport}->{pkt[UDP].dport}"
        elif UDP in pkt:
            proto = "UDP"
            extra = f"{pkt[UDP].sport}->{pkt[UDP].dport}"
        elif ICMP in pkt:
            proto = "ICMP"
        elif pkt.haslayer(DNS):
            proto = "DNS"
        else:
            proto = "OTHER"
        s = f"\n[{number}] {ip.src} -> {ip.dst}\t({proto}) {extra}"
    else:
        s = f"\n[{number}] (Non-IP Packet)"
    return s


# ---------------------- Analyzer ----------------------
class Analyzer:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.proto_counts = Counter()
        self.src_counts = Counter()
        self.dst_counts = Counter()
        self.tcp_flows = defaultdict(lambda: {'pkts': 0, 'bytes': 0})
        self.http_candidates = []
        self.packets = []

    def feed(self, pkt, liveFeed=None):
        with self.lock:
            self.total += 1
            self.packets.append(pkt)

            if liveFeed and liveFeed.lower() != "no":
                print(liveOutput(len(self.packets), pkt))

            if IP in pkt:
                ip = pkt[IP]
                self.src_counts[ip.src] += 1
                self.dst_counts[ip.dst] += 1

                if pkt.haslayer(DNS):
                    self.proto_counts["DNS"] += 1
                elif isHTTP(pkt):
                    self.proto_counts["HTTP"] += 1
                elif TCP in pkt and (pkt[TCP].sport == 25 or pkt[TCP].dport == 25):
                    self.proto_counts["SMTP"] += 1
                elif TCP in pkt:
                    self.proto_counts["TCP"] += 1
                    tcp = pkt[TCP]
                    key = (ip.src, tcp.sport, ip.dst, tcp.dport)
                    self.tcp_flows[key]["pkts"] += 1
                    self.tcp_flows[key]["bytes"] += len(pkt)
                elif DNS in pkt:
                    self.proto_counts['DNS'] += 1
                elif UDP in pkt:
                    self.proto_counts["UDP"] += 1
                elif ICMP in pkt:
                    self.proto_counts["ICMP"] += 1
                else:
                    self.proto_counts[f"IP_PROTO_{ip.proto}"] += 1
            else:
                self.proto_counts["NON_IP"] += 1

    def snapshot(self):
        with self.lock:
            return {
                "total": self.total,
                "proto_counts": self.proto_counts.most_common(),
                "top_src": self.src_counts.most_common(8),
                "top_dst": self.dst_counts.most_common(8),
                "top_flows": sorted(self.tcp_flows.items(), key=lambda kv: kv[1]['pkts'], reverse=True)[:10],
                "stored_packets": list(self.packets),
            }

    def report(self):
        snap = self.snapshot()
        print("\n=== Capture Summary ===")
        print(f"Total packets: {snap['total']}")
        print("\nTop protocols:")
        for proto, cnt in snap['proto_counts']:
            print(f"  {proto:12s} : {cnt}")
        print("\nTop source IPs:")
        for ip, c in snap['top_src']:
            print(f"  {ip:16s} : {c}")
        print("\nTop destination IPs:")
        for ip, c in snap['top_dst']:
            print(f"  {ip:16s} : {c}")
        print("\nTop TCP flows:")
        for (s, sport, d, dport), stats in snap['top_flows']:
            print(f"  {s}:{sport} -> {d}:{dport} pkts={stats['pkts']} bytes={pretty_bytes(stats['bytes'])}")


# ---------------------- Sniffer Controller ----------------------
class SnifferController:
    def __init__(self, iface=None, bpf=None, proto=None, src=None, dst=None, sport=None, dport=None, liveFeed=None):
        self.iface = iface
        self.bpf = bpf
        self.lfilter = None if bpf else build_lfilter(proto, src, dst, sport, dport)
        self.analyzer = Analyzer()
        self._run_flag = threading.Event()
        self._stop_event = threading.Event()
        self._sniff_thread = None
        self._pbar = None
        self.liveFeed = liveFeed

    def _process(self, pkt):
        self.analyzer.feed(pkt, liveFeed=self.liveFeed)
        if self._pbar is not None:
            self._pbar.update(1)

    def _sniff_loop(self):
        try:
            self._pbar = tqdm(
                desc="Capturing (type 'stop' to pause, 'quit' to exit)",
                unit="pkt",
                disable=True  # disables visual progress bar
            )
            while not self._stop_event.is_set():
                if not self._run_flag.is_set():
                    time.sleep(0.2)
                    continue
                sniff_kwargs = dict(prn=self._process, store=False, timeout=1.0)
                if self.iface:
                    sniff_kwargs['iface'] = self.iface
                if self.bpf:
                    sniff_kwargs['filter'] = self.bpf
                else:
                    sniff_kwargs['lfilter'] = self.lfilter
                try:
                    sniff(**sniff_kwargs)
                except Exception as e:
                    print(f"[sniff error] {e}")
                    time.sleep(0.5)
        finally:
            if self._pbar is not None:
                self._pbar.close()

    def start_capture_thread(self):
        if self._sniff_thread and self._sniff_thread.is_alive():
            return
        self._stop_event.clear()
        self._sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._sniff_thread.start()

    def start(self):
        self._run_flag.set()

    def stop(self):
        self._run_flag.clear()

    def shutdown(self):
        self._stop_event.set()
        self._run_flag.clear()
        if self._sniff_thread:
            self._sniff_thread.join(timeout=2)

    def save_pcap(self, filename):
        with self.analyzer.lock:
            if not self.analyzer.packets:
                print("No packets to save.")
                return
            wrpcap(filename, self.analyzer.packets)
        print(f"Saved {len(self.analyzer.packets)} packets to {filename}")

    def show_status(self):
        self.analyzer.report()

    def show_detail(self, idx):
        with self.analyzer.lock:
            if idx < 0 or idx >= len(self.analyzer.packets):
                print(f"Invalid index {idx}; total = {len(self.analyzer.packets)}")
                return
            pkt = self.analyzer.packets[idx]

        print(f"\n=== Packet Detail [{idx}] ===")
        print(packet_summary(pkt))
        print("=============================\n")


# ---------------------- Command Thread ----------------------
def command_thread_fn(controller):
    print("\nCommands: start | stop | status | save <file> | detail <N> | quit")
    while True:
        cmd = input("> ").strip().split()
        if not cmd:
            continue
        c = cmd[0].lower()
        if c == 'start':
            controller.start()
            print("Capture started.")
        elif c == 'stop':
            controller.stop()
            print("Capture stopped.")
        elif c == 'status':
            controller.show_status()
        elif c == 'save':
            if len(cmd) < 2:
                print("Usage: save file.pcap")
                continue
            controller.save_pcap(cmd[1])
        elif c == 'detail':
            if len(cmd) < 2:
                print("Usage: detail N")
                continue
            controller.show_detail(int(cmd[1]))
        elif c == 'quit':
            print("Exiting...")
            controller.shutdown()
            break
        else:
            print("Unknown command.")


# ---------------------- Utilities ----------------------
def pretty_bytes(n):
    for u in ['B', 'KB', 'MB', 'GB']:
        if n < 1024:
            return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}TB"


def packet_summary(pkt):
    ts = datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S.%f")[:-3]
    length = len(pkt)
    lines = [f"Timestamp: {ts}", f"Length: {length} bytes"]

    if IP in pkt:
        ip = pkt[IP]
        lines.append(f"IP {ip.src} -> {ip.dst}")
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            lines.append(f"DNS id={dns.id} qdcount={dns.qdcount} ancount={dns.ancount}")
            if dns.qd:
                lines.append(f" Query: {dns.qd.qname.decode(errors='ignore')}")
        elif TCP in pkt and (pkt[TCP].sport == 25 or pkt[TCP].dport == 25):
            lines.append("SMTP packet detected.")
        elif isHTTP(pkt):
            lines.append("HTTP packet detected.")
        elif TCP in pkt:
            t = pkt[TCP]
            lines.append(f"TCP sport={t.sport} dport={t.dport} seq={t.seq} ack={t.ack}")
        elif UDP in pkt:
            u = pkt[UDP]
            lines.append(f"UDP sport={u.sport} dport={u.dport}")
        elif ICMP in pkt:
            ic = pkt[ICMP]
            lines.append(f"ICMP type={ic.type} code={ic.code}")
    else:
        lines.append("Non-IP packet")

    return "\n".join(lines)


# ---------------------- Main ----------------------
def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer with Analysis (Wireshark-Lite)")
    parser.add_argument('--iface', '-i', default=None)
    parser.add_argument('--bpf', default=None)
    parser.add_argument('--proto', default=None)
    parser.add_argument('--src', default=None)
    parser.add_argument('--dst', default=None)
    parser.add_argument('--sport', default=None)
    parser.add_argument('--dport', default=None)
    parser.add_argument('--out', default=None)
    args = parser.parse_args()

    if len(sys.argv) == 1:
        iface, bpf, proto, src, dst, sport, dport, out, liveFeed = interactive_prompts()
    else:
        iface, bpf, proto, src, dst, sport, dport, out = (
            args.iface, args.bpf, args.proto, args.src, args.dst, args.sport, args.dport, args.out
        )
        liveFeed = "yes"

    controller = SnifferController(iface, bpf, proto, src, dst, sport, dport, liveFeed)
    controller.start_capture_thread()
    controller.start()

    cmd_thread = threading.Thread(target=command_thread_fn, args=(controller,), daemon=True)
    cmd_thread.start()

    try:
        while cmd_thread.is_alive():
            cmd_thread.join(timeout=0.5)
    except KeyboardInterrupt:
        print("Interrupted, shutting down.")
        controller.shutdown()

    if out:
        controller.save_pcap(out)


if __name__ == "__main__":
    main()
#C:\Users\harip\Downloads\project.py
#C:\Users\harip\Downloads\project_try.py
