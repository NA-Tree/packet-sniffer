#!/usr/bin/env python3
"""
sniff_analyze.py - Packet Sniffer with Analysis (Wireshark-Lite)
Features:
 - Live capture with BPF or Python lfilter
 - Start/Stop capture interactively via command prompt thread
 - Summary stats: protocol counts, top IPs, top TCP flows
 - Simple HTTP detection
 - Save to pcap
 - Request packet details by index
Usage:
  sudo python3 sniff_analyze.py               # interactive prompts
  sudo python3 sniff_analyze.py --count 200 --bpf "tcp port 80" --out capture.pcap
Interactive commands while program is running:
  start         - start/resume capture
  stop          - stop/pause capture
  status        - print current counters
  save file.pcap- save captured packets to pcap
  detail N      - show detailed parsed fields for packet index N (0-based)
  quit          - stop and exit
"""

import argparse
import signal
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime

from scapy.all import sniff, wrpcap, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet
from tqdm import tqdm

# ----------------------
# CLI and main
# ----------------------
def interactive_prompts():
    iface = input("Interface (blank for default): ").strip() or None
    bpf = input("BPF filter (leave blank to use simple filters): ").strip() or None
    proto = src = dst = sport = dport = None
    if not bpf:
        proto = input("Proto (tcp/udp/ip) or blank: ").strip() or None
        src = input("Source IP or blank: ").strip() or None
        dst = input("Dest IP or blank: ").strip() or None
        sport = input("Source port or blank: ").strip() or None
        dport = input("Dest port or blank: ").strip() or None
    out = input("Save to pcap filename (leave blank to skip): ").strip() or None
    liveFeed = input("live feed? (blank for no): ").strip() or None
    return iface, bpf, proto, src, dst, sport, dport, out, liveFeed

# ----------------------
# Filters
# ----------------------
def build_lfilter(proto=None, src=None, dst=None, sport=None, dport=None):
    proto = proto.lower() if proto else None
    def lfilter(pkt):
        try:
            if IP not in pkt:
                # if user asked for non-IP filters, drop non-IP
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
            if sport:
                try:
                    s = int(sport)
                except:
                    return False
                if TCP in pkt and pkt[TCP].sport != s:
                    return False
                if UDP in pkt and pkt[UDP].sport != s:
                    return False
            if dport:
                try:
                    d = int(dport)
                except:
                    return False
                if TCP in pkt and pkt[TCP].dport != d:
                    return False
                if UDP in pkt and pkt[UDP].dport != d:
                    return False
            return True
        except Exception:
            return False
    return lfilter

# ----------------------
# Analyzer
# ----------------------
class Analyzer:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.proto_counts = Counter()
        self.src_counts = Counter()
        self.dst_counts = Counter()
        self.tcp_flows = defaultdict(lambda: {'pkts':0,'bytes':0})
        self.http_candidates = []   # tuples (iso-ts, src, dst, summary)
        self.packets = []           # store scapy packets for details / pcap
    def feed(self, pkt: Packet, liveFeed=None):
        with self.lock:
            self.total += 1
            # store full packet
            self.packets.append(pkt)


            if(liveFeed is not None and liveFeed != "no"):
                #output the packets with their number
                print(f"\n{len(self.packets)}", pkt)

            # if IP
            if IP in pkt:
                ip = pkt[IP]
                self.src_counts[ip.src] += 1
                self.dst_counts[ip.dst] += 1
                if TCP in pkt:
                    self.proto_counts['TCP'] += 1
                    tcp = pkt[TCP]
                    key = (ip.src, tcp.sport, ip.dst, tcp.dport)
                    self.tcp_flows[key]['pkts'] += 1
                    self.tcp_flows[key]['bytes'] += len(pkt)
                    if Raw in pkt:
                        payload = bytes(pkt[Raw].load)
                        http_s = extract_http_from_payload(payload)
                        if http_s:
                            self.http_candidates.append((datetime.fromtimestamp(pkt.time).isoformat(), ip.src, ip.dst, http_s))
                elif UDP in pkt:
                    self.proto_counts['UDP'] += 1
                elif ICMP in pkt:
                    self.proto_counts['ICMP'] += 1
                else:
                    self.proto_counts[f"IP_PROTO_{ip.proto}"] += 1
            else:
                self.proto_counts['NON_IP'] += 1
    def snapshot(self):
        with self.lock:
            return {
                'total': self.total,
                'proto_counts': self.proto_counts.most_common(),
                'top_src': self.src_counts.most_common(8),
                'top_dst': self.dst_counts.most_common(8),
                'top_flows': sorted(self.tcp_flows.items(), key=lambda kv: kv[1]['pkts'], reverse=True)[:10],
                'http_candidates': list(self.http_candidates)[:10],
                'stored_packets': list(self.packets)  # shallow copy
            }
    def report(self):
        snap = self.snapshot()
        print("\n=== Capture Summary ===")
        print(f"Total packets: {snap['total']}")
        print("\nTop protocols:")
        for proto, cnt in snap['proto_counts']:
            print(f"  {proto:12s} : {cnt}")
        print("\nTop source IPs:")
        for ip,c in snap['top_src']:
            print(f"  {ip:16s} : {c}")
        print("\nTop destination IPs:")
        for ip,c in snap['top_dst']:
            print(f"  {ip:16s} : {c}")
        print("\nTop TCP flows:")
        for (s,sport,d,dport), stats in snap['top_flows']:
            print(f"  {s}:{sport} -> {d}:{dport}  pkts={stats['pkts']}  bytes={pretty_bytes(stats['bytes'])}")
        if snap['http_candidates']:
            print("\nHTTP-like payloads (sample):")
            for ts,src,dst,sc in snap['http_candidates']:
                print(f"  {ts} {src} -> {dst}  {sc}")

# ----------------------
# Sniffer Controller
# ----------------------
class SnifferController:
    def __init__(self, iface=None, bpf=None, proto=None, src=None, dst=None, sport=None, dport=None, liveFeed=None):
        self.iface = iface
        self.bpf = bpf
        self.lfilter = None if bpf else build_lfilter(proto, src, dst, sport, dport)
        self.analyzer = Analyzer()
        self._run_flag = threading.Event()  # if set -> capture running
        self._stop_event = threading.Event() # when set -> request exit of loop
        self._sniff_thread = None
        self._pbar = None
        self.liveFeed = liveFeed
    def _process(self, pkt):
        # called for each packet by sniff
        self.analyzer.feed(pkt, liveFeed=self.liveFeed)
        if self._pbar is not None:
            self._pbar.update(1)
        # periodically print a live summary
        if self.analyzer.total % 50 == 0:
            most = self.analyzer.proto_counts.most_common(1)
            if most:
                top_proto, top_cnt = most[0]
                print(f"\n[Live] pkts={self.analyzer.total} top_proto={top_proto} ({top_cnt})\n")
    def _sniff_loop(self):
        try:
            # create progress bar when running
            self._pbar = tqdm(desc="Capturing (type 'stop' to pause, 'quit' to exit)", unit="pkt")
            while not self._stop_event.is_set():
                if not self._run_flag.is_set():
                    time.sleep(0.2)
                    continue
                # call sniff with a short timeout so we can respond to start/stop quickly
                sniff_kwargs = {
                    'prn': self._process,
                    'store': False,
                    'timeout': 1.0,   # 1 second chunks
                }
                if self.iface:
                    sniff_kwargs['iface'] = self.iface
                if self.bpf:
                    sniff_kwargs['filter'] = self.bpf
                else:
                    sniff_kwargs['lfilter'] = self.lfilter
                try:
                    sniff(**sniff_kwargs)
                except Exception as e:
                    print(f"\n[sniff error] {e}")
                    time.sleep(0.5)
        finally:
            if self._pbar is not None:
                self._pbar.close()
                self._pbar = None
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
        # ensure capture stops
        self._run_flag.clear()
        if self._sniff_thread:
            self._sniff_thread.join(timeout=2)
    def save_pcap(self, filename):
        try:
            with self.analyzer.lock:
                if not self.analyzer.packets:
                    print("No packets to save.")
                    return False
                wrpcap(filename, self.analyzer.packets)
            print(f"Saved {len(self.analyzer.packets)} packets to {filename}")
            return True
        except Exception as e:
            print(f"Failed to save pcap: {e}")
            return False
    def show_status(self):
        self.analyzer.report()
    def show_detail(self, idx):
        with self.analyzer.lock:
            if idx < 0 or idx >= len(self.analyzer.packets):
                print(f"Invalid index {idx}; stored packets count = {len(self.analyzer.packets)}")
                return
            pkt = self.analyzer.packets[idx]

        # print a parsed breakdown
        print("\n=== Packet Detail ===\n")
        if IP in pkt:
            ip = pkt[IP]
            print(f"IP: version={ip.version} ihl={ip.ihl} tos={ip.tos} len={ip.len} id={ip.id} ttl={ip.ttl} proto={ip.proto}")
            print(f" src={ip.src} dst={ip.dst}")
            if TCP in pkt:
                t = pkt[TCP]
                print(f"TCP: sport={t.sport} dport={t.dport} seq={t.seq} ack={t.ack} flags={t.flags} win={t.window}")
                if Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                    summary = extract_http_from_payload(payload)
                    if summary:
                        print(f"Payload (http-like first-line): {summary}")
                    else:
                        print(f"Payload length: {len(payload)} bytes (non-HTTP / binary or truncated)")
            elif UDP in pkt:
                u = pkt[UDP]
                print(f"UDP: sport={u.sport} dport={u.dport} len={u.len}")
                if Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                    print(f"Payload length: {len(payload)} bytes")
            elif ICMP in pkt:
                ic = pkt[ICMP]
                print(f"ICMP: type={ic.type} code={ic.code} chksum={ic.chksum}")
        else:
            print("Non-IP packet - raw length:", len(pkt))

        print(packet_summary(pkt, idx))
        print("=====================\n")

# ----------------------
# Interactive command thread
# ----------------------
def command_thread_fn(controller: SnifferController):
    print("\nInteractive commands: start | stop | status | save filename.pcap | detail N | quit")
    while True:
        try:
            cmd_line = input("> ").strip()
        except EOFError:
            # likely terminal closed
            break
        if not cmd_line:
            continue
        parts = cmd_line.split()
        cmd = parts[0].lower()
        if cmd == 'start':
            controller.start()
            print("Capture started.")
        elif cmd == 'stop':
            controller.stop()
            print("Capture stopped.")
        elif cmd == 'status':
            controller.show_status()
        elif cmd == 'save':
            if len(parts) < 2:
                print("Usage: save filename.pcap")
                continue
            filename = parts[1]
            controller.save_pcap(filename)
        elif cmd == 'detail':
            if len(parts) < 2:
                print("Usage: detail N")
                continue
            try:
                idx = int(parts[1])
            except:
                print("Invalid index")
                continue
            controller.show_detail(idx)
        elif cmd == 'quit':
            print("Quitting...")
            controller.shutdown()
            break
        else:
            print("Unknown command. Valid: start stop status save detail quit")

# ----------------------
# Helper utilities
# ----------------------
def pretty_bytes(n: int) -> str:
    for unit in ['B','KB','MB','GB']:
        if n < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}TB"

def extract_http_from_payload(payload_bytes: bytes):
    try:
        s = payload_bytes.decode('utf-8', errors='replace')
    except Exception:
        return None
    if s.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'HTTP/')):
        first_line = s.splitlines()[0]
        return first_line if len(first_line) < 300 else first_line[:300] + '...'
    if 'HTTP/1.' in s or 'Host:' in s and '\r\n' in s:
        fl = s.splitlines()[0] if s.splitlines() else s
        return fl[:300]
    return None

def packet_summary(pkt: Packet, idx: int = None):
    ts = datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S.%f")[:-3]
    length = len(pkt)
    if IP in pkt:
        ip = pkt[IP]
        proto = "IP"
        extra = ""
        if TCP in pkt:
            proto = "TCP"
            extra = f"{pkt[TCP].sport}->{pkt[TCP].dport}"
        elif UDP in pkt:
            proto = "UDP"
            extra = f"{pkt[UDP].sport}->{pkt[UDP].dport}"
        elif ICMP in pkt:
            proto = "ICMP"

        s = f"\n{ts} {ip.src} -> {ip.dst} {proto}/{extra} {length}B\n\n=== PAYLOAD ===\n{pkt[proto].load.decode()}"
    else:
        s = f"{ts} NON-IP {length}B"
    if idx is not None:
        return f"[{idx}] {s}"
    return s


def main():
    #collect arguments from the user
    parser = argparse.ArgumentParser(description="Packet Sniffer with Analysis (Wireshark-Lite)")
    parser.add_argument('--iface', '-i', help='Interface to capture on', default=None)
    parser.add_argument('--bpf', help='BPF/libpcap filter string', default=None)
    parser.add_argument('--proto', help='Filter by proto: tcp/udp/ip (only if --bpf not used)', default=None)
    parser.add_argument('--src', help='Filter by source IP (only if --bpf not used)', default=None)
    parser.add_argument('--dst', help='Filter by dest IP (only if --bpf not used)', default=None)
    parser.add_argument('--sport', help='Filter by source port (only if --bpf not used)', default=None)
    parser.add_argument('--dport', help='Filter by dest port (only if --bpf not used)', default=None)
    parser.add_argument('--out', help='Write capture to pcap file on exit', default=None)
    args = parser.parse_args()

    #if there were arguments provided through the CLI, use them, if not, enter the interactive prompts
    if len(sys.argv) == 1:

        # interactive prompt values if there are no args
        iface, bpf, proto, src, dst, sport, dport, out, liveFeed = interactive_prompts()

    else:

        # CLI arguments if there were any
        iface = args.iface
        bpf = args.bpf
        proto = args.proto
        src = args.src
        dst = args.dst
        sport = args.sport
        dport = args.dport
        out = args.out

    #define your instance of the controller (class)
    controller = SnifferController(iface=iface, bpf=bpf, proto=proto, src=src, dst=dst, sport=sport, dport=dport, liveFeed=liveFeed)

    # start capture thread (it will wait until 'start' command sets the run_flag)
    controller.start_capture_thread()

    # start interactive command thread
    cmd_thread = threading.Thread(target=command_thread_fn, args=(controller,), daemon=True)
    cmd_thread.start()

    # by default start capture immediately
    controller.start()

    print("Capture running. Type 'stop' to pause capture, 'status' to display summary, 'quit' to exit.")

    try:
        # wait for command thread to exit (quit)
        while cmd_thread.is_alive():
            cmd_thread.join(timeout=0.5)
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received. Shutting down.")
        controller.shutdown()

    # on exit, ensure capture thread stops
    controller.shutdown()

    # final report
    print("\nFinal report:")
    controller.show_status()

    # save if requested on CLI
    if out:
        controller.save_pcap(out)

    exit()

if __name__ == '__main__':
    main()
