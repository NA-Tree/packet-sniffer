#!/usr/bin/env python3
"""
sniff_analyze_gui_enhanced.py - Complete Feature Parity Packet Sniffer GUI

New features added:
 - Statistics dashboard (protocols, top talkers, TCP flows)
 - Advanced filtering (source/dest IP, ports)
 - Export to CSV and text reports
 - Real-time capture rate monitoring
 - Complete Analyzer class from CLI version

Usage:
  sudo python3 sniff_analyze_gui_enhanced.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime
import csv

from scapy.all import sniff, wrpcap, Raw, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP


# ==================== HELPER FUNCTIONS ====================
def isHTTP(pkt):
    if TCP in pkt:
        try:
            raw = bytes(pkt[TCP].payload).decode(errors="ignore")
            return raw.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "HTTP/"))
        except:
            return False
    return False

def get_protocol(pkt):
    if IP in pkt:
        if isHTTP(pkt): return "HTTP"
        elif DNS in pkt: return "DNS"
        elif TCP in pkt:
            if pkt[TCP].sport == 25 or pkt[TCP].dport == 25: return "TCP (likely SMTP)"
            elif pkt[TCP].sport == 443 or pkt[TCP].dport == 443: return "TCP (likely HTTPS)"
            return "TCP"
        elif UDP in pkt: return "UDP"
        elif ICMP in pkt: return "ICMP"
        else: return f"IP({pkt[IP].proto})"
    elif ARP in pkt: return "ARP"
    else: return "Other"

def get_packet_info(pkt):
    try:
        ts = datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S.%f")[:-3]
        proto = get_protocol(pkt)
        length = len(pkt)
        
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            info = ""
            if TCP in pkt:
                info = f"{pkt[TCP].sport}→{pkt[TCP].dport}"
            elif UDP in pkt:
                info = f"{pkt[UDP].sport}→{pkt[UDP].dport}"
        elif ARP in pkt:
            src, dst = pkt[ARP].psrc, pkt[ARP].pdst
            info = "Req" if pkt[ARP].op == 1 else "Rep"
        else:
            src = dst = "N/A"
            info = "Non-IP"
        return (ts, src, dst, proto, length, info)
    except:
        return (datetime.now().strftime("%H:%M:%S"), "Err", "Err", "Err", 0, "Err")

def pretty_bytes(n):
    for u in ['B', 'KB', 'MB', 'GB']:
        if n < 1024: return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}TB"


# ==================== ANALYZER (FROM CLI) ====================
class Analyzer:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.total_bytes = 0
        self.proto_counts = Counter()
        self.src_counts = Counter()
        self.dst_counts = Counter()
        self.tcp_flows = defaultdict(lambda: {'pkts': 0, 'bytes': 0})
        self.start_time = time.time()
        
    def feed(self, pkt):
        with self.lock:
            self.total += 1
            self.total_bytes += len(pkt)
            if IP in pkt:
                ip = pkt[IP]
                self.src_counts[ip.src] += 1
                self.dst_counts[ip.dst] += 1
                proto = get_protocol(pkt)
                self.proto_counts[proto] += 1
                
                if TCP in pkt:
                    tcp = pkt[TCP]
                    key = (ip.src, tcp.sport, ip.dst, tcp.dport)
                    self.tcp_flows[key]["pkts"] += 1
                    self.tcp_flows[key]["bytes"] += len(pkt)
            elif ARP in pkt:
                self.proto_counts["ARP"] += 1
            else:
                self.proto_counts["NON_IP"] += 1

    def snapshot(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            rate = self.total / elapsed if elapsed > 0 else 0
            return {
                "total": self.total,
                "total_bytes": self.total_bytes,
                "proto_counts": self.proto_counts.most_common(),
                "top_src": self.src_counts.most_common(10),
                "top_dst": self.dst_counts.most_common(10),
                "top_flows": sorted(self.tcp_flows.items(), key=lambda kv: kv[1]['pkts'], reverse=True)[:15],
                "capture_rate": rate
            }


# ==================== CUSTOM FILTER BUILDER ====================
def build_custom_lfilter(proto=None, src=None, dst=None, sport=None, dport=None):
    def lfilter(pkt):
        try:
            if IP not in pkt:
                return not (proto or src or dst or sport or dport)
            
            ip = pkt[IP]
            if src and ip.src != src: return False
            if dst and ip.dst != dst: return False
            
            if proto:
                p = proto.lower()
                if p == 'dns' and DNS not in pkt: return False
                if p == 'http' and not isHTTP(pkt): return False

                # make sure to not get any stray HTTP packets
                if p == 'tcp' and TCP not in pkt: return False
                if p == 'tcp' and TCP in pkt and isHTTP(pkt): 
                    return False

                if p == 'udp' and UDP not in pkt: return False
                if p == 'udp' and UDP in pkt and DNS in pkt: return False


                if p == 'icmp' and ICMP not in pkt: return False
                
            if sport:
                s = int(sport)
                if TCP in pkt and pkt[TCP].sport != s: return False
                if UDP in pkt and pkt[UDP].sport != s: return False
            
            if dport:
                d = int(dport)
                if TCP in pkt and pkt[TCP].dport != d: return False
                if UDP in pkt and pkt[UDP].dport != d: return False
            
            return True
        except:
            return False
    return lfilter


# ==================== PACKET SNIFFER ====================
class PacketSniffer:
    def __init__(self, callback):
        self.callback = callback
        self.packets = []
        self.analyzer = Analyzer()
        self.running = False
        self.thread = None
        self.lock = threading.Lock()
        
    def start(self, iface=None, bpf=None, lfilter=None):
        if self.running: return False
        self.running = True
        self.thread = threading.Thread(target=self._capture, args=(iface, bpf, lfilter), daemon=True)
        self.thread.start()
        return True
    
    def stop(self):
        self.running = False
        if self.thread: self.thread.join(timeout=2)
        return True
    
    def _capture(self, iface, bpf, lfilter):
        while self.running:
            try:
                kwargs = {'prn': self._process, 'store': False, 'timeout': 1, 'count': 10}
                if iface: kwargs['iface'] = iface
                if bpf: kwargs['filter'] = bpf
                if lfilter: kwargs['lfilter'] = lfilter
                sniff(**kwargs)
            except Exception as e:
                print(f"Capture error: {e}")
                time.sleep(0.5)
    
    def _process(self, pkt):
        with self.lock:
            self.packets.append(pkt)
            self.analyzer.feed(pkt)
            self.callback(pkt)
    
    def get_packets(self): 
        with self.lock: return list(self.packets)
    
    def get_packet(self, idx):
        with self.lock:
            return self.packets[idx] if 0 <= idx < len(self.packets) else None
    
    def clear_packets(self):
        with self.lock:
            self.packets.clear()
            self.analyzer = Analyzer()
    
    def get_statistics(self):
        return self.analyzer.snapshot()


# ==================== STATISTICS WINDOW ====================
class StatisticsWindow:
    def __init__(self, parent, sniffer):
        self.win = tk.Toplevel(parent)
        self.win.title("Statistics & Analysis")
        self.win.geometry("850x600")
        self.sniffer = sniffer
        
        nb = ttk.Notebook(self.win)
        nb.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Summary tab
        sum_f = ttk.Frame(nb)
        nb.add(sum_f, text="Summary")
        self.sum_txt = scrolledtext.ScrolledText(sum_f, wrap=tk.WORD, font=('Courier', 9))
        self.sum_txt.pack(fill=tk.BOTH, expand=True)
        
        # Protocols tab
        proto_f = ttk.Frame(nb)
        nb.add(proto_f, text="Protocols")
        self.proto_tree = ttk.Treeview(proto_f, columns=("Proto", "Count", "%"), show='headings')
        for c in ["Proto", "Count", "%"]: self.proto_tree.heading(c, text=c)
        self.proto_tree.pack(fill=tk.BOTH, expand=True)
        
        # Top Talkers tab
        talk_f = ttk.Frame(nb)
        nb.add(talk_f, text="Top Talkers")
        ttk.Label(talk_f, text="Top Sources:", font=('bold',)).pack()
        self.src_tree = ttk.Treeview(talk_f, columns=("#", "IP", "Pkts"), show='headings', height=8)
        for c in ["#", "IP", "Pkts"]: self.src_tree.heading(c, text=c)
        self.src_tree.pack(fill=tk.BOTH, expand=True)
        ttk.Label(talk_f, text="Top Destinations:", font=('bold',)).pack()
        self.dst_tree = ttk.Treeview(talk_f, columns=("#", "IP", "Pkts"), show='headings', height=8)
        for c in ["#", "IP", "Pkts"]: self.dst_tree.heading(c, text=c)
        self.dst_tree.pack(fill=tk.BOTH, expand=True)
        
        # TCP Flows tab
        flow_f = ttk.Frame(nb)
        nb.add(flow_f, text="TCP Flows")
        self.flow_tree = ttk.Treeview(flow_f, columns=("Src", "SP", "Dst", "DP", "Pkts", "Bytes"), show='headings')
        for c in ["Src", "SP", "Dst", "DP", "Pkts", "Bytes"]: self.flow_tree.heading(c, text=c)
        self.flow_tree.pack(fill=tk.BOTH, expand=True)
        
        # Buttons
        btn_f = ttk.Frame(self.win)
        btn_f.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(btn_f, text="🔄 Refresh", command=self.refresh).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_f, text="💾 Export", command=self.export).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_f, text="Close", command=self.win.destroy).pack(side=tk.RIGHT, padx=2)
        
        self.refresh()
    
    def refresh(self):
        s = self.sniffer.get_statistics()
        
        # Summary
        txt = f"\nCAPTURE SUMMARY\n{'='*50}\n"
        txt += f"Total Packets: {s['total']}\n"
        txt += f"Total Bytes:   {pretty_bytes(s['total_bytes'])}\n"
        txt += f"Capture Rate:  {s['capture_rate']:.2f} pkt/s\n\n"
        txt += "Protocol Distribution:\n"
        for proto, cnt in s['proto_counts']:
            pct = (cnt/s['total']*100) if s['total'] else 0
            txt += f"  {proto:10s} {cnt:5d} ({pct:5.1f}%)\n"
        self.sum_txt.delete(1.0, tk.END)
        self.sum_txt.insert(1.0, txt)
        
        # Protocols
        self.proto_tree.delete(*self.proto_tree.get_children())
        for proto, cnt in s['proto_counts']:
            pct = f"{(cnt/s['total']*100):.1f}%" if s['total'] else "0%"
            self.proto_tree.insert('', tk.END, values=(proto, cnt, pct))
        
        # Top Talkers
        self.src_tree.delete(*self.src_tree.get_children())
        for i, (ip, cnt) in enumerate(s['top_src'], 1):
            self.src_tree.insert('', tk.END, values=(i, ip, cnt))
        
        self.dst_tree.delete(*self.dst_tree.get_children())
        for i, (ip, cnt) in enumerate(s['top_dst'], 1):
            self.dst_tree.insert('', tk.END, values=(i, ip, cnt))
        
        # TCP Flows
        self.flow_tree.delete(*self.flow_tree.get_children())
        for (src, sp, dst, dp), fs in s['top_flows']:
            self.flow_tree.insert('', tk.END, values=(src, sp, dst, dp, fs['pkts'], pretty_bytes(fs['bytes'])))
    
    def export(self):
        fn = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if fn:
            s = self.sniffer.get_statistics()
            with open(fn, 'w') as f:
                f.write(f"PACKET ANALYSIS REPORT\n{'='*60}\n")
                f.write(f"Generated: {datetime.now()}\n\n")
                f.write(f"Total: {s['total']} packets, {pretty_bytes(s['total_bytes'])}\n")
                f.write(f"Rate: {s['capture_rate']:.2f} pkt/s\n\n")
                f.write("PROTOCOLS:\n")
                for p, c in s['proto_counts']: f.write(f"  {p}: {c}\n")
                f.write("\nTOP SOURCES:\n")
                for ip, c in s['top_src']: f.write(f"  {ip}: {c}\n")
                f.write("\nTOP DESTINATIONS:\n")
                for ip, c in s['top_dst']: f.write(f"  {ip}: {c}\n")
                f.write("\nTOP TCP FLOWS:\n")
                for (src,sp,dst,dp), fs in s['top_flows']:
                    f.write(f"  {src}:{sp} -> {dst}:{dp} = {fs['pkts']} pkts, {pretty_bytes(fs['bytes'])}\n")
            messagebox.showinfo("Success", f"Report saved to {fn}")


# ==================== ADVANCED FILTER DIALOG ====================
class FilterDialog:
    def __init__(self, parent):
        self.result = None
        self.win = tk.Toplevel(parent)
        self.win.title("Advanced Filters")
        self.win.geometry("400x350")
        self.win.transient(parent)
        self.win.grab_set()
        
        f = ttk.Frame(self.win, padding=10)
        f.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(f, text="Protocol:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.proto = ttk.Combobox(f, values=["", "tcp", "udp", "icmp", "dns", "http"], state="readonly")
        self.proto.grid(row=0, column=1, sticky=tk.EW, pady=5)
        
        ttk.Label(f, text="Source IP:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.src = ttk.Entry(f)
        self.src.grid(row=1, column=1, sticky=tk.EW, pady=5)
        
        ttk.Label(f, text="Dest IP:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.dst = ttk.Entry(f)
        self.dst.grid(row=2, column=1, sticky=tk.EW, pady=5)
        
        ttk.Label(f, text="Source Port:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.sport = ttk.Entry(f)
        self.sport.grid(row=3, column=1, sticky=tk.EW, pady=5)
        
        ttk.Label(f, text="Dest Port:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.dport = ttk.Entry(f)
        self.dport.grid(row=4, column=1, sticky=tk.EW, pady=5)
        
        f.columnconfigure(1, weight=1)
        
        bf = ttk.Frame(self.win)
        bf.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(bf, text="Apply", command=self.apply).pack(side=tk.LEFT, padx=5)
        ttk.Button(bf, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=5)
        ttk.Button(bf, text="Cancel", command=self.win.destroy).pack(side=tk.RIGHT, padx=5)
        
        self.win.wait_window()
    
    def apply(self):
        self.result = {
            'proto': self.proto.get().strip(),
            'src': self.src.get().strip(),
            'dst': self.dst.get().strip(),
            'sport': self.sport.get().strip(),
            'dport': self.dport.get().strip()
        }
        self.win.destroy()
    
    def clear(self):
        self.proto.set('')
        self.src.delete(0, tk.END)
        self.dst.delete(0, tk.END)
        self.sport.delete(0, tk.END)
        self.dport.delete(0, tk.END)


# ==================== MAIN GUI ====================
class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer - Enhanced")
        self.root.geometry("1200x700")
        
        self.sniffer = PacketSniffer(self.on_packet)
        self.pkt_count = 0
        self.custom_filter = None
        
        self.create_widgets()
        self.update_stats_loop()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def create_widgets(self):
        # Top controls
        ctrl = ttk.Frame(self.root, padding=5)
        ctrl.pack(fill=tk.X)
        
        self.start_btn = ttk.Button(ctrl, text="▶ Start", command=self.start, width=10)
        self.start_btn.pack(side=tk.LEFT, padx=2)
        
        self.stop_btn = ttk.Button(ctrl, text="⏸ Stop", command=self.stop, width=10, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=2)
        
        ttk.Separator(ctrl, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        ttk.Button(ctrl, text="💾 Save All", command=self.save_all, width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctrl, text="💾 CSV", command=self.export_csv, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctrl, text="📊 Stats", command=self.show_stats, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctrl, text="🗑 Clear", command=self.clear, width=8).pack(side=tk.LEFT, padx=2)
        
        self.status_lbl = ttk.Label(ctrl, text="Stopped | 0 pkts | 0 B | 0 pkt/s", relief=tk.SUNKEN)
        self.status_lbl.pack(side=tk.RIGHT, padx=5)
        
        # Filter frame
        filt = ttk.Frame(self.root, padding=5)
        filt.pack(fill=tk.X)
        
        ttk.Label(filt, text="Interface:").pack(side=tk.LEFT, padx=2)
        self.iface_ent = ttk.Entry(filt, width=12)
        self.iface_ent.pack(side=tk.LEFT, padx=2)
        
        ttk.Label(filt, text="BPF:").pack(side=tk.LEFT, padx=(10,2))
        self.bpf_ent = ttk.Entry(filt, width=30)
        self.bpf_ent.pack(side=tk.LEFT, padx=2)
        
        ttk.Button(filt, text="⚙ Advanced", command=self.advanced_filter).pack(side=tk.LEFT, padx=5)
        
        # Packet list
        list_f = ttk.Frame(self.root)
        list_f.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        cols = ("No", "Time", "Src", "Dst", "Proto", "Len", "Info")
        self.tree = ttk.Treeview(list_f, columns=cols, show='headings', height=12)
        
        widths = [50, 100, 130, 130, 80, 70, 400]
        for c, w in zip(cols, widths):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w)
        
        vsb = ttk.Scrollbar(list_f, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree.bind('<<TreeviewSelect>>', self.on_select)
        
        # Detail view
        det_f = ttk.Frame(self.root)
        det_f.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(det_f, text="Packet Details:", font=('bold',)).pack(anchor=tk.W)
        self.det_txt = scrolledtext.ScrolledText(det_f, height=12, wrap=tk.WORD, font=('Courier', 9))
        self.det_txt.pack(fill=tk.BOTH, expand=True)
        self.det_txt.insert(1.0, "Select a packet...")
        self.det_txt.config(state=tk.DISABLED)
    
    def start(self):
        iface = self.iface_ent.get().strip() or None
        bpf = self.bpf_ent.get().strip() or None
        lfilter = None
        
        if self.custom_filter and not bpf:
            lfilter = build_custom_lfilter(**self.custom_filter)
        
        if self.sniffer.start(iface, bpf, lfilter):
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.iface_ent.config(state=tk.DISABLED)
            self.bpf_ent.config(state=tk.DISABLED)
    
    def stop(self):
        self.sniffer.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.iface_ent.config(state=tk.NORMAL)
        self.bpf_ent.config(state=tk.NORMAL)
    
    def on_packet(self, pkt):
        self.root.after(0, self._add_pkt, pkt)
    
    def _add_pkt(self, pkt):
        self.pkt_count += 1
        info = get_packet_info(pkt)
        self.tree.insert('', tk.END, values=(self.pkt_count, *info))
        self.tree.yview_moveto(1.0)
    
    def on_select(self, event):
        sel = self.tree.selection()
        if not sel: return
        idx = int(self.tree.item(sel[0])['values'][0]) - 1
        pkt = self.sniffer.get_packet(idx)
        if pkt:
            self.det_txt.config(state=tk.NORMAL)
            self.det_txt.delete(1.0, tk.END)
            self.det_txt.insert(1.0, pkt.show(dump=True))
            self.det_txt.config(state=tk.DISABLED)
    
    def save_all(self):
        pkts = self.sniffer.get_packets()
        if not pkts:
            messagebox.showwarning("No Data", "No packets to save")
            return
        fn = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP", "*.pcap")])
        if fn:
            wrpcap(fn, pkts)
            messagebox.showinfo("Success", f"Saved {len(pkts)} packets")
    
    def export_csv(self):
        pkts = self.sniffer.get_packets()
        if not pkts:
            messagebox.showwarning("No Data", "No packets to export")
            return
        fn = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if fn:
            with open(fn, 'w', newline='') as f:
                w = csv.writer(f)
                w.writerow(["No", "Time", "Src", "Dst", "Proto", "Len", "Info"])
                for i, pkt in enumerate(pkts, 1):
                    w.writerow([i, *get_packet_info(pkt)])
            messagebox.showinfo("Success", f"Exported {len(pkts)} packets to CSV")
    
    def show_stats(self):
        StatisticsWindow(self.root, self.sniffer)
    
    def clear(self):
        if messagebox.askyesno("Clear", "Clear all packets?"):
            self.sniffer.clear_packets()
            self.tree.delete(*self.tree.get_children())
            self.pkt_count = 0
            self.det_txt.config(state=tk.NORMAL)
            self.det_txt.delete(1.0, tk.END)
            self.det_txt.insert(1.0, "Select a packet...")
            self.det_txt.config(state=tk.DISABLED)
    
    def advanced_filter(self):
        dlg = FilterDialog(self.root)
        if dlg.result:
            self.custom_filter = {k: v for k, v in dlg.result.items() if v}
            if self.custom_filter:
                messagebox.showinfo("Filter Set", f"Custom filter applied:\n{self.custom_filter}")
            else:
                self.custom_filter = None
                messagebox.showinfo("Filter Cleared", "All filters removed")
    
    def update_stats_loop(self):
        if self.sniffer.running:
            s = self.sniffer.get_statistics()
            txt = f"Running | {s['total']} pkts | {pretty_bytes(s['total_bytes'])} | {s['capture_rate']:.1f} pkt/s"
            self.status_lbl.config(text=txt)
        else:
            s = self.sniffer.get_statistics()
            txt = f"Stopped | {s['total']} pkts | {pretty_bytes(s['total_bytes'])}"
            self.status_lbl.config(text=txt)
        
        self.root.after(1000, self.update_stats_loop)
    
    def on_close(self):
        if self.sniffer.running: self.sniffer.stop()
        self.root.destroy()


# ==================== MAIN ====================
def main():
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
