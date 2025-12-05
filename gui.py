#!/usr/bin/env python3
"""
sniff_analyze_gui.py - Packet Sniffer with GUI (Enhanced Version)

Features:
 - Simple GUI with packet list and detail view
 - Protocol filter dropdown (DNS, HTTP, HTTPS, SMTP, TCP, UDP, ALL)
 - Start/Stop/Save/Clear buttons
 - Click packet to see details
 - Save all or save selected packet
 - Live packet capture display
 - Enhanced packet detailing from CLI version

Usage:
  sudo python3 snifARPf_analyze_gui.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime

from scapy.all import sniff, wrpcap, Raw, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP


# ---------------------- Helper Functions (from CLI version) ----------------------
def isHTTP(pkt):
    if TCP in pkt:
        try:
            raw = bytes(pkt[TCP].payload).decode(errors="ignore")
            return raw.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "HTTP/"))
        except:
            return False
    return False


def get_http_info(pkt):
    """Extract HTTP method and path from packet"""
    try:
        raw = bytes(pkt[TCP].payload).decode(errors="ignore")
        lines = raw.split('\r\n')
        if lines:
            return lines[0][:80]
    except:
        pass
    return ""


def get_dns_info(pkt):
    """Extract DNS query information"""
    try:
        if DNS in pkt and pkt[DNS].qd:
            qname = pkt[DNS].qd.qname.decode(errors='ignore').rstrip('.')
            qtype = pkt[DNS].qd.qtype
            type_map = {1: 'A', 2: 'NS', 5: 'CNAME', 15: 'MX', 16: 'TXT', 28: 'AAAA'}
            qtype_str = type_map.get(qtype, str(qtype))
            return f"{qname} ({qtype_str})"
    except:
        pass
    return ""


def get_protocol(pkt):
    """Determine packet protocol"""
    if IP in pkt:
        if isHTTP(pkt):
            return "HTTP"
        elif DNS in pkt:
            return "DNS"
        elif TCP in pkt:
            if pkt[TCP].sport == 25 or pkt[TCP].dport == 25:
                return "SMTP"
            elif pkt[TCP].sport == 443 or pkt[TCP].dport == 443:
                return "HTTPS"
            return "TCP"
        elif UDP in pkt:
            return "UDP"
        elif ICMP in pkt:
            return "ICMP"
        else:
            return f"IP({pkt[IP].proto})"
    elif ARP in pkt:
        return "ARP"
    else:
        return "Other"


def get_packet_info(pkt):
    """Extract basic packet info for list display"""
    try:
        ts = datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S.%f")[:-3]
        proto = get_protocol(pkt)
        length = len(pkt)
        
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            info = ""
            
            if TCP in pkt:
                info = f"{pkt[TCP].sport} → {pkt[TCP].dport}"
                flags = []
                if pkt[TCP].flags.S: flags.append("SYN")
                if pkt[TCP].flags.A: flags.append("ACK")
                if pkt[TCP].flags.F: flags.append("FIN")
                if pkt[TCP].flags.R: flags.append("RST")
                if flags:
                    info += f" [{','.join(flags)}]"
                # Add HTTP/HTTPS info
                if isHTTP(pkt):
                    http_info = get_http_info(pkt)
                    if http_info:
                        info += f" {http_info[:40]}"
            elif UDP in pkt:
                info = f"{pkt[UDP].sport} → {pkt[UDP].dport}"
                # Add DNS info
                if DNS in pkt:
                    dns_info = get_dns_info(pkt)
                    if dns_info:
                        info += f" {dns_info}"
            elif ICMP in pkt:
                type_map = {0: 'Echo Reply', 8: 'Echo Request', 3: 'Dest Unreachable'}
                info = type_map.get(pkt[ICMP].type, f"Type {pkt[ICMP].type}")
                
        elif ARP in pkt:
            src = pkt[ARP].psrc
            dst = pkt[ARP].pdst
            info = "Request" if pkt[ARP].op == 1 else "Reply"
        else:
            src = "N/A"
            dst = "N/A"
            info = "Non-IP"
            
        return (ts, src, dst, proto, length, info)
    except:
        return (datetime.now().strftime("%H:%M:%S.%f")[:-3], "Error", "Error", "Error", 0, "Parse Error")


def get_tcp_flags_str(tcp):
    """Return a readable string of TCP flags"""
    flags = []
    if tcp.flags.S: flags.append("SYN")
    if tcp.flags.A: flags.append("ACK")
    if tcp.flags.F: flags.append("FIN")
    if tcp.flags.R: flags.append("RST")
    if tcp.flags.P: flags.append("PSH")
    if tcp.flags.U: flags.append("URG")
    return ", ".join(flags) if flags else "None"


def get_payload_preview(pkt, max_len=200):
    """Extract and preview packet payload"""
    if Raw in pkt:
        try:
            raw_data = bytes(pkt[Raw].load)
            try:
                text = raw_data.decode('utf-8', errors='ignore')
                preview = text[:max_len].replace('\r', '\\r').replace('\n', '\\n')
                if len(text) > max_len:
                    preview += "..."
                return preview
            except:
                hex_str = raw_data[:max_len].hex()
                if len(raw_data) > max_len:
                    hex_str += "..."
                return f"HEX: {hex_str}"
        except:
            pass
    return "(No payload)"


def get_packet_detail(pkt):
    """Generate detailed packet information (from CLI version)"""
    lines = []
    
    ts = datetime.fromtimestamp(pkt.time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    lines.append(f"═══════════════════════════════════════════════════════════════")
    lines.append(f"PACKET DETAILS")
    lines.append(f"═══════════════════════════════════════════════════════════════")
    lines.append(f"Timestamp: {ts}")
    lines.append(f"Length:    {len(pkt)} bytes")
    lines.append("")
    
    # Ethernet
    if Ether in pkt:
        eth = pkt[Ether]
        lines.append(f"── Ethernet Layer ──")
        lines.append(f"Source MAC:      {eth.src}")
        lines.append(f"Dest MAC:        {eth.dst}")
        lines.append(f"Type:            {hex(eth.type)}")
        lines.append("")
    
    # ARP
    if ARP in pkt:
        arp = pkt[ARP]
        op = "Request" if arp.op == 1 else "Reply"
        lines.append(f"── ARP {op} ──")
        lines.append(f"Hardware Src:    {arp.hwsrc}")
        lines.append(f"Hardware Dst:    {arp.hwdst}")
        lines.append(f"Protocol Src:    {arp.psrc}")
        lines.append(f"Protocol Dst:    {arp.pdst}")
        return "\n".join(lines)
    
    # IP
    if IP in pkt:
        ip = pkt[IP]
        lines.append(f"── IP Layer ──")
        lines.append(f"Source IP:       {ip.src}")
        lines.append(f"Dest IP:         {ip.dst}")
        lines.append(f"TTL:             {ip.ttl}")
        lines.append(f"Protocol:        {ip.proto}")
        lines.append(f"Length:          {ip.len}")
        lines.append("")
        
        # TCP
        if TCP in pkt:
            tcp = pkt[TCP]
            lines.append(f"── TCP Layer ──")
            lines.append(f"Source Port:     {tcp.sport}")
            lines.append(f"Dest Port:       {tcp.dport}")
            lines.append(f"Sequence:        {tcp.seq}")
            lines.append(f"Acknowledgment:  {tcp.ack}")
            lines.append(f"Flags:           {get_tcp_flags_str(tcp)}")
            lines.append(f"Window Size:     {tcp.window}")
            lines.append("")
            
            # HTTP/HTTPS
            if isHTTP(pkt):
                lines.append(f"── HTTP Content ──")
                try:
                    raw = bytes(tcp.payload).decode(errors='ignore')
                    http_lines = raw.split('\r\n')[:10]
                    for line in http_lines:
                        if line:
                            lines.append(f"  {line}")
                except:
                    lines.append("  [Unable to parse HTTP content]")
                lines.append("")
            elif tcp.sport == 443 or tcp.dport == 443:
                lines.append(f"── HTTPS (Encrypted) ──")
                lines.append("  Content is encrypted and cannot be displayed")
                lines.append("")
            
            # SMTP
            if tcp.sport == 25 or tcp.dport == 25:
                lines.append(f"── SMTP Packet ──")
                lines.append("")
            
            # Payload
            if Raw in pkt:
                lines.append(f"── Payload Preview ──")
                lines.append(get_payload_preview(pkt, 200))
        
        # UDP
        elif UDP in pkt:
            udp = pkt[UDP]
            lines.append(f"── UDP Layer ──")
            lines.append(f"Source Port:     {udp.sport}")
            lines.append(f"Dest Port:       {udp.dport}")
            lines.append(f"Length:          {udp.len}")
            lines.append("")
            
            # DNS
            if DNS in pkt:
                dns = pkt[DNS]
                lines.append(f"── DNS Layer ──")
                lines.append(f"Transaction ID:  {dns.id}")
                lines.append(f"Type:            {'Response' if dns.qr else 'Query'}")
                lines.append(f"Questions:       {dns.qdcount}")
                lines.append(f"Answers:         {dns.ancount}")
                
                if dns.qd:
                    lines.append(f"Query Name:      {dns.qd.qname.decode(errors='ignore').rstrip('.')}")
                    qtype_map = {1: 'A', 2: 'NS', 5: 'CNAME', 15: 'MX', 16: 'TXT', 28: 'AAAA'}
                    lines.append(f"Query Type:      {qtype_map.get(dns.qd.qtype, dns.qd.qtype)}")
                
                if dns.an:
                    lines.append(f"Answers:")
                    try:
                        for i in range(min(dns.ancount, 5)):
                            ans = dns.an[i] if hasattr(dns.an, '__getitem__') else dns.an
                            if hasattr(ans, 'rdata'):
                                lines.append(f"  - {ans.rdata}")
                    except:
                        pass
                lines.append("")
            
            # Payload
            if Raw in pkt:
                lines.append(f"── Payload Preview ──")
                lines.append(get_payload_preview(pkt, 200))
        
        # ICMP
        elif ICMP in pkt:
            ic = pkt[ICMP]
            type_map = {0: 'Echo Reply', 3: 'Dest Unreachable', 8: 'Echo Request', 11: 'Time Exceeded'}
            lines.append(f"── ICMP Layer ──")
            lines.append(f"Type:            {ic.type} ({type_map.get(ic.type, 'Unknown')})")
            lines.append(f"Code:            {ic.code}")
            if hasattr(ic, 'id'):
                lines.append(f"ID:              {ic.id}")
            if hasattr(ic, 'seq'):
                lines.append(f"Sequence:        {ic.seq}")
    
    return "\n".join(lines)


def build_bpf_from_protocol(protocol):
    """Build BPF filter from protocol selection"""
    filters = {
        "DNS": "udp port 53",
        "HTTP": "tcp port 80",
        "HTTPS": "tcp port 443",
        "SMTP": "tcp port 25",
        "TCP": "tcp",
        "UDP": "udp",
        "ICMP": "icmp",
        "ARP": "arp",
        "ALL": None
    }
    return filters.get(protocol, None)


# ---------------------- Packet Sniffer ----------------------
class PacketSniffer:
    def __init__(self, callback):
        self.callback = callback
        self.packets = []
        self.running = False
        self.thread = None
        self.lock = threading.Lock()
        
    def start(self, iface=None, bpf=None):
        """Start packet capture"""
        if self.running:
            return False
        
        self.running = True
        self.thread = threading.Thread(target=self._capture, args=(iface, bpf), daemon=True)
        self.thread.start()
        return True
    
    def stop(self):
        """Stop packet capture"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        return True
    
    def _capture(self, iface, bpf):
        """Capture loop"""
        try:
            while self.running:
                try:
                    sniff(
                        iface=iface,
                        filter=bpf,
                        prn=self._process_packet,
                        store=False,
                        timeout=1,
                        count=10
                    )
                except Exception as e:
                    print(f"Capture error: {e}")
                    time.sleep(0.5)
        except Exception as e:
            print(f"Fatal capture error: {e}")
    
    def _process_packet(self, pkt):
        """Process captured packet"""
        with self.lock:
            self.packets.append(pkt)
            self.callback(pkt)
    
    def get_packets(self):
        """Get all captured packets"""
        with self.lock:
            return list(self.packets)
    
    def get_packet(self, idx):
        """Get specific packet"""
        with self.lock:
            if 0 <= idx < len(self.packets):
                return self.packets[idx]
        return None
    
    def clear_packets(self):
        """Clear all packets"""
        with self.lock:
            self.packets.clear()


# ---------------------- GUI Application ----------------------
class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("1200x700")
        
        self.sniffer = PacketSniffer(self.on_packet_captured)
        self.packet_count = 0
        
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def create_widgets(self):
        """Create all GUI widgets"""
        
        # ===== Top Control Panel =====
        control_frame = ttk.Frame(self.root, padding="5")
        control_frame.pack(fill=tk.X, side=tk.TOP)
        
        # Buttons
        self.start_btn = ttk.Button(control_frame, text="▶ Start", command=self.start_capture, width=12)
        self.start_btn.pack(side=tk.LEFT, padx=2)
        
        self.stop_btn = ttk.Button(control_frame, text="⏸ Stop", command=self.stop_capture, width=12, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=2)
        
        ttk.Separator(control_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        ttk.Button(control_frame, text="💾 Save All", command=self.save_all, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(control_frame, text="💾 Save Selected", command=self.save_selected, width=14).pack(side=tk.LEFT, padx=2)
        
        ttk.Separator(control_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        ttk.Button(control_frame, text="🗑 Clear", command=self.clear_packets, width=10).pack(side=tk.LEFT, padx=2)
        
        # Status label
        self.status_label = ttk.Label(control_frame, text="Status: Stopped | Packets: 0", relief=tk.SUNKEN)
        self.status_label.pack(side=tk.RIGHT, padx=5)
        
        # Filter frame
        filter_frame = ttk.Frame(self.root, padding="5")
        filter_frame.pack(fill=tk.X, side=tk.TOP)
        
        ttk.Label(filter_frame, text="Interface:").pack(side=tk.LEFT, padx=2)
        self.iface_entry = ttk.Entry(filter_frame, width=15)
        self.iface_entry.pack(side=tk.LEFT, padx=2)
        
        ttk.Label(filter_frame, text="Protocol Filter:").pack(side=tk.LEFT, padx=(15, 2))
        self.proto_combo = ttk.Combobox(filter_frame, width=12, state="readonly")
        self.proto_combo['values'] = ("ALL", "DNS", "HTTP", "HTTPS", "SMTP", "TCP", "UDP", "ICMP", "ARP")
        self.proto_combo.current(0)
        self.proto_combo.pack(side=tk.LEFT, padx=2)
        
        ttk.Label(filter_frame, text="Custom BPF:").pack(side=tk.LEFT, padx=(15, 2))
        self.bpf_entry = ttk.Entry(filter_frame, width=35)
        self.bpf_entry.pack(side=tk.LEFT, padx=2)
        
        ttk.Button(filter_frame, text="Apply Filter", command=self.apply_filter, width=12).pack(side=tk.LEFT, padx=5)
        
        # ===== Packet List (Top) =====
        list_frame = ttk.Frame(self.root)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5, side=tk.TOP)
        
        ttk.Label(list_frame, text="Captured Packets:", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        
        columns = ("No", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=12)
        
        self.tree.column("No", width=50, anchor=tk.CENTER)
        self.tree.column("Time", width=100, anchor=tk.W)
        self.tree.column("Source", width=140, anchor=tk.W)
        self.tree.column("Destination", width=140, anchor=tk.W)
        self.tree.column("Protocol", width=80, anchor=tk.CENTER)
        self.tree.column("Length", width=80, anchor=tk.CENTER)
        self.tree.column("Info", width=400, anchor=tk.W)
        
        for col in columns:
            self.tree.heading(col, text=col)
        
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.tree.bind('<<TreeviewSelect>>', self.on_packet_select)
        
        # ===== Packet Detail (Bottom) =====
        detail_frame = ttk.Frame(self.root)
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5, side=tk.BOTTOM)
        
        ttk.Label(detail_frame, text="Packet Details:", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        
        self.detail_text = scrolledtext.ScrolledText(detail_frame, height=15, wrap=tk.WORD, font=('Courier', 9))
        self.detail_text.pack(fill=tk.BOTH, expand=True)
        self.detail_text.insert(1.0, "Select a packet to view details...")
        self.detail_text.config(state=tk.DISABLED)
    
    def start_capture(self):
        """Start packet capture"""
        iface = self.iface_entry.get().strip() or None
        
        # Get BPF filter (custom or from protocol dropdown)
        custom_bpf = self.bpf_entry.get().strip()
        if custom_bpf:
            bpf = custom_bpf
        else:
            protocol = self.proto_combo.get()
            bpf = build_bpf_from_protocol(protocol)
        
        if self.sniffer.start(iface, bpf):
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.iface_entry.config(state=tk.DISABLED)
            self.proto_combo.config(state=tk.DISABLED)
            self.update_status("Running")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.sniffer.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.iface_entry.config(state=tk.NORMAL)
        self.proto_combo.config(state="readonly")
        self.update_status("Stopped")
    
    def apply_filter(self):
        """Apply filter by restarting capture"""
        if self.sniffer.running:
            self.sniffer.stop()
            time.sleep(0.5)
            
            iface = self.iface_entry.get().strip() or None
            custom_bpf = self.bpf_entry.get().strip()
            if custom_bpf:
                bpf = custom_bpf
            else:
                protocol = self.proto_combo.get()
                bpf = build_bpf_from_protocol(protocol)
            
            if self.sniffer.start(iface, bpf):
                messagebox.showinfo("Filter Applied", "Capture restarted with new filter")
            else:
                messagebox.showerror("Error", "Failed to restart capture")
                self.start_btn.config(state=tk.NORMAL)
                self.stop_btn.config(state=tk.DISABLED)
        else:
            messagebox.showinfo("Not Running", "Start capture first, then apply filter")
    
    def on_packet_captured(self, pkt):
        """Callback when packet is captured"""
        self.root.after(0, self._add_packet_to_list, pkt)
    
    def _add_packet_to_list(self, pkt):
        """Add packet to treeview"""
        self.packet_count += 1
        ts, src, dst, proto, length, info = get_packet_info(pkt)
        
        tag = proto.lower()
        self.tree.insert('', tk.END, values=(self.packet_count, ts, src, dst, proto, length, info), tags=(tag,))
        
        self.tree.yview_moveto(1.0)
        self.update_status(f"Running")
    
    def on_packet_select(self, event):
        """Handle packet selection"""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = self.tree.item(selection[0])
        packet_no = int(item['values'][0]) - 1
        
        pkt = self.sniffer.get_packet(packet_no)
        if pkt:
            detail = get_packet_detail(pkt)
            self.detail_text.config(state=tk.NORMAL)
            self.detail_text.delete(1.0, tk.END)
            self.detail_text.insert(1.0, detail)
            self.detail_text.config(state=tk.DISABLED)
    
    def save_all(self):
        """Save all packets to file"""
        packets = self.sniffer.get_packets()
        if not packets:
            messagebox.showwarning("No Packets", "No packets to save!")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                wrpcap(filename, packets)
                messagebox.showinfo("Success", f"Saved {len(packets)} packets to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {e}")
    
    def save_selected(self):
        """Save selected packet to file"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a packet first!")
            return
        
        item = self.tree.item(selection[0])
        packet_no = int(item['values'][0]) - 1
        
        pkt = self.sniffer.get_packet(packet_no)
        if not pkt:
            messagebox.showerror("Error", "Failed to retrieve packet!")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
            initialfile=f"packet_{packet_no+1}.pcap"
        )
        
        if filename:
            try:
                wrpcap(filename, [pkt])
                messagebox.showinfo("Success", f"Saved packet {packet_no+1} to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {e}")
    
    def clear_packets(self):
        """Clear all packets"""
        if messagebox.askyesno("Clear Packets", "Clear all captured packets?"):
            self.sniffer.clear_packets()
            self.tree.delete(*self.tree.get_children())
            self.packet_count = 0
            self.detail_text.config(state=tk.NORMAL)
            self.detail_text.delete(1.0, tk.END)
            self.detail_text.insert(1.0, "Select a packet to view details...")
            self.detail_text.config(state=tk.DISABLED)
            self.update_status("Stopped" if not self.sniffer.running else "Running")
    
    def update_status(self, status):
        """Update status label"""
        self.status_label.config(text=f"Status: {status} | Packets: {self.packet_count}")
    
    def on_closing(self):
        """Handle window close"""
        if self.sniffer.running:
            self.sniffer.stop()
        self.root.destroy()


# ---------------------- Main ----------------------
def main():
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
