from scapy.all import sniff, Ether, ARP, IP, srp, sendp, TCP
import socket
import re
import os

OUI_FILE = "oui.txt"
SEEN = {}

# Load local OUI vendor database
def load_oui_data():
    oui = {}
    if not os.path.exists(OUI_FILE):
        print("[!] OUI file not found.")
        return oui
    with open(OUI_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = re.match(r"^([0-9A-Fa-f\-]{8})\s+\(hex\)\s+(.+)", line)
            if match:
                prefix = match.group(1).replace("-", ":").upper()
                vendor = match.group(2).strip()
                oui[prefix] = vendor
    return oui

# Extract vendor from MAC
def get_vendor(mac, oui):
    prefix = ":".join(mac.split(":")[:3])
    return oui.get(prefix, "Unknown Vendor")

# Scan common ports on device
def scan_ports(ip):
    open_ports = []
    common_ports = [80, 443, 554, 8008, 22, 23]
    for port in common_ports:
        try:
            s = socket.socket()
            s.settimeout(0.4)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except:
            pass
    return open_ports

# Guess device type from vendor + port
def guess_type(vendor, ports):
    vendor = vendor.lower()
    if "hikvision" in vendor or 554 in ports:
        return "IP Camera"
    if "samsung" in vendor and 8008 in ports:
        return "Smart TV"
    if "apple" in vendor and 62078 in ports:
        return "iPhone / iPad"
    if "raspberry" in vendor:
        return "Raspberry Pi"
    if 22 in ports:
        return "Linux Device / SSH Enabled"
    if 23 in ports:
        return "Legacy Router / Telnet"
    if "router" in vendor or "mikrotik" in vendor or "tplink" in vendor:
        return "Router / Access Point"
    if 80 in ports and 443 not in ports:
        return "Basic Web IoT"
    return "Generic / Unknown"

# ARP ping the IP to get MAC if not seen passively
def active_arp(ip):
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=ip)
    ans, _ = srp(ether / arp, timeout=2, verbose=0)
    for _, rcv in ans:
        return rcv.hwsrc
    return None

# Main logic to process new IP
def process_ip(ip, mac, oui):
    if not mac:
        mac = active_arp(ip)
    if not mac:
        return
    if mac in SEEN:
        return
    vendor = get_vendor(mac, oui)
    ports = scan_ports(ip)
    dev_type = guess_type(vendor, ports)
    SEEN[mac] = True
    print(f"\nDevice Detected:")
    print(f"    IP: {ip}")
    print(f"    MAC: {mac}")
    print(f"    Vendor: {vendor}")
    print(f"    Open Ports: {ports}")
    print(f"    Device Type: {dev_type}")

# Passive sniffing
def sniff_callback(pkt):
    if pkt.haslayer(Ether) and pkt.haslayer(IP):
        mac = pkt[Ether].src.upper()
        ip = pkt[IP].src
        process_ip(ip, mac, OUI)

def main():
    global OUI
    print("Starting scan... \n")
    OUI = load_oui_data()
    if not OUI:
        print("OUI DB missing")
        return
    try:
        sniff(prn=sniff_callback, store=0, filter="ip", promisc=True)
    except KeyboardInterrupt:
        print("\nExiting.")


if __name__ == "__main__":
    main()
