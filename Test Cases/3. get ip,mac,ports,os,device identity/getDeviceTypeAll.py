from scapy.all import sniff, Ether, ARP, IP, srp, sendp, TCP
import socket
import re
import os
import getTTL

OUI_FILE = "oui.txt"
SEEN = {}

# Load local OUI vendor database
def load_oui_data():
    oui = {}
    if not os.path.exists(OUI_FILE):
        print("OUI file not found.")
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
    common_ports = [
    554, 34567, 8000,  # Camera ports
    8008, 1900, 443,   # TV ports
    62078, 8888, 5228, 5222,  # Mobile ports
    22, 23,  # Raspberry Pi, Telnet
    433, 8883,  # Smart Plug ports
    1883, 8883,  # Smart Thermostat ports
    9999,  # Smart Lights port
    3389,  # Laptop RDP port
    5683,  # IoT Device CoAP port
    ]
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

def guess_type(vendor, ports, ttl):
    vendor = vendor.lower()

    # Camera Detection (e.g., Hikvision, Axis, Dahua, Foscam, Amcrest, Zmodo)
    if any(v in vendor for v in ["hikvision", "axis", "dahua", "foscam", "amcrest", "zmodo"]) or 554 in ports or 34567 in ports or 8000 in ports:
        return "Camera"
    
    # TV Detection (e.g., Samsung, LG, Sony, Vizio, TCL, Sharp, Panasonic)
    if any(v in vendor for v in ["samsung", "lg", "sony", "vizio", "tcl", "sharp", "panasonic"]) or 8008 in ports or 1900 in ports:
        return "TV"
    
    # Mobile Detection (e.g., Apple, Xiaomi, Huawei, Samsung, Motorola, OnePlus, Google)
    if any(v in vendor for v in ["apple", "xiaomi", "huawei", "samsung", "motorola", "oneplus", "google"]) or ("xiaomi" in vendor and ttl and ttl <= 64):
        return "Mobile"
    
    # Raspberry Pi Detection
    if "raspberry" in vendor or (22 in ports and ttl and ttl >= 120):
        return "Raspberry Pi"

    # Smart Plug Detection (e.g., Sonoff, TP-Link Kasa, Xiaomi)
    if any(v in vendor for v in ["sonoff", "tp-link", "xiaomi"]) or 433 in ports or 8883 in ports:
        return "Smart Plug"
    
    # Smart Thermostat Detection (e.g., Nest, Ecobee, Honeywell, Emerson)
    if any(v in vendor for v in ["nest", "ecobee", "honeywell", "emerson"]) or 1883 in ports or 8883 in ports:
        return "Smart Thermostat"
    
    # Smart Lights Detection (e.g., Philips Hue, LIFX, Xiaomi, TP-Link Kasa)
    if any(v in vendor for v in ["philips hue", "lifx", "xiaomi", "tp-link kasa"])or 9999 in ports:
        return "Smart Lights"
    
    # Laptop Detection (e.g., Apple, Dell, HP, Lenovo, ASUS, Acer, Microsoft)
    if ttl and ttl >= 120 and (22 in ports or 3389 in ports):
        return "Laptop"
    
    # Smart Security Systems Detection (e.g., Ring, Arlo, Nest)
    if any(v in vendor for v in ["ring", "arlo", "nest"]) or 554 in ports:
        return "Smart Security System"
    
    # General IoT Device (if vendor and ports match an IoT device, but no specific match)
    if 1883 in ports or 5683 in ports:
        return "IoT Device"
    
    return "Unknown"


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
    ttl = getTTL.get_ttl(ip)
    dev_type = guess_type(vendor, ports, ttl)
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
