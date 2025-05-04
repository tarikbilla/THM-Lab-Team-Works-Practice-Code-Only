import os
import socket
import subprocess
import re

OUI_FILE = "oui.txt"

# Load vendor from local OUI file
def load_oui():
    vendors = {}
    if not os.path.exists(OUI_FILE):
        print("OUI file not found.")
        return vendors
    with open(OUI_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = re.match(r"^([0-9A-Fa-f\-]{8})\s+\(hex\)\s+(.+)", line)
            if match:
                mac = match.group(1).replace("-", ":").upper()
                vendors[mac] = match.group(2).strip()
    return vendors

# Get MAC using arp
def get_mac(ip):
    try:
        subprocess.run(["ping", "-c", "1", ip], stdout=subprocess.DEVNULL)
        arp = subprocess.check_output(["arp", "-n", ip]).decode()
        mac_match = re.search(r"(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})", arp)
        if mac_match:
            return mac_match.group(1).upper()
    except:
        return None
    return None

# Get vendor from MAC
def get_vendor(mac, vendors):
    prefix = ":".join(mac.split(":")[:3])
    return vendors.get(prefix.upper(), "Unknown")

# Scan key ports
def scan_ports(ip):
    ports = [22, 23, 80, 81, 88, 443, 554, 8008, 8080, 34567]
    open_ports = []
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except:
            pass
    return open_ports

# TTL-based OS fingerprinting
def get_ttl(ip):
    try:
        output = subprocess.check_output(["ping", "-c", "1", ip], stderr=subprocess.DEVNULL).decode()
        ttl_match = re.search(r"ttl=(\d+)", output.lower())
        if ttl_match:
            return int(ttl_match.group(1))
    except:
        return None
    return None

# Final device guessing
def guess_type(vendor, ports, ttl):
    vendor = vendor.lower()

    if "hikvision" in vendor or 554 in ports or 34567 in ports:
        return "Camera"
    if "samsung" in vendor or 8008 in ports or 88 in ports:
        return "TV"
    if "apple" in vendor or ("xiaomi" in vendor and ttl and ttl <= 64):
        return "Mobile"
    if ttl and ttl >= 120 and (22 in ports or 443 in ports):
        return "Laptop"
    return "Unknown"

# Main detection
def detect(ip):
    vendors = load_oui()
    mac = get_mac(ip)
    if not mac:
        print("MAC Address: Not found")
        print("Device Type: Unknown")
        return

    vendor = get_vendor(mac, vendors)
    ports = scan_ports(ip)
    ttl = get_ttl(ip)
    device = guess_type(vendor, ports, ttl)

    print(f"IP Address: {ip}")
    print(f"MAC Address: {mac}")
    print(f"Vendor: {vendor}")
    print(f"Open Ports: {ports}")
    print(f"TTL: {ttl}")
    print(f"Device Type: {device}")

if __name__ == "__main__":
    ip = input("Enter IP address: ").strip()
    detect(ip)
