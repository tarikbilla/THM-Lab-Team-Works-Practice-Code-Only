import os
import socket
import subprocess
import re

OUI_FILE = "oui.txt"

def load_oui():
    vendors = {}
    if not os.path.exists(OUI_FILE):
        print("OUI file not found.")
        return vendors
    with open(OUI_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "(hex)" in line:
                parts = line.strip().split()
                if len(parts) >= 3:
                    mac = parts[0].replace("-", ":").upper()
                    vendor = " ".join(parts[2:])
                    vendors[mac] = vendor
    return vendors

def get_mac(ip):
    try:
        subprocess.run(["ping", "-c", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        output = subprocess.check_output(["arp", "-n", ip]).decode()
        match = re.search(r"(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})", output)
        return match.group(1).upper() if match else None
    except:
        return None

def get_vendor(mac, vendors):
    return vendors.get(":".join(mac.split(":")[:3]).upper(), "Unknown")

def scan_ports(ip):
    ports = [554, 8008, 88, 443, 22, 80, 81, 23, 8080, 34567]
    open_ports = []
    for port in ports:
        try:
            with socket.socket() as s:
                s.settimeout(0.4)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except:
            continue
    return open_ports

def get_ttl(ip):
    try:
        result = subprocess.check_output(["ping", "-c", "1", ip], stderr=subprocess.DEVNULL).decode()
        ttl = re.search(r"ttl=(\d+)", result.lower())
        return int(ttl.group(1)) if ttl else None
    except:
        return None

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

def detect(ip):
    vendors = load_oui()
    mac = get_mac(ip)
    if not mac:
        print("MAC Address: Not found")
        print("Device Type: Unknown")
        return

    vendor = get_vendor(mac, vendors)
    ttl = get_ttl(ip)
    ports = scan_ports(ip)
    dtype = guess_type(vendor, ports, ttl)

    print(f"IP Address: {ip}")
    print(f"MAC Address: {mac}")
    print(f"Vendor: {vendor}")
    print(f"Open Ports: {ports}")
    print(f"TTL: {ttl}")
    print(f"Device Type: {dtype}")

if __name__ == "__main__":
    ip = input("Enter IP address: ").strip()
    detect(ip)
