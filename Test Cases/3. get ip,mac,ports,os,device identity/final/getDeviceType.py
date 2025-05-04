from scapy.all import sniff, ARP, IP, Ether
import re
import os
import time

OUI_FILE = "oui.txt"
SEEN_DEVICES = {}

def load_oui_data():
    oui_map = {}
    if not os.path.exists(OUI_FILE):
        print(f"[!] OUI file not found: {OUI_FILE}")
        return oui_map
    with open(OUI_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = re.match(r"^([0-9A-Fa-f\-]{8})\s+\(hex\)\s+(.+)", line)
            if match:
                prefix = match.group(1).replace("-", ":").upper()
                vendor = match.group(2).strip()
                oui_map[prefix] = vendor
    return oui_map

def get_vendor(mac, oui_map):
    if not mac:
        return "Unknown"
    prefix = ":".join(mac.split(":")[:3])
    return oui_map.get(prefix, "Unknown Vendor")

def guess_device_type(vendor):
    vendor = vendor.lower()
    if "hikvision" in vendor:
        return "IP Camera"
    if "samsung" in vendor or "lg" in vendor:
        return "Smart TV"
    if "raspberry" in vendor:
        return "Raspberry Pi"
    if "apple" in vendor:
        return "iPhone or Mac"
    if "intel" in vendor or "realtek" in vendor:
        return "Laptop or PC"
    if "google" in vendor:
        return "Smart Home Device"
    if "router" in vendor or "ubiquiti" in vendor or "tplink" in vendor:
        return "Router or Access Point"
    return "Unknown"

def handle_packet(packet):
    if packet.haslayer(ARP) or packet.haslayer(IP):
        mac = packet[Ether].src.upper()
        ip = packet[IP].src if packet.haslayer(IP) else "No IP"
        if mac not in SEEN_DEVICES:
            vendor = get_vendor(mac, OUI)
            dev_type = guess_device_type(vendor)
            SEEN_DEVICES[mac] = (ip, vendor, dev_type)
            print(f"\n[+] New Device Detected:")
            print(f"    MAC: {mac}")
            print(f"    IP: {ip}")
            print(f"    Vendor: {vendor}")
            print(f"    Device Type: {dev_type}")

def main():
    print("[*] Starting passive device discovery... (Press Ctrl+C to stop)\n")
    global OUI
    OUI = load_oui_data()
    if not OUI:
        print("[!] Empty or missing OUI database. Aborting.")
        return
    sniff(prn=handle_packet, store=0)

if __name__ == "__main__":
    main()
