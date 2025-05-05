import getPorts, findMacAddress, findVendor, getTTL



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




if __name__ == "__main__":
    ip = input("Enter IP address: ").strip()
    print("Start Scanning.....\n")

    print(f"IP Address: {ip}")
    mac = findMacAddress.get_mac(ip).upper()
    print(f"MAC Address: {mac}")
    if not mac:
        print("Device Type: Unknown")

    ttl = getTTL.get_ttl(ip)
    print(f"TTL: {ttl}")

    vendor = findVendor.get_vendor(mac)
    print(f"Vendor: {vendor}")

    ports = getPorts.scan_ports(ip)
    print(f"Open Ports: {ports}")
    
    dtype = guess_type(vendor, ports, ttl)
    print(f"Device Type: {dtype}")
