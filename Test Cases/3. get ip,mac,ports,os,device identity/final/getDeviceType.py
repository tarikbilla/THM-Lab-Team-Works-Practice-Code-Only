import getPorts
import findMacAddress
import findVendor
import getTTL



def guess_type(vendor, ports, ttl):
    vendor = vendor.lower()

    # Camera Detection (e.g., Hikvision, Axis, Dahua, Foscam, Amcrest, Zmodo)
    if any(v in vendor for v in ["hikvision", "axis", "dahua", "foscam", "amcrest", "zmodo"]) or 554 in ports or 34567 in ports or 8000 in ports:
        return "Camera"
    
    # TV Detection (e.g., Samsung, LG, Sony, Vizio, TCL, Sharp, Panasonic)
    if any(v in vendor for v in ["samsung", "lg", "sony", "vizio", "tcl", "sharp", "panasonic"]) or 8008 in ports or 1900 in ports or 443 in ports:
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
    if any(v in vendor for v in ["philips hue", "lifx", "xiaomi", "tp-link kasa"]) or 443 in ports or 9999 in ports:
        return "Smart Lights"
    
    # Laptop Detection (e.g., Apple, Dell, HP, Lenovo, ASUS, Acer, Microsoft)
    if ttl and ttl >= 120 and (22 in ports or 3389 in ports):
        return "Laptop"
    
    # Smart Security Systems Detection (e.g., Ring, Arlo, Nest)
    if any(v in vendor for v in ["ring", "arlo", "nest"]) or 443 in ports or 554 in ports:
        return "Smart Security System"
    
    # General IoT Device (if vendor and ports match an IoT device, but no specific match)
    if 1883 in ports or 5683 in ports:
        return "IoT Device"
    
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
