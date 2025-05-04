import subprocess, re

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    except:
        return ""

def nmap_os(ip):
    print("1. Nmap OS detection...")
    out = run(f"sudo nmap -O {ip}")
    m = re.search(r"(OS details:.*|Running:.*)", out)
    return m.group(0) if m else None

def netcat_banner(ip, port=22):
    print("2. Netcat banner grab...")
    run(f"nc -vz {ip} {port}")
    banner = run(f"echo | nc {ip} {port}")
    return f"Banner: {banner}" if banner else None

def snmp_os(ip):
    print("3. SNMP check...")
    out = run(f"snmpget -v 2c -c public {ip} 1.3.6.1.2.1.1.1.0")
    return f"SNMP: {out}" if out else None

def dns_lookup(ip):
    print("4. Reverse DNS...")
    out = run(f"nslookup {ip}")
    if "name =" in out:
        return "DNS: " + out.split("name =")[-1].strip()
    return None

def mac_vendor(ip):
    print("5. MAC vendor...")
    out = run(f"arp -n {ip}")
    m = re.search(r"(([0-9a-f]{2}:){5}[0-9a-f]{2})", out, re.I)
    return f"MAC: {m.group(0)} (Check vendor manually)" if m else None

def ttl_os_guess(ip):
    print("6. TTL OS Guess...")
    out = run(f"ping -c 1 {ip}")
    ttl = re.search(r"ttl=(\d+)", out)
    if ttl:
        val = int(ttl.group(1))
        guess = "Windows" if val >= 120 else "Linux/Unix" if val <= 64 else "Unknown"
        return f"TTL: {val} → Possible OS: {guess}"
    return None

def xprobe2_os(ip):
    print("7. xprobe2 OS fingerprinting...")
    out = run(f"xprobe2 {ip}")
    m = re.search(r"Operating system: (.+)", out)
    return f"xprobe2: {m.group(1)}" if m else None

def detect_os(ip):
    results = []
    checks = [
        nmap_os,
        netcat_banner,
        snmp_os,
        dns_lookup,
        mac_vendor,
        ttl_os_guess,
        xprobe2_os,
    ]
    for check in checks:
        try:
            res = check(ip)
            if res:
                results.append(res)
        except Exception as e:
            results.append(f"Error in {check.__name__}: {e}")
    return results if results else ["OS not detected."]

if __name__ == "__main__":
    ip = input("Enter IP: ").strip()
    print("\n Starting OS finding...\n")
    for line in detect_os(ip):
        print(line)
