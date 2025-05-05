import subprocess
from datetime import datetime

def run_command(cmd):
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
        return result.decode().strip()
    except subprocess.CalledProcessError:
        return "no response"

def is_reachable(ip):
    response = run_command(f"ping -c 1 {ip}")
    return "1 received" in response or "bytes from" in response

def get_fingerprint(ip):
    if not is_reachable(ip):
        return {"Error": f"Device at {ip} is not reachable."}

    return {
        "Target IP": ip,
        "Scan Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Reverse DNS": run_command(f"nslookup {ip}"),
        "ARP Entry": run_command(f"arp -n {ip}"),
        "MAC Address": run_command(f"arp -n {ip} | awk '{{print $3}}' | grep -Eo '([0-9a-f]{{2}}:?){{6}}'"),
        "Nmap OS Detection": run_command("sudo nmap -O {ip}"),
        "Nmap Open Ports Only": run_command(f"nmap --top-ports 20 {ip} | grep 'open'"),
        "Device Uptime Guess": run_command(f"snmpwalk -v2c -c public {ip} 1.3.6.1.2.1.1.3.0 || uptime"),
    }

def print_fingerprint_report(fingerprint_data):
    print("\nDevice Fingerprint Report\n")
    for key, value in fingerprint_data.items():
        print(f"\n{key}: \n{value}")
    print("End process")

if __name__ == "__main__":
    ip = input("IP address: ").strip()
    print("\nRunning scan...\n")
    report = get_fingerprint(ip)
    print_fingerprint_report(report)
