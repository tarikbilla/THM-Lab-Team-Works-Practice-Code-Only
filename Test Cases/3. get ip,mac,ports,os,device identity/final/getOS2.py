import subprocess
import re

def detect_os(ip):
    try:
        print(f"Running OS detection process {ip}...\n")
        result = subprocess.check_output(['sudo', 'nmap', '-O', '-Pn', '--top-ports', '1000', ip],
                                         stderr=subprocess.STDOUT,
                                         text=True)

        # Extract OS match
        os_matches = re.findall(r'OS details: (.+)', result)
        if os_matches:
            for match in os_matches:
                print(f"Detected OS: {match}")
        else:
            print("OS detection inconclusive. See full Nmap output below:\n")
            print(result)

    except subprocess.CalledProcessError as e:
        print("Nmap error:\n", e.output)

# Input IP
target_ip = input("Enter IP address: ")
detect_os(target_ip)

