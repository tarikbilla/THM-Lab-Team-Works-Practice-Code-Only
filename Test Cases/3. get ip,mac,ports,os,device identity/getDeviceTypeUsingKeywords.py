import subprocess
import re

def run_command(cmd):
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
        return result.decode().strip()
    except subprocess.CalledProcessError:
        return ""

def guess_device_type(ip):
    print("\nScanning with Nmap...\n")
    scan_output = run_command(f"sudo nmap -O {ip}")
    
    if not scan_output:
        print("Nmap failed, trying xprobe2...\n")
        scan_output = run_command(f"xprobe2 {ip}")

    device_type = "Others"

    if re.search(r'Android', scan_output, re.IGNORECASE):
        device_type = "Android Mobile"
    elif re.search(r'Windows', scan_output, re.IGNORECASE):
        device_type = "Laptop"
    elif re.search(r'Linux|Ubuntu|Debian|CentOS|Red Hat|Fedora|Kali|Arch', scan_output, re.IGNORECASE):
        device_type = "Linux PC/Server"
    elif re.search(r'RTSP|IP Camera|Webcam|Camera', scan_output, re.IGNORECASE):
        device_type = "Camera"
    elif re.search(r'iPhone|iPad|iOS', scan_output, re.IGNORECASE):
        device_type = "Apple Mobile"
    elif re.search(r'Mac OS|Macintosh', scan_output, re.IGNORECASE):
        device_type = "Laptop"
    elif re.search(r'Tablet|Tab', scan_output, re.IGNORECASE):
        device_type = "Tab"
    elif re.search(r'Smart TV|TV', scan_output, re.IGNORECASE):
        device_type = "Smart TV"


    return device_type

if __name__ == "__main__":
    ip = input("Enter IP address: ").strip()
    if not ip:
        print("No IP entered.")
    else:
        device = guess_device_type(ip)
        print(f"\nDetected Device Type: {device}\n")

