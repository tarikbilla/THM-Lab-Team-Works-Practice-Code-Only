import subprocess

# Function to run Nmap OS detection
def nmap_os_scan(ip):
    try:
        # Run Nmap with the -O flag for OS detection
        command = ["nmap", "-O", ip]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Capture the output of the Nmap scan
        nmap_output = result.stdout.decode()
        
        # Look for OS detection results in the output
        for line in nmap_output.splitlines():
            if "OS details" in line:
                return line.strip()
        
        return "OS details not found"
    
    except Exception as e:
        return f"Error running Nmap: {str(e)}"

# Example usage
ip_address = input("Enter IP Address: ")
os_info = nmap_os_scan(ip_address)
print("OS Info:", os_info)

