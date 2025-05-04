#read -p "Enter an IP address to find its MAC address: " ip_address
#echo "IP Address: $ip_address"

#mac=$(arp -n $user_ip | grep -o -E '([a-f0-9]{1,2}:){5}[a-f0-9]{1,2}')
#echo "MAC Address: $mac"


user_ip="192.168.0.1"
common_ports=(20 21 22 23 25 53 80 110 139 143 443 445 465 993 995 3306 3389 5432 5900 8080)


function wait_for_jobs() {
    while (( $(jobs -r | wc -l) >= 100 )); do
        sleep 0.1
    done
}

echo "Scanning $user_ip..."
for port in "${common_ports[@]}"; do
    wait_for_jobs
    (
        timeout 1 bash -c "echo > /dev/tcp/$user_ip/$port" 2>/dev/null &&
        echo "Port $port is OPEN"
    ) &
done
wait

echo "Scan complete."



