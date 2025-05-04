read -p "Enter an IP address to find its MAC address: " ip_address
echo "IP Address: $ip_address"

mac=$(arp -n $user_ip | grep -o -E '([a-f0-9]{1,2}:){5}[a-f0-9]{1,2}')
echo "MAC Address: $mac"
