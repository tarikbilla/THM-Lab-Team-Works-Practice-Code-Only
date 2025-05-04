
read -p "Enter an IP address to find its MAC address: " user_ip
mac=$(arp -n $user_ip | grep -o -E '([a-f0-9]{1,2}:){5}[a-f0-9]{1,2}')
echo "MAC Address for $user_ip: $mac"

echo "done test case 2"
