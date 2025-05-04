read -p "Enter an IP address: " ip_address

for port in {1..65535}; do
    while (( $(jobs -r | wc -l) >= 100 )); do
        sleep 0.1
    done

    (timeout 1 bash -c "echo > /dev/tcp/$ip_address/$port" 2>/dev/null && echo "Port $port is OPEN") &
done

wait

echo "Phase 3 is completed!"
