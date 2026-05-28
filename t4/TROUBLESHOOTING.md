# Troubleshooting Guide

## Common Issues and Solutions

### Issue 1: No Alerts Generated

**Symptoms:**
- Dashboard shows 0 alerts
- eve.json file is empty or not being updated
- No activity in alert.log

**Diagnosis Steps:**

```bash
# 1. Check Suricata is running
sudo systemctl status suricata
# or for Docker
docker ps | grep suricata

# 2. Verify network interface has traffic
sudo tcpdump -i eth0 -c 10
# Should show packets

# 3. Check Suricata can access the interface
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -T
# Should show "Configuration check OK"

# 4. Check rules are loaded
suricata -c /etc/suricata/suricata.yaml -S | head
# Should show list of rules

# 5. View Suricata debug logs
tail -f /var/log/suricata/suricata.log
```

**Solutions:**

**A. Wrong network interface:**
```bash
# Find correct interface
ip link show
# or
ifconfig -a

# Update config
sed -i 's/eth0/your_interface/g' config/suricata.yaml
docker-compose restart suricata
```

**B. Interface in promisc mode failed:**
```bash
# Manually enable promiscuous mode
sudo ip link set eth0 promisc on

# Restart Suricata
sudo systemctl restart suricata
```

**C. Rules not loading:**
```bash
# Verify rules files exist
ls -la rules/

# Check syntax
suricata -c /etc/suricata/suricata.yaml -T -v

# Look for errors in logs
grep "ERROR\|error" /var/log/suricata/suricata.log
```

**D. No traffic on interface:**
- Check network cable connection
- Verify interface is not in monitoring/bridge mode
- Ensure not behind another IDS/sniffer
- Check if virtual machine network settings

---

### Issue 2: Dashboard Not Loading

**Symptoms:**
- Connection refused on localhost:5000
- Page doesn't load or loads with errors
- API endpoints return 500 errors

**Diagnosis Steps:**

```bash
# 1. Check dashboard container running
docker ps | grep dashboard

# 2. Check port is listening
sudo netstat -tlnp | grep 5000
# or
sudo ss -tlnp | grep 5000

# 3. View dashboard logs
docker logs -f ids-dashboard

# 4. Test API endpoint
curl http://localhost:5000/api/health

# 5. Check data files exist
ls -la data/
```

**Solutions:**

**A. Port already in use:**
```bash
# Find what's using port 5000
sudo lsof -i :5000

# Kill the process or use different port
# Edit docker-compose.yml:
# ports:
#   - "5001:5000"  # Use 5001 instead

docker-compose down
docker-compose up -d
```

**B. Flask not starting:**
```bash
# Check Flask installation in container
docker exec ids-dashboard pip list | grep -i flask

# Rebuild container
docker-compose down
docker image rm ids-dashboard
docker-compose build
docker-compose up -d
```

**C. Data files missing:**
```bash
# Create missing directories
mkdir -p data logs/suricata

# Ensure proper permissions
chmod 755 data logs

# Start services to generate files
docker-compose up -d alert-monitor
```

**D. Permission issues:**
```bash
# Check file permissions
ls -la data/
ls -la logs/

# Fix permissions (if needed)
chmod 644 data/*.json
chmod 755 data logs
```

---

### Issue 3: High CPU Usage

**Symptoms:**
- Suricata process using 80-100% CPU
- System becomes unresponsive
- Dropped packets increase

**Diagnosis Steps:**

```bash
# 1. Monitor CPU usage
top -p $(pgrep suricata)

# 2. Check dropped packets
cat /proc/net/dev | grep eth0

# 3. Identify slow rules
grep "rule:" /var/log/suricata/suricata.log | grep "slow"

# 4. Check packet rate
tcpdump -i eth0 -c 100 | wc -l
# Multiply by (10/seconds_elapsed) for packets/sec
```

**Solutions:**

**A. Reduce rule set:**
```bash
# Disable expensive rules
# Edit rules/custom-rules.rules
# Comment out heavy pattern rules

# Rebuild and restart
docker-compose restart suricata
```

**B. Enable multithreading:**
```yaml
# Edit config/suricata.yaml
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: ["0"]
      receive-cpu-set:
        cpu: ["1"]
      worker-cpu-set:
        cpu: ["2-7"]  # Adjust based on available CPUs
```

**C. Optimize performance:**
```yaml
# In suricata.yaml
stream:
  checksum-validation: no  # Disable if validated elsewhere
  
app-layer:
  protocols:
    tls: no  # Disable if not needed
    http: yes
    dns: no  # Disable if not needed
```

**D. Increase buffer:**
```bash
# Increase system buffer
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.rmem_default=134217728

# Make permanent
echo "net.core.rmem_max=134217728" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

---

### Issue 4: Memory Issues

**Symptoms:**
- Out of memory errors
- Suricata killed by OOM killer
- Services failing to start

**Diagnosis Steps:**

```bash
# 1. Check memory usage
free -h
ps aux | grep suricata | grep -v grep

# 2. Check for memory leaks
top -M  # Sort by memory

# 3. Check container memory limits
docker stats ids-suricata

# 4. Check system logs for OOM
dmesg | tail -20
grep "Out of memory" /var/log/syslog
```

**Solutions:**

**A. Increase available memory:**
```bash
# Add swap space (if on VM)
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Verify
free -h
```

**B. Reduce stream buffer:**
```yaml
# Edit config/suricata.yaml
stream:
  memcap: 16777216  # Reduce from 32MB

app-layer:
  memcap: 100000000  # Reduce from 200MB
```

**C. Reduce rule set:**
```bash
# Keep only essential rules
# Remove or comment rules not needed
wc -l rules/*.rules
```

**D. Docker memory limit:**
```yaml
# Edit docker-compose.yml for suricata service
mem_limit: 1g
memswap_limit: 2g
```

---

### Issue 5: Alerts Not Being Blocked

**Symptoms:**
- Alerts generated but IPs not blocked
- Response handler shows actions but traffic continues
- blocked_ips.txt shows entries but traffic not blocked

**Diagnosis Steps:**

```bash
# 1. Check response handler is running
docker ps | grep response

# 2. View response handler logs
docker logs -f ids-response

# 3. Check iptables rules
sudo iptables -L -n | head -20

# 4. Test manual block
sudo iptables -I INPUT 1 -s 192.0.2.1 -j DROP

# 5. Check if IP is whitelisted
grep "192.0.2.1" config/whitelist.txt
```

**Solutions:**

**A. Response handler not running:**
```bash
docker-compose logs ids-response
docker-compose restart response-handler
```

**B. iptables not configured:**
```bash
# Enable iptables (requires root)
sudo iptables -F  # Clear existing rules
sudo iptables -X

# Restart services
docker-compose restart response-handler
```

**C. Docker network isolation:**
```bash
# For Docker, blocking needs to be on host
# Edit docker-compose.yml response-handler:
network_mode: host
cap_add:
  - NET_ADMIN

docker-compose down
docker-compose up -d
```

**D. IP is whitelisted:**
```bash
# Check whitelist
cat config/whitelist.txt | grep "203.0.113"

# Remove from whitelist if false positive
# Edit config/whitelist.txt
```

---

### Issue 6: Duplicate Alerts Flooding

**Symptoms:**
- Same alert repeated many times
- Alert count very high
- Dashboard slow to load

**Diagnosis Steps:**

```bash
# 1. Check for repeated alerts
tail -100 data/processed_alerts.json | \
  jq '.message' | sort | uniq -c | sort -rn

# 2. Check alert frequency
grep "SQL Injection" data/processed_alerts.json | wc -l

# 3. Identify repeating source
grep "203.0.113" data/processed_alerts.json | wc -l
```

**Solutions:**

**A. Enable alert suppression:**
```yaml
# Edit config/suricata.yaml
detect:
  alert-on-each: no  # Don't alert on every packet
  
# Add threshold to rules
# alert tcp ... (msg:"..."; threshold: type limit, track by_src, count 10, seconds 60;)
```

**B. Filter in alert monitor:**
```python
# Edit scripts/alert_monitor.py
# Add deduplication logic
if alert_id in self.processed_alerts:
    return  # Skip duplicate
```

**C. Remove low-value rules:**
```bash
# Comment out rules generating noise
# In rules/custom-rules.rules
# # alert tcp any any -> any any (msg:"noisy rule";...)
```

---

### Issue 7: False Positives (Blocking Legitimate Traffic)

**Symptoms:**
- Legitimate services blocked
- Business impact from blocked IPs
- Users complaining about connectivity issues

**Diagnosis Steps:**

```bash
# 1. Check recently blocked IPs
tail -20 data/blocked_ips.txt

# 2. Check incident tickets
tail -10 data/incident_tickets.json | jq .

# 3. Verify alert legitimacy
grep "203.0.113.50" data/processed_alerts.json | jq '.message' | sort | uniq

# 4. Check whitelist
cat config/whitelist.txt
```

**Solutions:**

**A. Whitelist legitimate IPs:**
```bash
# Edit config/whitelist.txt
# Add IP to prevent blocking
echo "203.0.113.50  # Legitimate partner" >> config/whitelist.txt

# Restart response handler
docker-compose restart response-handler
```

**B. Adjust rule threshold:**
```
# Edit rules to be less sensitive
# Before:
alert tcp any any -> any any (msg:"Scan"; flags:S; threshold:type both, count 5;)

# After:
alert tcp any any -> any any (msg:"Scan"; flags:S; threshold:type both, count 50;)
```

**C. Disable problematic rule:**
```bash
# Comment out rule causing issues in custom-rules.rules
# # alert http ... (msg:"False positive rule";)
```

**D. Manual unblock:**
```bash
# Unblock IP immediately
sudo iptables -D INPUT -s 203.0.113.50 -j DROP

# Update whitelist
echo "203.0.113.50" >> config/whitelist.txt
```

---

### Issue 8: Lost Network Connectivity

**Symptoms:**
- Network interface goes down
- No packets captured
- All services stop

**Diagnosis Steps:**

```bash
# 1. Check interface status
ip link show eth0

# 2. Check interface IP
ip addr show eth0

# 3. Check routes
ip route

# 4. Test connectivity
ping 8.8.8.8

# 5. Check system logs
dmesg | tail -20
```

**Solutions:**

**A. Interface down:**
```bash
# Bring interface up
sudo ip link set eth0 up

# Or restart network
sudo systemctl restart networking

# For Docker
docker-compose restart suricata
```

**B. IP configuration lost:**
```bash
# Check configuration
cat /etc/network/interfaces
# or for netplan
cat /etc/netplan/01-netcfg.yaml

# Restart networking
sudo netplan apply
# or
sudo systemctl restart networking
```

---

## Performance Tuning Tips

### For Better Detection
- Add custom rules for your environment
- Update rule sets regularly
- Fine-tune thresholds based on your network

### For Better Performance
- Disable unused protocol analyzers
- Use smaller rule set
- Enable multithreading
- Increase buffer sizes
- Use SSD for logs

### For Better Reliability
- Monitor disk space
- Archive old logs
- Set up log rotation
- Monitor service health
- Enable auto-restart

---

## Getting More Help

1. **Check Suricata Documentation:**
   https://suricata.readthedocs.io/

2. **Review System Logs:**
   ```bash
   docker logs -f ids-suricata
   docker logs -f ids-monitor
   tail -f /var/log/syslog
   ```

3. **Enable Debug Logging:**
   ```bash
   # Edit suricata.yaml
   logging:
     default-log-level: debug
   
   docker-compose restart suricata
   ```

4. **Test Configuration:**
   ```bash
   suricata -c config/suricata.yaml -T -vvv
   ```

---

Version: 1.0
Last Updated: May 2026
