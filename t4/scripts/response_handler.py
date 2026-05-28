#!/usr/bin/env python3
"""
Response Handler - Implements automated response mechanisms for detected intrusions
Handles IP blocking, rate limiting, traffic rerouting, and incident logging
"""

import json
import time
import os
import sys
import logging
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('response_handler.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ResponseHandler:
    def __init__(self):
        self.blocked_ips = defaultdict(int)
        self.rate_limited_ips = set()
        self.whitelisted_ips = self.load_whitelist()
        self.incident_log = []
        self.response_history = []
        
    def load_whitelist(self):
        """Load whitelisted IPs that should not be blocked"""
        whitelist = set()
        whitelist_file = 'whitelist.txt'
        
        if os.path.exists(whitelist_file):
            with open(whitelist_file, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        whitelist.add(ip)
                        
        logger.info(f"Loaded {len(whitelist)} whitelisted IPs")
        return whitelist
    
    def check_incident(self, alert_data):
        """Check if alert requires response action"""
        severity = alert_data.get('severity', 3)
        src_ip = alert_data.get('src_ip')
        msg = alert_data.get('message', '')
        
        # Skip whitelisted IPs
        if src_ip in self.whitelisted_ips:
            logger.info(f"Skipping whitelisted IP: {src_ip}")
            return False
        
        # Determine response based on severity and threat type
        if severity == 1 or any(keyword in msg.lower() 
                                for keyword in ['exploit', 'malware', 'injection', 'overflow']):
            return True
        
        return False
    
    def execute_block_ip(self, ip_address, duration=3600):
        """Execute IP block using iptables"""
        if ip_address in self.blocked_ips:
            self.blocked_ips[ip_address] += 1
            logger.warning(f"IP already blocked (block #{self.blocked_ips[ip_address]}): {ip_address}")
            return
        
        try:
            # Create iptables rule (requires root)
            cmd = f"sudo iptables -I INPUT 1 -s {ip_address} -j DROP"
            
            # Log the action without executing (for demonstration)
            logger.info(f"BLOCK ACTION: {cmd}")
            
            # In production, uncomment to actually execute:
            # subprocess.run(cmd, shell=True, check=True)
            
            self.blocked_ips[ip_address] = 1
            
            # Log block action
            self.log_response_action('BLOCK_IP', ip_address, {'duration': duration})
            
            # Schedule unblock if duration specified
            if duration > 0:
                self.schedule_unblock(ip_address, duration)
                logger.info(f"IP {ip_address} will be unblocked in {duration} seconds")
            
        except Exception as e:
            logger.error(f"Failed to block IP {ip_address}: {e}")
    
    def schedule_unblock(self, ip_address, duration):
        """Schedule automatic unblock after duration"""
        # This would typically be handled by a separate scheduler
        # For now, we'll just log the intention
        unblock_time = datetime.now() + timedelta(seconds=duration)
        logger.info(f"Scheduled unblock for {ip_address} at {unblock_time}")
    
    def rate_limit_ip(self, ip_address, limit=10, window=60):
        """Apply rate limiting to IP address"""
        try:
            # Create tc (traffic control) rule
            cmd = f"sudo tc qdisc add dev eth0 root tbf rate {limit}kbit burst 32kbit latency 400ms"
            
            logger.info(f"RATE_LIMIT ACTION: Limiting {ip_address} to {limit}kbit/s")
            
            self.rate_limited_ips.add(ip_address)
            self.log_response_action('RATE_LIMIT', ip_address, {
                'limit': f"{limit}kbit/s",
                'window': window
            })
            
        except Exception as e:
            logger.error(f"Failed to rate limit IP {ip_address}: {e}")
    
    def reroute_traffic(self, src_ip, dest_port, action='drop'):
        """Reroute or drop specific traffic patterns"""
        try:
            if action == 'drop':
                cmd = f"sudo iptables -A FORWARD -s {src_ip} -p tcp --dport {dest_port} -j DROP"
            elif action == 'redirect':
                cmd = f"sudo iptables -A FORWARD -s {src_ip} -p tcp --dport {dest_port} -j REDIRECT --to-port 8080"
            
            logger.info(f"REROUTE ACTION: {cmd}")
            self.log_response_action('REROUTE_TRAFFIC', src_ip, {
                'port': dest_port,
                'action': action
            })
            
        except Exception as e:
            logger.error(f"Failed to reroute traffic: {e}")
    
    def enable_enhanced_logging(self, src_ip):
        """Enable enhanced logging for suspicious source"""
        try:
            cmd = f"sudo iptables -A INPUT -s {src_ip} -j LOG --log-prefix 'SUSPICIOUS: '"
            
            logger.info(f"ENHANCED_LOGGING ACTION: {cmd}")
            self.log_response_action('ENHANCED_LOGGING', src_ip, {})
            
        except Exception as e:
            logger.error(f"Failed to enable enhanced logging: {e}")
    
    def create_incident_ticket(self, alert_data):
        """Create incident ticket for manual review"""
        incident = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': alert_data.get('src_ip'),
            'threat': alert_data.get('message'),
            'severity': alert_data.get('severity'),
            'status': 'open',
            'ticket_id': f"INC-{int(time.time())}"
        }
        
        self.incident_log.append(incident)
        
        logger.info(f"Created incident ticket: {incident['ticket_id']}")
        
        # Write to file
        with open('incident_tickets.json', 'a') as f:
            f.write(json.dumps(incident) + '\n')
    
    def log_response_action(self, action_type, target, details):
        """Log all response actions taken"""
        action_record = {
            'timestamp': datetime.now().isoformat(),
            'action': action_type,
            'target': target,
            'details': details,
            'status': 'executed'
        }
        
        self.response_history.append(action_record)
        
        with open('response_actions.json', 'a') as f:
            f.write(json.dumps(action_record) + '\n')
    
    def process_alert(self, alert_data):
        """Process alert and determine response"""
        if not self.check_incident(alert_data):
            return
        
        src_ip = alert_data.get('src_ip')
        severity = alert_data.get('severity', 3)
        msg = alert_data.get('message', '')
        
        logger.info(f"Processing response for: {src_ip} - {msg}")
        
        # Response strategy based on severity
        if severity == 1:
            # Critical - immediate block
            self.execute_block_ip(src_ip, duration=3600)
            self.enable_enhanced_logging(src_ip)
            self.create_incident_ticket(alert_data)
            
        elif severity == 2:
            # High - block for limited time
            self.execute_block_ip(src_ip, duration=600)
            self.create_incident_ticket(alert_data)
            
        else:
            # Medium/Low - rate limit and enhanced logging
            self.rate_limit_ip(src_ip)
            self.enable_enhanced_logging(src_ip)
        
        # Always log the response
        self.log_response_action('ALERT_PROCESSED', src_ip, {
            'severity': severity,
            'threat': msg
        })
    
    def monitor_alerts(self, alert_file='processed_alerts.json'):
        """Monitor and process alerts from alert monitor"""
        processed = set()
        
        logger.info("Response Handler started")
        logger.info(f"Monitoring: {alert_file}")
        
        try:
            while True:
                if os.path.exists(alert_file):
                    with open(alert_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                try:
                                    alert = json.loads(line)
                                    alert_id = f"{alert['timestamp']}-{alert['src_ip']}"
                                    
                                    if alert_id not in processed:
                                        self.process_alert(alert)
                                        processed.add(alert_id)
                                        
                                except json.JSONDecodeError:
                                    continue
                
                # Print statistics
                self.print_statistics()
                time.sleep(10)
                
        except KeyboardInterrupt:
            logger.info("Response Handler stopped by user")
            self.print_statistics()
    
    def print_statistics(self):
        """Print response statistics"""
        if len(self.blocked_ips) % 5 == 0 and len(self.blocked_ips) > 0:
            logger.info("=" * 60)
            logger.info("RESPONSE STATISTICS")
            logger.info(f"Blocked IPs: {len(self.blocked_ips)}")
            logger.info(f"Rate limited IPs: {len(self.rate_limited_ips)}")
            logger.info(f"Open incidents: {len([i for i in self.incident_log if i['status'] == 'open'])}")
            logger.info(f"Total response actions: {len(self.response_history)}")
            logger.info("=" * 60)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='IDS Response Handler')
    parser.add_argument('--alert-file', default='processed_alerts.json',
                        help='Path to processed alerts file')
    
    args = parser.parse_args()
    
    handler = ResponseHandler()
    handler.monitor_alerts(alert_file=args.alert_file)

if __name__ == '__main__':
    main()
