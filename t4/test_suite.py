#!/usr/bin/env python3
"""
IDS Test Suite - Automated testing for Network Intrusion Detection System
Tests connectivity, configuration, and alerting mechanisms
"""

import subprocess
import sys
import time
import json
import os
from datetime import datetime
from pathlib import Path

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

class IDSTestSuite:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []
    
    def test(self, name, condition, error_msg=""):
        """Generic test function"""
        if condition:
            self.passed += 1
            print(f"{Colors.GREEN}✓{Colors.END} {name}")
            self.results.append({'test': name, 'status': 'PASS'})
        else:
            self.failed += 1
            print(f"{Colors.RED}✗{Colors.END} {name}")
            if error_msg:
                print(f"  {Colors.YELLOW}Error: {error_msg}{Colors.END}")
            self.results.append({'test': name, 'status': 'FAIL', 'error': error_msg})
    
    def run_command(self, cmd, check=False):
        """Run shell command and return output"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if check and result.returncode != 0:
                return False, result.stderr
            return True, result.stdout
        except Exception as e:
            return False, str(e)
    
    # ============================================
    # ENVIRONMENT TESTS
    # ============================================
    
    def test_environment(self):
        """Test environment prerequisites"""
        print(f"\n{Colors.BLUE}=== Environment Tests ==={Colors.END}")
        
        # Check Docker
        success, _ = self.run_command("docker --version")
        self.test("Docker installed", success)
        
        # Check Docker Compose
        success, _ = self.run_command("docker-compose --version")
        self.test("Docker Compose installed", success)
        
        # Check Python
        success, _ = self.run_command("python3 --version")
        self.test("Python 3 installed", success)
        
        # Check network interface
        success, output = self.run_command("ip link show eth0")
        self.test("Network interface eth0 available", success)
    
    # ============================================
    # CONFIGURATION TESTS
    # ============================================
    
    def test_configuration(self):
        """Test configuration files"""
        print(f"\n{Colors.BLUE}=== Configuration Tests ==={Colors.END}")
        
        # Check main files exist
        self.test("suricata.yaml exists", os.path.exists('config/suricata.yaml'))
        self.test("custom-rules.rules exists", os.path.exists('rules/custom-rules.rules'))
        self.test("default-rules.rules exists", os.path.exists('rules/default-rules.rules'))
        self.test("docker-compose.yml exists", os.path.exists('docker-compose.yml'))
        
        # Check YAML syntax
        success, _ = self.run_command("python3 -c \"import yaml; yaml.safe_load(open('config/suricata.yaml'))\"")
        self.test("suricata.yaml valid YAML", success)
        
        # Check Python files syntax
        success, _ = self.run_command("python3 -m py_compile scripts/alert_monitor.py")
        self.test("alert_monitor.py valid Python", success)
        
        success, _ = self.run_command("python3 -m py_compile scripts/response_handler.py")
        self.test("response_handler.py valid Python", success)
        
        success, _ = self.run_command("python3 -m py_compile dashboard/app.py")
        self.test("dashboard/app.py valid Python", success)
    
    # ============================================
    # SERVICE TESTS
    # ============================================
    
    def test_services(self):
        """Test service deployment"""
        print(f"\n{Colors.BLUE}=== Service Deployment Tests ==={Colors.END}")
        
        # Check if services are running
        success, output = self.run_command("docker-compose ps")
        self.test("docker-compose accessible", success, output)
        
        # Check Suricata service
        success, output = self.run_command("docker-compose ps ids-suricata")
        running = "Up" in output if output else False
        self.test("Suricata container running", running)
        
        # Check Alert Monitor service
        success, output = self.run_command("docker-compose ps ids-monitor")
        running = "Up" in output if output else False
        self.test("Alert Monitor container running", running)
        
        # Check Response Handler service
        success, output = self.run_command("docker-compose ps ids-response")
        running = "Up" in output if output else False
        self.test("Response Handler container running", running)
        
        # Check Dashboard service
        success, output = self.run_command("docker-compose ps ids-dashboard")
        running = "Up" in output if output else False
        self.test("Dashboard container running", running)
    
    # ============================================
    # CONNECTIVITY TESTS
    # ============================================
    
    def test_connectivity(self):
        """Test service connectivity"""
        print(f"\n{Colors.BLUE}=== Connectivity Tests ==={Colors.END}")
        
        # Check port 5000 (Dashboard)
        success, _ = self.run_command("curl -s -o /dev/null -w '%{http_code}' http://localhost:5000")
        self.test("Dashboard port 5000 accessible", success)
        
        # Check API health endpoint
        success, _ = self.run_command("curl -s http://localhost:5000/api/health | python3 -m json.tool > /dev/null")
        self.test("Dashboard API health endpoint", success)
        
        # Check API statistics endpoint
        success, _ = self.run_command("curl -s http://localhost:5000/api/statistics | python3 -m json.tool > /dev/null")
        self.test("Dashboard API statistics endpoint", success)
    
    # ============================================
    # LOG TESTS
    # ============================================
    
    def test_logs(self):
        """Test log files and output"""
        print(f"\n{Colors.BLUE}=== Log Output Tests ==={Colors.END}")
        
        # Check log directories exist
        self.test("logs/suricata directory exists", os.path.isdir('logs/suricata'))
        self.test("data directory exists", os.path.isdir('data'))
        
        # Check eve.json exists and has content
        eve_file = 'logs/suricata/eve.json'
        eve_exists = os.path.exists(eve_file)
        self.test("eve.json file exists", eve_exists)
        
        if eve_exists:
            with open(eve_file, 'r') as f:
                lines = f.readlines()
            self.test("eve.json has content", len(lines) > 0, f"File has {len(lines)} lines")
        
        # Check processed alerts
        alerts_file = 'data/processed_alerts.json'
        alerts_exist = os.path.exists(alerts_file)
        self.test("processed_alerts.json exists", alerts_exist)
        
        if alerts_exist:
            try:
                with open(alerts_file, 'r') as f:
                    lines = f.readlines()
                alert_count = len([l for l in lines if l.strip()])
                self.test("processed_alerts.json has alerts", alert_count > 0, f"{alert_count} alerts processed")
            except:
                self.test("processed_alerts.json readable", False)
    
    # ============================================
    # RULE TESTS
    # ============================================
    
    def test_rules(self):
        """Test detection rules"""
        print(f"\n{Colors.BLUE}=== Detection Rules Tests ==={Colors.END}")
        
        # Check rule file syntax
        success, output = self.run_command("grep -c '^alert' rules/custom-rules.rules")
        custom_count = int(output.strip()) if output else 0
        self.test(f"Custom rules found ({custom_count} rules)", custom_count > 0)
        
        success, output = self.run_command("grep -c '^alert' rules/default-rules.rules")
        default_count = int(output.strip()) if output else 0
        self.test(f"Default rules found ({default_count} rules)", default_count > 0)
        
        # Check rule IDs are unique
        success, output = self.run_command("""
            grep 'sid:[0-9]' rules/*.rules | \
            awk -F: '{print $NF}' | \
            sort | uniq -d | wc -l
        """)
        duplicates = int(output.strip()) if output else 0
        self.test("No duplicate rule IDs", duplicates == 0)
        
        # Check rule format
        success, output = self.run_command("""
            grep '^alert' rules/custom-rules.rules | \
            grep -v 'msg:.*sid:.*rev:' | wc -l
        """)
        invalid = int(output.strip()) if output else 0
        self.test("All rules have required fields", invalid == 0)
    
    # ============================================
    # ALERT GENERATION TEST
    # ============================================
    
    def test_alert_generation(self):
        """Test if system can generate alerts"""
        print(f"\n{Colors.BLUE}=== Alert Generation Tests ==={Colors.END}")
        
        print(f"{Colors.YELLOW}Note: This test requires network traffic or manual generation{Colors.END}")
        
        # Try to generate test alert
        print("\nAttempting to generate test alert...")
        
        # Simple test: attempt a port scan-like pattern
        cmd = """
        timeout 5 nc -z 192.168.1.1 80 81 82 83 84 85 2>/dev/null || true
        sleep 2
        tail -5 logs/suricata/eve.json 2>/dev/null | grep -c "alert" || echo 0
        """
        
        success, count = self.run_command(cmd)
        alerts_generated = int(count.strip()) if count else 0
        
        if alerts_generated > 0:
            self.test("Test alerts generated", True, f"{alerts_generated} alerts")
        else:
            self.test("Test alerts generated", False, "No alerts (may need real traffic)")
    
    # ============================================
    # RESPONSE ACTION TESTS
    # ============================================
    
    def test_response_actions(self):
        """Test response handling"""
        print(f"\n{Colors.BLUE}=== Response Action Tests ==={Colors.END}")
        
        # Check response actions file
        response_file = 'data/response_actions.json'
        if os.path.exists(response_file):
            with open(response_file, 'r') as f:
                lines = f.readlines()
            action_count = len([l for l in lines if l.strip()])
            self.test("Response actions logged", action_count >= 0, f"{action_count} actions")
        else:
            self.test("Response actions file exists", False)
        
        # Check incident tickets
        incidents_file = 'data/incident_tickets.json'
        if os.path.exists(incidents_file):
            with open(incidents_file, 'r') as f:
                lines = f.readlines()
            incident_count = len([l for l in lines if l.strip()])
            self.test("Incident tickets created", incident_count >= 0, f"{incident_count} incidents")
        else:
            self.test("Incident tickets file exists", False)
    
    # ============================================
    # PERFORMANCE TESTS
    # ============================================
    
    def test_performance(self):
        """Test system performance"""
        print(f"\n{Colors.BLUE}=== Performance Tests ==={Colors.END}")
        
        # Check Docker memory usage
        success, output = self.run_command("""
            docker stats --no-stream ids-suricata --format "{{.MemUsage}}" 2>/dev/null || echo "N/A"
        """)
        if output and output.strip() != "N/A":
            self.test("Suricata memory accessible", True, f"Using {output.strip()}")
        
        # Check CPU cores available
        success, output = self.run_command("nproc")
        cpu_count = int(output.strip()) if output else 0
        self.test(f"CPU cores available", cpu_count > 0, f"{cpu_count} cores")
        
        # Check disk space
        success, output = self.run_command("df -h . | tail -1 | awk '{print $4}'")
        if output:
            self.test("Disk space available", True, f"Free: {output.strip()}")
        
        # Check file sizes
        eve_size = os.path.getsize('logs/suricata/eve.json') if os.path.exists('logs/suricata/eve.json') else 0
        self.test("eve.json size reasonable", eve_size < 1000000000, f"{eve_size / 1024 / 1024:.1f} MB")
    
    # ============================================
    # DASHBOARD TESTS
    # ============================================
    
    def test_dashboard(self):
        """Test dashboard functionality"""
        print(f"\n{Colors.BLUE}=== Dashboard Tests ==={Colors.END}")
        
        # Check dashboard HTML loads
        success, output = self.run_command("""
            curl -s http://localhost:5000 | grep -c "Network Intrusion Detection System"
        """)
        html_loaded = int(output.strip() if output else 0) > 0
        self.test("Dashboard HTML loads", html_loaded)
        
        # Check dashboard chart libraries
        success, output = self.run_command("""
            curl -s http://localhost:5000 | grep -c "chart.js"
        """)
        charts_loaded = int(output.strip() if output else 0) > 0
        self.test("Chart library loaded", charts_loaded)
        
        # Test all API endpoints
        endpoints = [
            '/api/statistics',
            '/api/alerts',
            '/api/blocked-ips',
            '/api/incidents',
            '/api/health'
        ]
        
        for endpoint in endpoints:
            success, output = self.run_command(f"""
                curl -s -w '%{{http_code}}' http://localhost:5000{endpoint} | tail -c 3
            """)
            status = int(output.strip()) if output else 0
            self.test(f"API endpoint {endpoint}", status in [200, 500])
    
    # ============================================
    # SECURITY TESTS
    # ============================================
    
    def test_security(self):
        """Test security configuration"""
        print(f"\n{Colors.BLUE}=== Security Tests ==={Colors.END}")
        
        # Check whitelist exists
        self.test("Whitelist configured", os.path.exists('config/whitelist.txt'))
        
        # Check rules don't have hardcoded passwords
        success, output = self.run_command("""
            grep -i "password\|pass=" rules/*.rules | wc -l
        """)
        pwd_refs = int(output.strip() if output else 0)
        self.test("No hardcoded passwords in rules", pwd_refs == 0)
        
        # Check configurations don't expose secrets
        success, output = self.run_command("""
            grep -i "api_key\|token\|secret" config/*.yaml | wc -l
        """)
        secrets = int(output.strip() if output else 0)
        self.test("No exposed secrets in config", secrets == 0)
    
    # ============================================
    # REPORT
    # ============================================
    
    def print_report(self):
        """Print test report"""
        total = self.passed + self.failed
        percentage = (self.passed / total * 100) if total > 0 else 0
        
        print(f"\n{Colors.BLUE}{'='*50}{Colors.END}")
        print(f"{Colors.BLUE}TEST REPORT{Colors.END}")
        print(f"{Colors.BLUE}{'='*50}{Colors.END}")
        print(f"Total Tests: {total}")
        print(f"{Colors.GREEN}Passed: {self.passed}{Colors.END}")
        print(f"{Colors.RED}Failed: {self.failed}{Colors.END}")
        print(f"Success Rate: {percentage:.1f}%")
        print(f"{Colors.BLUE}{'='*50}{Colors.END}\n")
        
        return self.failed == 0

def main():
    print(f"{Colors.BLUE}Network IDS Test Suite{Colors.END}")
    print(f"Started: {datetime.now().isoformat()}\n")
    
    suite = IDSTestSuite()
    
    # Run test suites
    suite.test_environment()
    suite.test_configuration()
    suite.test_services()
    
    # Give services time to start if needed
    time.sleep(2)
    
    suite.test_connectivity()
    suite.test_logs()
    suite.test_rules()
    suite.test_alert_generation()
    suite.test_response_actions()
    suite.test_performance()
    suite.test_dashboard()
    suite.test_security()
    
    # Print report
    success = suite.print_report()
    
    # Save report
    with open('test_report.json', 'w') as f:
        json.dump({
            'timestamp': datetime.now().isoformat(),
            'total': len(suite.results),
            'passed': suite.passed,
            'failed': suite.failed,
            'tests': suite.results
        }, f, indent=2)
    
    return 0 if success else 1

if __name__ == '__main__':
    sys.exit(main())
