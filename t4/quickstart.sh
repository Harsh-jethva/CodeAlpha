#!/bin/bash
# Quick Start Script for Network IDS

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Network Intrusion Detection System - Quick Start ===${NC}\n"

# Check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Error: Docker not installed${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Docker installed${NC}"
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}Error: Docker Compose not installed${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Docker Compose installed${NC}"
    
    # Check network interface
    INTERFACE=${1:-eth0}
    if ! ip link show "$INTERFACE" &> /dev/null; then
        echo -e "${RED}Error: Network interface $INTERFACE not found${NC}"
        echo "Available interfaces:"
        ip link show | grep "^[0-9]:" | awk -F: '{print $2}'
        exit 1
    fi
    echo -e "${GREEN}✓ Network interface $INTERFACE available${NC}"
}

# Create directories
create_directories() {
    echo -e "\n${YELLOW}Creating directories...${NC}"
    mkdir -p logs/suricata logs/monitor logs/response logs/dashboard
    mkdir -p data
    chmod 755 logs data
    echo -e "${GREEN}✓ Directories created${NC}"
}

# Update configuration
update_config() {
    local interface=$1
    
    echo -e "\n${YELLOW}Updating configuration for interface: $interface${NC}"
    
    # Update suricata.yaml if interface is not eth0
    if [ "$interface" != "eth0" ]; then
        sed -i "s/eth0/$interface/g" config/suricata.yaml 2>/dev/null || true
        sed -i "s/eth0/$interface/g" docker-compose.yml 2>/dev/null || true
        echo -e "${GREEN}✓ Configuration updated for $interface${NC}"
    fi
}

# Start services
start_services() {
    echo -e "\n${YELLOW}Starting IDS services...${NC}"
    
    docker-compose up -d
    
    echo -e "${GREEN}✓ Services started${NC}"
    
    # Wait for services to be ready
    echo -e "\n${YELLOW}Waiting for services to be ready...${NC}"
    sleep 5
    
    # Check service status
    echo -e "\n${YELLOW}Service Status:${NC}"
    docker-compose ps
}

# Display access information
display_access_info() {
    echo -e "\n${GREEN}=== IDS is Running ===${NC}\n"
    echo "Services:"
    echo -e "  ${GREEN}✓${NC} Suricata IDS (running)"
    echo -e "  ${GREEN}✓${NC} Alert Monitor (running)"
    echo -e "  ${GREEN}✓${NC} Response Handler (running)"
    echo -e "  ${GREEN}✓${NC} Dashboard (http://localhost:5000)"
    
    echo -e "\n${YELLOW}Useful Commands:${NC}"
    echo "  View logs:          docker-compose logs -f"
    echo "  View Suricata logs: docker logs -f ids-suricata"
    echo "  View alerts:        tail -f logs/suricata/alert.log"
    echo "  Stop services:      docker-compose down"
    echo "  View dashboard:     http://localhost:5000"
    
    echo -e "\n${YELLOW}Monitoring:${NC}"
    echo "  Real-time alerts:"
    echo "    tail -f logs/suricata/eve.json | jq ."
    echo ""
    echo "  Processed alerts:"
    echo "    tail -f data/processed_alerts.json | jq ."
    echo ""
}

# Cleanup
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    docker-compose down
    echo -e "${GREEN}✓ Cleanup complete${NC}"
}

# Main execution
main() {
    local interface=${1:-eth0}
    
    # Trap cleanup on exit
    trap cleanup EXIT
    
    check_prerequisites "$interface"
    create_directories
    update_config "$interface"
    start_services
    display_access_info
    
    # Keep script running
    echo -e "\n${YELLOW}Press Ctrl+C to stop all services${NC}\n"
    
    # Monitor services
    while true; do
        sleep 60
        # Check if any service is down
        if ! docker-compose ps | grep -q "ids-suricata.*Up"; then
            echo -e "${RED}Warning: A service is not running${NC}"
            docker-compose ps
        fi
    done
}

# Show help
show_help() {
    echo "Usage: ./quickstart.sh [INTERFACE]"
    echo ""
    echo "Arguments:"
    echo "  INTERFACE  Network interface to monitor (default: eth0)"
    echo ""
    echo "Examples:"
    echo "  ./quickstart.sh              # Monitor eth0"
    echo "  ./quickstart.sh ens0         # Monitor ens0"
    echo ""
    echo "Available interfaces:"
    ip link show | grep "^[0-9]:" | awk -F: '{print "  " $2}'
}

# Handle arguments
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    show_help
    exit 0
fi

# Run main
main "$@"
