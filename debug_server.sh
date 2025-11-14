#!/bin/bash

# SecTools Server Debug Script
# Service: puma-sectools
# Directory: /var/www/sectools.whoisjoe.com

set -e

echo "=================================="
echo "SecTools Server Debug Script"
echo "=================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SERVICE_NAME="puma-sectools"
APP_DIR="/var/www/sectools.whoisjoe.com"

echo "Service: $SERVICE_NAME"
echo "App Directory: $APP_DIR"
echo ""

# Function to print section headers
print_header() {
    echo ""
    echo "=================================="
    echo "$1"
    echo "=================================="
}

# Function to check if running as root/sudo
check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}Note: Some commands may require sudo${NC}"
    fi
}

# Check systemd service status
print_header "1. Service Status"
if systemctl is-active --quiet $SERVICE_NAME 2>/dev/null; then
    echo -e "${GREEN}✓ Service is running${NC}"
    systemctl status $SERVICE_NAME --no-pager -l | head -20
else
    echo -e "${RED}✗ Service is not running${NC}"
    systemctl status $SERVICE_NAME --no-pager -l 2>&1 | head -20 || echo "Could not get service status"
fi

# Check if service is enabled
print_header "2. Service Auto-start Status"
if systemctl is-enabled --quiet $SERVICE_NAME 2>/dev/null; then
    echo -e "${GREEN}✓ Service is enabled (will start on boot)${NC}"
else
    echo -e "${YELLOW}! Service is not enabled${NC}"
fi

# Check recent journal logs
print_header "3. Recent Service Logs (last 50 lines)"
if command -v journalctl &> /dev/null; then
    journalctl -u $SERVICE_NAME -n 50 --no-pager 2>&1 || echo "Could not read journal logs"
else
    echo "journalctl not available"
fi

# Check application directory
print_header "4. Application Directory"
if [ -d "$APP_DIR" ]; then
    echo -e "${GREEN}✓ Directory exists${NC}"
    echo "Path: $APP_DIR"
    echo "Owner: $(stat -c '%U:%G' $APP_DIR 2>/dev/null || stat -f '%Su:%Sg' $APP_DIR 2>/dev/null)"
    echo "Permissions: $(stat -c '%a' $APP_DIR 2>/dev/null || stat -f '%A' $APP_DIR 2>/dev/null)"
else
    echo -e "${RED}✗ Directory not found${NC}"
fi

# Check Rails environment
print_header "5. Rails Application Files"
if [ -f "$APP_DIR/config/environment.rb" ]; then
    echo -e "${GREEN}✓ Rails application found${NC}"

    # Check for key files
    echo ""
    echo "Key Files:"
    [ -f "$APP_DIR/Gemfile" ] && echo "  ✓ Gemfile" || echo "  ✗ Gemfile missing"
    [ -f "$APP_DIR/Gemfile.lock" ] && echo "  ✓ Gemfile.lock" || echo "  ✗ Gemfile.lock missing"
    [ -f "$APP_DIR/config/database.yml" ] && echo "  ✓ database.yml" || echo "  ✗ database.yml missing"
    [ -f "$APP_DIR/config/puma.rb" ] && echo "  ✓ puma.rb" || echo "  ✗ puma.rb missing"
    [ -d "$APP_DIR/tmp/pids" ] && echo "  ✓ tmp/pids directory" || echo "  ✗ tmp/pids directory missing"
else
    echo -e "${RED}✗ Rails application not found${NC}"
fi

# Check for PID file
print_header "6. Process ID (PID) File"
PID_FILE="$APP_DIR/tmp/pids/server.pid"
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    echo "PID file exists: $PID_FILE"
    echo "PID: $PID"

    if ps -p $PID > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Process is running${NC}"
        echo ""
        ps aux | grep -E "PID|$PID" | grep -v grep
    else
        echo -e "${RED}✗ Process not running (stale PID file)${NC}"
        echo "Recommendation: Remove stale PID file with: rm $PID_FILE"
    fi
else
    echo "No PID file found at: $PID_FILE"
fi

# Check for Puma processes
print_header "7. Running Puma Processes"
PUMA_PROCS=$(ps aux | grep -i puma | grep -v grep || true)
if [ -n "$PUMA_PROCS" ]; then
    echo -e "${GREEN}Found Puma processes:${NC}"
    echo "$PUMA_PROCS"
else
    echo -e "${YELLOW}No Puma processes found${NC}"
fi

# Check for Ruby processes
print_header "8. Running Ruby Processes"
RUBY_PROCS=$(ps aux | grep -E "ruby|rails" | grep -v grep | head -10 || true)
if [ -n "$RUBY_PROCS" ]; then
    echo "Ruby/Rails processes:"
    echo "$RUBY_PROCS"
else
    echo "No Ruby processes found"
fi

# Check port binding
print_header "9. Port Usage (Common Rails Ports)"
echo "Checking ports 3000, 80, 443..."
for port in 3000 80 443; do
    echo ""
    echo "Port $port:"
    if command -v lsof &> /dev/null; then
        lsof -i :$port 2>/dev/null || echo "  Not in use"
    elif command -v netstat &> /dev/null; then
        netstat -tuln | grep ":$port " || echo "  Not in use"
    elif command -v ss &> /dev/null; then
        ss -tuln | grep ":$port " || echo "  Not in use"
    else
        echo "  No port checking tools available"
    fi
done

# Check recent application logs
print_header "10. Application Logs"
LOG_FILE="$APP_DIR/log/production.log"
if [ -f "$LOG_FILE" ]; then
    echo "Last 30 lines of production.log:"
    echo ""
    tail -30 "$LOG_FILE"
else
    echo "Production log not found at: $LOG_FILE"
    echo ""
    echo "Available log files:"
    ls -lh "$APP_DIR/log/" 2>/dev/null || echo "Log directory not accessible"
fi

# Check disk space
print_header "11. Disk Space"
df -h "$APP_DIR" 2>/dev/null || df -h /

# Check Ruby version
print_header "12. Ruby Environment"
if [ -f "$APP_DIR/.ruby-version" ]; then
    echo "Required Ruby version: $(cat $APP_DIR/.ruby-version)"
fi
echo "Current Ruby version: $(ruby --version 2>/dev/null || echo 'Ruby not found in PATH')"
echo "Current Bundler version: $(bundle --version 2>/dev/null || echo 'Bundler not found')"

# Check database
print_header "13. Database Status"
if [ -f "$APP_DIR/config/database.yml" ]; then
    echo "Database configuration exists"
    # Check for SQLite database
    if [ -f "$APP_DIR/db/production.sqlite3" ]; then
        echo -e "${GREEN}✓ SQLite database found${NC}"
        ls -lh "$APP_DIR/db/production.sqlite3"
    fi
fi

# Quick fixes section
print_header "14. Quick Fix Commands"
echo ""
echo "If the service is not running, try these commands:"
echo ""
echo -e "${YELLOW}1. Restart the service:${NC}"
echo "   sudo systemctl restart $SERVICE_NAME"
echo ""
echo -e "${YELLOW}2. View live logs:${NC}"
echo "   sudo journalctl -u $SERVICE_NAME -f"
echo ""
echo -e "${YELLOW}3. Check service configuration:${NC}"
echo "   systemctl cat $SERVICE_NAME"
echo ""
echo -e "${YELLOW}4. Remove stale PID file (if needed):${NC}"
echo "   rm $APP_DIR/tmp/pids/server.pid"
echo ""
echo -e "${YELLOW}5. Manually start in foreground (for debugging):${NC}"
echo "   cd $APP_DIR && RAILS_ENV=production bundle exec puma -C config/puma.rb"
echo ""
echo -e "${YELLOW}6. Check for errors in Rails console:${NC}"
echo "   cd $APP_DIR && RAILS_ENV=production bundle exec rails console"
echo ""
echo -e "${YELLOW}7. View systemd service file:${NC}"
echo "   cat /etc/systemd/system/$SERVICE_NAME.service"
echo ""

print_header "Debug Script Complete"
echo ""
echo "For more help, check:"
echo "  - systemd logs: journalctl -xe"
echo "  - application logs: $APP_DIR/log/"
echo "  - systemd service: systemctl cat $SERVICE_NAME"
echo ""

check_sudo
