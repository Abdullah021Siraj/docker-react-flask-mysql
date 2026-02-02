#!/bin/bash

# =====================================================================
# ENHANCED SERVER COMPLIANCE & SECURITY AUDIT SCRIPT
# Version: 2.2 (With Log Rotation)
# Frameworks: CIS Benchmarks, PCI-DSS, NIST CSF
# =====================================================================

# COLORS
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ERROR HANDLING
set -o pipefail

# --- CONFIGURATION ---
# Ports allowed to be open to the WORLD (0.0.0.0)
GLOBAL_ALLOW_LIST=("22" "80" "443")

# LOGGING & ROTATION CONFIG
# Directory to store audit logs
LOG_DIR="/var/log/server_audit"
# How many days to keep logs before deleting them
LOG_RETENTION_DAYS=30
# Current Log File Name
LOG_FILE="/var/log/server_audit/audit.log"

# Statistics counters
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
INFO_COUNT=0
# ---------------------

# PRIVILEGE CHECK
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}ERROR: This script must be run as root (or with sudo)${NC}" 
   echo "Usage: sudo $0"
   exit 1
fi

# COMMAND AVAILABILITY CHECK
check_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo -e "${RED}ERROR: Required command '$1' not found${NC}"
        echo "Install it with: apt install $2 (Debian/Ubuntu) or yum install $2 (RHEL/CentOS)"
        exit 1
    fi
}

check_command "ss" "iproute2"
check_command "awk" "gawk"
check_command "stat" "coreutils"

# =========================================================
# LOG MANAGEMENT & ROTATION
# =========================================================
# 1. Create Log Directory if not exists
if [ ! -d "$LOG_DIR" ]; then
    mkdir -p "$LOG_DIR"
    chmod 700 "$LOG_DIR" # Secure the directory (root only)
fi

# 2. Perform Log Rotation (Cleanup old logs)
echo -e "${BLUE}Performing log rotation (Retention: $LOG_RETENTION_DAYS days)...${NC}"
# Find files in LOG_DIR ending in .log, older than X days, and delete them
find "$LOG_DIR" -name "audit_*.log" -type f -mtime +$LOG_RETENTION_DAYS -delete

# 3. Start Logging
exec > >(tee -a "$LOG_FILE")
exec 2>&1

clear
echo -e "${YELLOW}======================================================${NC}"
echo -e "${YELLOW}   ENHANCED SERVER COMPLIANCE & SECURITY AUDIT       ${NC}"
echo -e "${YELLOW}======================================================${NC}"
echo "Hostname:   $(hostname)"
echo "Kernel:     $(uname -r)"
echo "Date:       $(date)"
echo "Log File:   $LOG_FILE"
echo "Retention:  $LOG_RETENTION_DAYS days"
echo -e "------------------------------------------------------\n"

# HELPER FUNCTION FOR OUTPUT
log_result() {
    local status=$1
    local ref=$2
    local msg=$3
    local fix=$4

    if [ "$status" == "PASS" ]; then
        echo -e "[ ${GREEN}PASS${NC} ] [${ref}] $msg"
        ((PASS_COUNT++))
    elif [ "$status" == "INFO" ]; then
        echo -e "[ ${BLUE}INFO${NC} ] [${ref}] $msg"
        ((INFO_COUNT++))
    elif [ "$status" == "WARN" ]; then
        echo -e "[ ${YELLOW}WARN${NC} ] [${ref}] $msg"
        ((WARN_COUNT++))
        [ -n "$fix" ] && echo -e "         L__ Fix: $fix"
    else
        echo -e "[ ${RED}FAIL${NC} ] [${ref}] $msg"
        ((FAIL_COUNT++))
        [ -n "$fix" ] && echo -e "         L__ Fix: $fix"
    fi
}

# HELPER FUNCTION FOR FILE PERMISSION CHECK
check_file_perms() {
    local file=$1
    local expected=$2
    local ref=$3
    
    if [ -f "$file" ]; then
        ACTUAL=$(stat -c "%a" "$file")
        if [[ "$ACTUAL" -le "$expected" ]]; then
            log_result "PASS" "$ref" "$file permissions secure ($ACTUAL)" ""
        else
            log_result "FAIL" "$ref" "$file too permissive ($ACTUAL)" "chmod $expected $file"
        fi
    else
        log_result "INFO" "$ref" "$file not found (may be normal in containers)" ""
    fi
}

# HELPER FUNCTION FOR SYSCTL CHECK
check_sysctl() {
    local param=$1
    local expected=$2
    local ref=$3
    
    ACTUAL=$(sysctl -n "$param" 2>/dev/null || echo "not_set")
    if [[ "$ACTUAL" == "$expected" ]]; then
        log_result "PASS" "$ref" "$param = $expected" ""
    else
        log_result "FAIL" "$ref" "$param = $ACTUAL (expected $expected)" "sysctl -w $param=$expected && add to /etc/sysctl.conf"
    fi
}

# =========================================================
# PART 1: SSH HARDENING (CIS Benchmarks)
# =========================================================
echo -e "${CYAN}>>> PART 1: SSH CONFIGURATION HARDENING${NC}"

if [ -f /etc/ssh/sshd_config ]; then
    # Root Login
    ROOT_CONFIG=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
    if [[ "$ROOT_CONFIG" == "no" ]]; then
        log_result "PASS" "CIS 5.2.10" "Root Login is disabled" ""
    else
        log_result "FAIL" "CIS 5.2.10" "Root Login is '$ROOT_CONFIG'" "Set 'PermitRootLogin no' in sshd_config"
    fi

    # Password Authentication
    PASS_CONFIG=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')
    if [[ "$PASS_CONFIG" == "no" ]]; then
        log_result "PASS" "CIS 5.2.9" "Password Authentication is disabled" ""
    else
        log_result "FAIL" "CIS 5.2.9" "Password Authentication is enabled" "Set 'PasswordAuthentication no' and use SSH keys"
    fi

    # Protocol Version
    PROTOCOL=$(grep "^Protocol" /etc/ssh/sshd_config | awk '{print $2}')
    if [[ "$PROTOCOL" == "2" ]] || [[ -z "$PROTOCOL" ]]; then
        log_result "PASS" "CIS 5.2.3" "SSH Protocol 2 (or default)" ""
    else
        log_result "FAIL" "CIS 5.2.3" "Insecure SSH Protocol $PROTOCOL" "Set 'Protocol 2'"
    fi

    # X11 Forwarding
    X11=$(grep "^X11Forwarding" /etc/ssh/sshd_config | awk '{print $2}')
    if [[ "$X11" == "no" ]]; then
        log_result "PASS" "CIS 5.2.6" "X11 Forwarding disabled" ""
    else
        log_result "WARN" "CIS 5.2.6" "X11 Forwarding is ${X11:-enabled}" "Set 'X11Forwarding no' unless required"
    fi

    # Max Authentication Tries
    MAX_AUTH=$(grep "^MaxAuthTries" /etc/ssh/sshd_config | awk '{print $2}')
    if [[ -n "$MAX_AUTH" ]] && [[ "$MAX_AUTH" -le 4 ]]; then
        log_result "PASS" "CIS 5.2.5" "MaxAuthTries is $MAX_AUTH" ""
    else
        log_result "FAIL" "CIS 5.2.5" "MaxAuthTries is ${MAX_AUTH:-not set} (should be <=4)" "Set 'MaxAuthTries 4'"
    fi

    # Empty Passwords
    EMPTY_PASS=$(grep "^PermitEmptyPasswords" /etc/ssh/sshd_config | awk '{print $2}')
    if [[ "$EMPTY_PASS" == "no" ]] || [[ -z "$EMPTY_PASS" ]]; then
        log_result "PASS" "CIS 5.2.8" "Empty passwords prohibited" ""
    else
        log_result "FAIL" "CIS 5.2.8" "Empty passwords permitted" "Set 'PermitEmptyPasswords no'"
    fi

    # Client Alive Interval (session timeout)
    CLIENT_ALIVE=$(grep "^ClientAliveInterval" /etc/ssh/sshd_config | awk '{print $2}')
    if [[ -n "$CLIENT_ALIVE" ]] && [[ "$CLIENT_ALIVE" -gt 0 ]] && [[ "$CLIENT_ALIVE" -le 300 ]]; then
        log_result "PASS" "CIS 5.2.16" "SSH timeout configured ($CLIENT_ALIVE seconds)" ""
    else
        log_result "WARN" "CIS 5.2.16" "SSH timeout not configured" "Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 0'"
    fi
else
    log_result "INFO" "N/A" "SSH config not found (container or SSH not installed)" ""
fi

echo -e "\n------------------------------------------------------"

# =========================================================
# PART 2: FILE PERMISSIONS (CIS Benchmarks)
# =========================================================
echo -e "${CYAN}>>> PART 2: CRITICAL FILE PERMISSIONS${NC}"

check_file_perms "/etc/passwd" 644 "CIS 6.1.1"
check_file_perms "/etc/shadow" 600 "CIS 6.1.2"
check_file_perms "/etc/group" 644 "CIS 6.1.3"
check_file_perms "/etc/gshadow" 600 "CIS 6.1.4"
check_file_perms "/etc/ssh/sshd_config" 600 "CIS 5.2.1"

if [ -f /boot/grub/grub.cfg ]; then
    check_file_perms "/boot/grub/grub.cfg" 600 "CIS 1.4.1"
elif [ -f /boot/grub2/grub.cfg ]; then
    check_file_perms "/boot/grub2/grub.cfg" 600 "CIS 1.4.1"
fi

echo -e "\n------------------------------------------------------"

# =========================================================
# PART 3: USER ACCOUNT SECURITY
# =========================================================
echo -e "${CYAN}>>> PART 3: USER ACCOUNT SECURITY${NC}"

# Check for UID 0 accounts (should only be root)
NON_ROOT_UID0=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
if [[ -z "$NON_ROOT_UID0" ]]; then
    log_result "PASS" "CIS 6.2.1" "Only root has UID 0" ""
else
    log_result "FAIL" "CIS 6.2.1" "Non-root accounts with UID 0: $NON_ROOT_UID0" "Remove or change UID"
fi

# Password aging policy
if [ -f /etc/login.defs ]; then
    MAX_DAYS=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
    if [[ -n "$MAX_DAYS" ]] && [[ "$MAX_DAYS" -le 90 ]]; then
        log_result "PASS" "CIS 5.4.1.1" "Password max age: $MAX_DAYS days" ""
    else
        log_result "FAIL" "CIS 5.4.1.1" "Password max age is ${MAX_DAYS:-not set} (should be <=90)" "Set PASS_MAX_DAYS 90 in /etc/login.defs"
    fi

    MIN_DAYS=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
    if [[ -n "$MIN_DAYS" ]] && [[ "$MIN_DAYS" -ge 1 ]]; then
        log_result "PASS" "CIS 5.4.1.2" "Password min age: $MIN_DAYS days" ""
    else
        log_result "WARN" "CIS 5.4.1.2" "Password min age not enforced" "Set PASS_MIN_DAYS 1"
    fi
fi

# Check for accounts with empty passwords
if [ -f /etc/shadow ]; then
    EMPTY_PASS_USERS=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
    if [[ -z "$EMPTY_PASS_USERS" ]]; then
        log_result "PASS" "CIS 5.4.1" "No accounts with empty passwords" ""
    else
        log_result "FAIL" "CIS 5.4.1" "Accounts with empty passwords: $EMPTY_PASS_USERS" "Set passwords or lock accounts"
    fi
fi

echo -e "\n------------------------------------------------------"

# =========================================================
# PART 4: KERNEL SECURITY PARAMETERS
# =========================================================
echo -e "${CYAN}>>> PART 4: KERNEL HARDENING${NC}"

# Network parameters
check_sysctl "net.ipv4.ip_forward" "0" "CIS 3.1.1"
check_sysctl "net.ipv4.conf.all.send_redirects" "0" "CIS 3.1.2"
check_sysctl "net.ipv4.conf.all.accept_source_route" "0" "CIS 3.2.1"
check_sysctl "net.ipv4.conf.all.accept_redirects" "0" "CIS 3.2.2"
check_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1" "CIS 3.2.5"
check_sysctl "net.ipv4.tcp_syncookies" "1" "CIS 3.2.8"

# ASLR (Address Space Layout Randomization)
check_sysctl "kernel.randomize_va_space" "2" "CIS 1.5.3"

# IPv6 (if enabled)
if [ -f /proc/net/if_inet6 ]; then
    check_sysctl "net.ipv6.conf.all.forwarding" "0" "CIS 3.3.1"
    check_sysctl "net.ipv6.conf.all.accept_redirects" "0" "CIS 3.3.2"
fi

echo -e "\n------------------------------------------------------"

# =========================================================
# PART 5: FIREWALL CONFIGURATION
# =========================================================
echo -e "${CYAN}>>> PART 5: FIREWALL STATUS${NC}"

if command -v ufw >/dev/null; then
    UFW_STATE=$(ufw status 2>/dev/null | grep "Status: active")
    if [[ ! -z "$UFW_STATE" ]]; then
        log_result "PASS" "PCI 1.1.1" "Firewall (UFW) is ACTIVE" ""
    else
        log_result "FAIL" "PCI 1.1.1" "Firewall (UFW) is INACTIVE" "Run 'ufw enable'"
    fi
elif command -v firewall-cmd >/dev/null; then
    FW_STATE=$(firewall-cmd --state 2>/dev/null)
    if [[ "$FW_STATE" == "running" ]]; then
        log_result "PASS" "PCI 1.1.1" "Firewall (firewalld) is ACTIVE" ""
    else
        log_result "FAIL" "PCI 1.1.1" "Firewall (firewalld) is INACTIVE" "systemctl enable --now firewalld"
    fi
elif command -v iptables >/dev/null; then
    # Check iptables default policies
    INPUT_POLICY=$(iptables -L INPUT -n | head -1 | awk '{print $4}' | tr -d ')')
    if [[ "$INPUT_POLICY" == "DROP" ]] || [[ "$INPUT_POLICY" == "REJECT" ]]; then
        log_result "PASS" "PCI 1.2.1" "iptables default INPUT policy: $INPUT_POLICY" ""
    else
        log_result "WARN" "PCI 1.2.1" "iptables default INPUT policy: $INPUT_POLICY (consider DROP)" "iptables -P INPUT DROP"
    fi
else
    log_result "FAIL" "PCI 1.1" "No firewall detected" "Install ufw, firewalld, or configure iptables"
fi

echo -e "\n------------------------------------------------------"

# =========================================================
# PART 6: MANDATORY ACCESS CONTROL
# =========================================================
echo -e "${CYAN}>>> PART 6: MANDATORY ACCESS CONTROL${NC}"

# SELinux (RHEL/CentOS/Fedora)
if command -v getenforce >/dev/null 2>&1; then
    SELINUX=$(getenforce 2>/dev/null)
    if [[ "$SELINUX" == "Enforcing" ]]; then
        log_result "PASS" "CIS 1.6.1.1" "SELinux is Enforcing" ""
    elif [[ "$SELINUX" == "Permissive" ]]; then
        log_result "WARN" "CIS 1.6.1.1" "SELinux is Permissive" "Set to Enforcing mode"
    else
        log_result "FAIL" "CIS 1.6.1.1" "SELinux is Disabled" "Enable SELinux in /etc/selinux/config"
    fi
fi

# AppArmor (Ubuntu/Debian)
if command -v apparmor_status >/dev/null 2>&1; then
    AA_STATUS=$(apparmor_status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}')
    if [[ "$AA_STATUS" -gt 0 ]]; then
        log_result "PASS" "CIS 1.6.2.1" "AppArmor enabled: $AA_STATUS profiles loaded" ""
    else
        log_result "FAIL" "CIS 1.6.2.1" "AppArmor not configured" "Enable AppArmor profiles"
    fi
fi

# If neither is present
if ! command -v getenforce >/dev/null 2>&1 && ! command -v apparmor_status >/dev/null 2>&1; then
    log_result "WARN" "CIS 1.6" "No MAC system (SELinux/AppArmor) detected" "Install and configure SELinux or AppArmor"
fi

echo -e "\n------------------------------------------------------"

# =========================================================
# PART 7: AUDIT LOGGING (CRITICAL FOR COMPLIANCE)
# =========================================================
echo -e "${CYAN}>>> PART 7: AUDIT LOGGING${NC}"

# Check if auditd is running
if systemctl is-active --quiet auditd 2>/dev/null; then
    log_result "PASS" "PCI 10.2" "Audit daemon (auditd) is running" ""
    
    # Check audit rules
    RULE_COUNT=$(auditctl -l 2>/dev/null | grep -v "No rules" | wc -l)
    if [[ "$RULE_COUNT" -gt 10 ]]; then
        log_result "PASS" "PCI 10.2.2" "$RULE_COUNT audit rules configured" ""
    elif [[ "$RULE_COUNT" -gt 0 ]]; then
        log_result "WARN" "PCI 10.2.2" "Only $RULE_COUNT audit rules (recommend 15+)" "Review /etc/audit/rules.d/"
    else
        log_result "FAIL" "PCI 10.2.2" "No audit rules configured" "Configure audit rules for file access, user actions, etc."
    fi
else
    log_result "FAIL" "PCI 10.2" "Audit daemon (auditd) not running" "systemctl enable --now auditd"
fi

# Check for failed login tracking
if [ -f /var/log/auth.log ]; then
    FAILED=$(grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20 | wc -l)
    if [[ "$FAILED" -gt 10 ]]; then
        log_result "WARN" "PCI 8.1.6" "$FAILED recent failed login attempts (potential brute force)" "Review /var/log/auth.log"
    else
        log_result "INFO" "PCI 8.1.6" "$FAILED recent failed login attempts" ""
    fi
elif [ -f /var/log/secure ]; then
    FAILED=$(grep "Failed password" /var/log/secure 2>/dev/null | tail -20 | wc -l)
    if [[ "$FAILED" -gt 10 ]]; then
        log_result "WARN" "PCI 8.1.6" "$FAILED recent failed login attempts" "Review /var/log/secure"
    else
        log_result "INFO" "PCI 8.1.6" "$FAILED recent failed login attempts" ""
    fi
fi

echo -e "\n------------------------------------------------------"

# =========================================================
# PART 8: DANGEROUS SERVICES CHECK
# =========================================================
echo -e "${CYAN}>>> PART 8: DANGEROUS SERVICES${NC}"

DANGEROUS_PACKAGES=("telnet" "rsh-server" "rsh-client" "ypbind" "tftp-server")

for pkg in "${DANGEROUS_PACKAGES[@]}"; do
    if dpkg -l 2>/dev/null | grep -q "^ii.*$pkg" || rpm -qa 2>/dev/null | grep -q "$pkg"; then
        log_result "FAIL" "PCI 2.2.2" "Insecure package installed: $pkg" "Remove with: apt remove $pkg (or yum remove)"
    fi
done

# Check for running telnet/FTP services
if systemctl is-active --quiet telnet 2>/dev/null; then
    log_result "FAIL" "PCI 2.2.2" "Telnet service is running" "systemctl stop telnet && systemctl disable telnet"
fi

if systemctl is-active --quiet vsftpd 2>/dev/null; then
    log_result "WARN" "PCI 2.2.2" "FTP service (vsftpd) is running" "Use SFTP instead of FTP"
fi

echo -e "\n------------------------------------------------------"

# =========================================================
# PART 9: PORT EXPOSURE ANALYSIS (ENHANCED)
# =========================================================
echo -e "${CYAN}>>> PART 9: NETWORK PORT EXPOSURE ANALYSIS${NC}"

ss -tuln | awk 'NR>1 {print $5}' | while read -r SOCKET; do
    
    # Extract IP and Port
    PORT=$(echo $SOCKET | rev | cut -d: -f1 | rev)
    IP=$(echo $SOCKET | rev | cut -d: -f2- | rev)
    IP=$(echo $IP | tr -d '[]') # Clean brackets from IPv6

    # CHECK 1: LOCALHOST (Safe)
    if [[ "$IP" == "127.0.0.1" ]] || [[ "$IP" == "::1" ]] || [[ "$IP" == *"127.0.0."* ]]; then
        case "$PORT" in
            3306) log_result "INFO" "PCI 1.3" "MySQL ($PORT) bound to localhost (secure)" "" ;;
            5432) log_result "INFO" "PCI 1.3" "PostgreSQL ($PORT) bound to localhost (secure)" "" ;;
            6379) log_result "INFO" "PCI 1.3" "Redis ($PORT) bound to localhost (secure)" "" ;;
            27017) log_result "INFO" "PCI 1.3" "MongoDB ($PORT) bound to localhost (secure)" "" ;;
            11211) log_result "INFO" "PCI 1.3" "Memcached ($PORT) bound to localhost (secure)" "" ;;
            9200|9300) log_result "INFO" "PCI 1.3" "Elasticsearch ($PORT) bound to localhost (secure)" "" ;;
            53) log_result "INFO" "System" "DNS ($PORT) bound to localhost" "" ;;
            *) log_result "INFO" "Internal" "Port $PORT bound to localhost" "" ;;
        esac
        continue
    fi

    # CHECK 2: GLOBAL EXPOSURE
    IS_ALLOWED=0
    for ALLOWED in "${GLOBAL_ALLOW_LIST[@]}"; do
        if [[ "$PORT" == "$ALLOWED" ]]; then
            IS_ALLOWED=1
            break
        fi
    done

    if [[ "$IS_ALLOWED" -eq 1 ]]; then
        case "$PORT" in
            80|443) log_result "PASS" "PCI 4.1" "Web service ($PORT) globally accessible" "" ;;
            22) log_result "PASS" "CIS 5.2" "SSH ($PORT) globally accessible" "" ;;
            *) log_result "PASS" "Config" "Allowed port $PORT is open" "" ;;
        esac
    else
        # DANGEROUS EXPOSURE CHECKS
        case "$PORT" in
            23) log_result "FAIL" "PCI 2.2.2" "CRITICAL: Telnet ($PORT) exposed to internet!" "Uninstall telnet immediately" ;;
            21) log_result "FAIL" "PCI 2.2.2" "CRITICAL: FTP ($PORT) exposed to internet!" "Use SFTP instead" ;;
            3306) log_result "FAIL" "PCI 1.3" "CRITICAL: MySQL ($PORT) exposed to internet!" "Bind to 127.0.0.1" ;;
            5432) log_result "FAIL" "PCI 1.3" "CRITICAL: PostgreSQL ($PORT) exposed to internet!" "Bind to 127.0.0.1" ;;
            27017) log_result "FAIL" "PCI 1.3" "CRITICAL: MongoDB ($PORT) exposed to internet!" "Bind to 127.0.0.1 + enable auth" ;;
            6379) log_result "FAIL" "PCI 1.3" "CRITICAL: Redis ($PORT) exposed to internet!" "Bind to 127.0.0.1 + requirepass" ;;
            2375|2376) log_result "FAIL" "CRITICAL" "EMERGENCY: Docker API ($PORT) exposed! Container takeover risk!" "Close immediately: iptables -A INPUT -p tcp --dport $PORT -j DROP" ;;
            9200|9300) log_result "FAIL" "PCI 1.3" "CRITICAL: Elasticsearch ($PORT) exposed!" "Enable authentication + bind to 127.0.0.1" ;;
            11211) log_result "FAIL" "PCI 1.3" "CRITICAL: Memcached ($PORT) exposed!" "Bind to 127.0.0.1" ;;
            5672) log_result "FAIL" "PCI 1.3" "CRITICAL: RabbitMQ ($PORT) exposed!" "Configure firewall rules" ;;
            3389) log_result "FAIL" "CIS 3.4" "RDP ($PORT) exposed to internet!" "Restrict access with firewall" ;;
            161|162) log_result "WARN" "CIS 3.4" "SNMP ($PORT) exposed on $IP" "Restrict SNMP access" ;;
            8080|8443) log_result "WARN" "CIS 3.4" "Alternative web port ($PORT) exposed on $IP" "Verify if intentional" ;;
            *) log_result "WARN" "CIS 3.4" "Unknown port $PORT exposed on $IP" "Investigate this service" ;;
        esac
    fi
done

echo -e "\n------------------------------------------------------"

# =========================================================
# PART 10: WEB SERVER CHECKS (Nginx / Apache)
# =========================================================
echo -e "${CYAN}>>> PART 10: WEB SERVER CONFIGURATION${NC}"

NGINX_INSTALLED=0
APACHE_INSTALLED=0

# --- NGINX CHECK ---
if command -v nginx >/dev/null; then
    NGINX_INSTALLED=1
    log_result "INFO" "System" "Nginx detected" ""
    
    # Check server_tokens (Hiding version number)
    if grep -r "server_tokens off" /etc/nginx/ > /dev/null 2>&1; then
        log_result "PASS" "CIS Nginx 2.1" "Nginx Version Hiding (server_tokens off)" ""
    else
        log_result "FAIL" "CIS Nginx 2.1" "Nginx Version is visible" "Add 'server_tokens off;' to nginx.conf"
    fi
fi

# --- APACHE CHECK ---
if command -v apache2 >/dev/null || command -v httpd >/dev/null; then
    APACHE_INSTALLED=1
    log_result "INFO" "System" "Apache detected" ""
    
    CONF_ROOT="/etc/apache2"
    [ -d "/etc/httpd" ] && CONF_ROOT="/etc/httpd"

    # Check ServerTokens (Should be Prod)
    if grep -r "ServerTokens Prod" "$CONF_ROOT" > /dev/null 2>&1; then
        log_result "PASS" "CIS Apache 2.3" "Apache Version Hiding (ServerTokens Prod)" ""
    else
        log_result "FAIL" "CIS Apache 2.3" "Apache Version/OS details visible" "Set 'ServerTokens Prod' in apache config"
    fi

    # Check ServerSignature (Should be Off)
    if grep -r "ServerSignature Off" "$CONF_ROOT" > /dev/null 2>&1; then
        log_result "PASS" "CIS Apache 2.4" "Apache Footer Signature disabled" ""
    else
        log_result "FAIL" "CIS Apache 2.4" "Apache Footer Signature enabled" "Set 'ServerSignature Off' in apache config"
    fi
fi

if [[ $NGINX_INSTALLED -eq 0 ]] && [[ $APACHE_INSTALLED -eq 0 ]]; then
    echo "No standard web server (Nginx/Apache) found. Skipping."
fi

echo -e "\n------------------------------------------------------"

# =========================================================
# PART 11: DOCKER SECURITY
# =========================================================
echo -e "${CYAN}>>> PART 11: CONTAINER RUNTIME (Docker)${NC}"

if command -v docker >/dev/null; then
    log_result "INFO" "System" "Docker detected" ""
    
    # Check Docker Socket Permissions
    if [ -S /var/run/docker.sock ]; then
        SOCK_PERM=$(stat -c "%a" /var/run/docker.sock)
        if [[ "$SOCK_PERM" == "660" ]]; then
            log_result "PASS" "CIS Docker 3.1" "Docker Socket permissions secure (660)" ""
        else
            log_result "WARN" "CIS Docker 3.1" "Docker Socket permissions are $SOCK_PERM" "Should be 660 (root:docker)"
        fi
    else
        log_result "INFO" "System" "Docker socket not active or not found at default path" ""
    fi
    
else
    echo "Docker not found. Skipping."
fi

echo -e "\n------------------------------------------------------"

# =========================================================
# FINAL SUMMARY
# =========================================================
echo -e "\n${YELLOW}======================================================${NC}"
echo -e "${YELLOW}                 AUDIT SUMMARY                        ${NC}"
echo -e "${YELLOW}======================================================${NC}"
echo -e "[PASS]: ${GREEN}$PASS_COUNT${NC}"
echo -e "[INFO]: ${BLUE}$INFO_COUNT${NC}"
echo -e "[WARN]: ${YELLOW}$WARN_COUNT${NC}"
echo -e "[FAIL]: ${RED}$FAIL_COUNT${NC}"
echo -e "------------------------------------------------------"

# Compliance Status
TOTAL_CHECKS=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT))
if [[ $TOTAL_CHECKS -gt 0 ]]; then
    COMPLIANCE_RATE=$(( (PASS_COUNT * 100) / TOTAL_CHECKS ))
    echo -e "Compliance Rate: ${COMPLIANCE_RATE}%"
fi

echo -e "\nLog saved to: ${LOG_FILE}"

# EXIT CODE
if [[ $FAIL_COUNT -gt 0 ]]; then
    echo -e "\n${RED}ACTION REQUIRED: $FAIL_COUNT critical security issues detected${NC}"
    echo -e "${RED}System is NOT compliant. Address FAIL items immediately.${NC}"
    exit 1
elif [[ $WARN_COUNT -gt 5 ]]; then
    echo -e "\n${YELLOW}ATTENTION: $WARN_COUNT warnings detected${NC}"
    echo -e "${YELLOW}System is partially compliant. Review WARN items.${NC}"
    exit 0
else
    echo -e "\n${GREEN}System passes basic security compliance checks${NC}"
    exit 0
fi
