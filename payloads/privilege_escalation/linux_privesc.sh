#!/bin/bash
# Linux Privilege Escalation Script
# Safe privilege escalation enumeration for authorized testing

echo "=== Linux Privilege Escalation Enumeration ==="
echo "Date: $(date)"
echo "User: $(whoami)"
echo "UID: $(id -u)"
echo "GID: $(id -g)"
echo "Groups: $(id -Gn)"
echo ""

echo "=== System Information ==="
uname -a
echo ""

echo "=== Kernel Version ==="
cat /proc/version
echo ""

echo "=== CPU Information ==="
cat /proc/cpuinfo | head -20
echo ""

echo "=== Memory Information ==="
cat /proc/meminfo | head -10
echo ""

echo "=== Network Interfaces ==="
ip addr show
echo ""

echo "=== Running Processes ==="
ps aux | head -20
echo ""

echo "=== SUID Binaries ==="
find / -perm -4000 2>/dev/null | head -20
echo ""

echo "=== SGID Binaries ==="
find / -perm -2000 2>/dev/null | head -20
echo ""

echo "=== World Writable Files ==="
find / -perm -002 -type f 2>/dev/null | head -20
echo ""

echo "=== World Writable Directories ==="
find / -perm -002 -type d 2>/dev/null | head -20
echo ""

echo "=== Cron Jobs ==="
crontab -l 2>/dev/null
echo ""

echo "=== Sudo Permissions ==="
sudo -l 2>/dev/null
echo ""

echo "=== Environment Variables ==="
env | grep -E "(PATH|HOME|USER|SHELL)"
echo ""

echo "=== History Files ==="
ls -la ~/.bash_history ~/.zsh_history ~/.history 2>/dev/null
echo ""

echo "=== SSH Keys ==="
find /home -name "id_*" -type f 2>/dev/null
echo ""

echo "=== Capabilities ==="
getcap -r / 2>/dev/null | head -20
echo ""

echo "=== Mount Information ==="
mount | grep -E "(noexec|nosuid|nodev)"
echo ""

echo "=== Services ==="
systemctl list-units --type=service --state=running 2>/dev/null | head -20
echo ""

echo "=== Network Connections ==="
netstat -tulpn 2>/dev/null | head -20
echo ""

echo "=== World Writable SUID/SGID ==="
find / -perm -4000 -o -perm -2000 2>/dev/null | xargs ls -la 2>/dev/null | grep -E "^-.*w.*w"
echo ""

echo "=== Files with Capabilities ==="
getcap -r / 2>/dev/null
echo ""

echo "=== Docker Information ==="
docker --version 2>/dev/null
docker ps 2>/dev/null
echo ""

echo "=== Container Information ==="
cat /proc/1/cgroup 2>/dev/null
echo ""

echo "=== Kernel Modules ==="
lsmod | head -20
echo ""

echo "=== Hardware Information ==="
lscpu 2>/dev/null
lsblk 2>/dev/null
echo ""

echo "=== Privilege Escalation Check Complete ==="
