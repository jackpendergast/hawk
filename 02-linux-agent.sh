#!/usr/bin/env bash
# ============================================================================
# 02-linux-agent.sh  --  Wazuh 4.7 Agent + ClamAV on Linux
# Targets: Ubuntu Ecom (24.04), Fedora Webmail (42), Splunk Oracle Linux (9.2)
# Usage:   sudo bash 02-linux-agent.sh <MANAGER_IP>
#
# What this does:
#   - Detects distro (apt vs dnf)
#   - Installs ClamAV + enables daemon + creates systemd timer for hourly scan
#   - Installs Wazuh 4.7 agent pointed at the manager
#   - Patches ossec.conf to enable syscollector, FIM (realtime), and syslog
#   - Restarts wazuh-agent
# ============================================================================
set -euo pipefail

WAZUH_VERSION="4.7"
WAZUH_AGENT_DEB="wazuh-agent_4.7.3-1_amd64.deb"
WAZUH_AGENT_RPM="wazuh-agent-4.7.3-1.x86_64.rpm"
REG_PASSWORD="MyStrongKey"

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    echo "Usage: sudo bash $0 <MANAGER_IP>"
    exit 1
fi
MANAGER_IP="$1"
echo "[*] Manager IP: ${MANAGER_IP}"

# ---------------------------------------------------------------------------
# Detect distro family
# ---------------------------------------------------------------------------
if command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"
else
    echo "[!] Unsupported package manager. Exiting."
    exit 1
fi
echo "[*] Detected package manager: ${PKG_MGR}"

# ===========================
# SECTION 1: ClamAV
# ===========================
echo ""
echo "===== ClamAV Installation ====="

if [[ "$PKG_MGR" == "apt" ]]; then
    apt-get update -qq
    apt-get install -y clamav clamav-daemon
    # Stop freshclam so we can do initial DB pull
    systemctl stop clamav-freshclam || true
    freshclam || echo "[!] freshclam initial pull failed (may retry on its own)"
    systemctl enable --now clamav-freshclam
    systemctl enable --now clamav-daemon
else
    # Fedora / Oracle Linux / RHEL family
    "$PKG_MGR" install -y clamav clamav-update clamd
    # On RHEL-family, the service is clamd@scan
    # Update SELinux booleans if needed
    setsebool -P antivirus_can_scan_system 1 2>/dev/null || true
    # Initial signature update
    freshclam || echo "[!] freshclam initial pull failed"
    # Figure out which service name exists
    if systemctl list-unit-files | grep -q "clamd@scan"; then
        CLAMD_SVC="clamd@scan"
        # Ensure the scan config is usable (RHEL/Oracle often ship with Example line)
        sed -i 's/^Example/#Example/' /etc/clamd.d/scan.conf 2>/dev/null || true
        # Make sure LocalSocket is set
        grep -q "^LocalSocket" /etc/clamd.d/scan.conf 2>/dev/null || \
            echo "LocalSocket /run/clamd.scan/clamd.sock" >> /etc/clamd.d/scan.conf
    elif systemctl list-unit-files | grep -q "clamav-daemon"; then
        CLAMD_SVC="clamav-daemon"
    else
        CLAMD_SVC="clamd"
    fi
    systemctl enable --now "$CLAMD_SVC"
    systemctl enable --now clamav-freshclam 2>/dev/null || true
fi

echo "[*] ClamAV daemon is running."

# ---------------------------------------------------------------------------
# Create systemd timer for hourly ClamAV full scan
# (inject requirement: "schedule with timer")
# ---------------------------------------------------------------------------
cat > /etc/systemd/system/clamav-scan.service <<'EOF'
[Unit]
Description=ClamAV Full System Scan
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/clamscan --recursive --infected --log=/var/log/clamav/scan.log /
Nice=19
IOSchedulingClass=idle
EOF

cat > /etc/systemd/system/clamav-scan.timer <<'EOF'
[Unit]
Description=Run ClamAV scan hourly

[Timer]
OnCalendar=hourly
Persistent=true
RandomizedDelaySec=120

[Install]
WantedBy=timers.target
EOF

mkdir -p /var/log/clamav
systemctl daemon-reload
systemctl enable --now clamav-scan.timer

echo "[*] Hourly ClamAV scan timer enabled."

# ---------------------------------------------------------------------------
# Enable on-access / real-time scanning (clamonacc)
# (inject requirement: "enable real-time scanning")
# clamonacc requires clamd running with LocalSocket or TCPSocket
# ---------------------------------------------------------------------------
if command -v clamonacc &>/dev/null; then
    # Enable on-access scanning for common directories
    cat > /etc/systemd/system/clamav-onacc.service <<EOF
[Unit]
Description=ClamAV On-Access Scanner
After=clamav-daemon.service
Requires=clamav-daemon.service

[Service]
Type=simple
ExecStart=/usr/bin/clamonacc --fdpass --move=/tmp/quarantine
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    mkdir -p /tmp/quarantine
    systemctl daemon-reload
    systemctl enable --now clamav-onacc.service 2>/dev/null || \
        echo "[!] clamonacc failed to start (may need kernel fanotify). Timer scanning still active."
else
    echo "[!] clamonacc not available on this distro. Relying on hourly timer scans."
fi

# ===========================
# SECTION 2: Wazuh Agent
# ===========================
echo ""
echo "===== Wazuh Agent Installation ====="

if [[ "$PKG_MGR" == "apt" ]]; then
    cd /tmp
    curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/${WAZUH_AGENT_DEB}"
    WAZUH_MANAGER="${MANAGER_IP}" \
    WAZUH_REGISTRATION_PASSWORD="${REG_PASSWORD}" \
        apt-get install -y "./${WAZUH_AGENT_DEB}"
else
    cd /tmp
    curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/${WAZUH_AGENT_RPM}"
    WAZUH_MANAGER="${MANAGER_IP}" \
    WAZUH_REGISTRATION_PASSWORD="${REG_PASSWORD}" \
        rpm -ivh "${WAZUH_AGENT_RPM}" || \
    WAZUH_MANAGER="${MANAGER_IP}" \
    WAZUH_REGISTRATION_PASSWORD="${REG_PASSWORD}" \
        "$PKG_MGR" localinstall -y "${WAZUH_AGENT_RPM}"
fi

# ---------------------------------------------------------------------------
# Patch ossec.conf to enable modules per the inject requirements:
#   - syscollector
#   - FIM with realtime on /home, /etc, /var/www
#   - (no Windows event channels on Linux obviously)
# ---------------------------------------------------------------------------
OSSEC_CONF="/var/ossec/etc/ossec.conf"

echo "[*] Configuring ossec.conf modules..."

# --- Enable syscollector (usually present but may be disabled) ---
if grep -q '<syscollector>' "$OSSEC_CONF"; then
    sed -i 's|<syscollector>|<syscollector>\n    <enabled>yes</enabled>|' "$OSSEC_CONF" 2>/dev/null || true
    # If already has <enabled>, flip it to yes
    sed -i '/<syscollector>/,/<\/syscollector>/s|<enabled>no</enabled>|<enabled>yes</enabled>|' "$OSSEC_CONF"
fi

# --- Enable/configure FIM (syscheck) with realtime ---
# The inject shows FIM with realtime="yes" on directories.
# We patch syscheck to add realtime directories.
if grep -q '<syscheck>' "$OSSEC_CONF"; then
    # Add realtime-monitored directories inside existing <syscheck> block
    sed -i '/<syscheck>/a\
    <directories realtime="yes">/home</directories>\
    <directories realtime="yes">/etc</directories>\
    <directories realtime="yes">/var/www</directories>' "$OSSEC_CONF"
else
    # No syscheck block at all, add one before </ossec_config>
    sed -i '/<\/ossec_config>/i\
  <syscheck>\
    <disabled>no</disabled>\
    <directories realtime="yes">/home</directories>\
    <directories realtime="yes">/etc</directories>\
    <directories realtime="yes">/var/www</directories>\
  </syscheck>' "$OSSEC_CONF"
fi

# ---------------------------------------------------------------------------
# Ensure manager address is correct in ossec.conf
# ---------------------------------------------------------------------------
sed -i "s|<address>.*</address>|<address>${MANAGER_IP}</address>|g" "$OSSEC_CONF"

# ---------------------------------------------------------------------------
# Start the agent
# ---------------------------------------------------------------------------
systemctl daemon-reload
systemctl enable --now wazuh-agent

echo ""
echo "===== Done ====="
echo "[*] Wazuh agent enrolled to ${MANAGER_IP}"
echo "[*] ClamAV daemon active, hourly timer scan enabled"
echo ""
echo "Verification commands:"
echo "  sudo ss -ltnp | grep :3310        # ClamAV listening"
echo "  sudo systemctl status wazuh-agent  # Agent status"
echo "  sudo systemctl list-timers         # Confirm scan timer"
