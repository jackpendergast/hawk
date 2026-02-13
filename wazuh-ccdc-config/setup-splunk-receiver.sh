#!/usr/bin/env bash
# ============================================================================
# setup-splunk-receiver.sh  -  Configure Splunk to receive Wazuh alerts
# Run on: Splunk / Oracle Linux box (172.20.242.20)
# Usage:  sudo bash setup-splunk-receiver.sh
# ============================================================================
set -euo pipefail

# Detect Splunk install location
SPLUNK_HOME=""
for dir in /opt/splunk /opt/splunkforwarder; do
    if [[ -d "$dir" ]]; then
        SPLUNK_HOME="$dir"
        break
    fi
done

if [[ -z "$SPLUNK_HOME" ]]; then
    echo "[!] Splunk not found in /opt/splunk or /opt/splunkforwarder"
    exit 1
fi

echo "[*] Splunk found at: $SPLUNK_HOME"

# Create app directory for clean config
APP_DIR="$SPLUNK_HOME/etc/apps/wazuh_ccdc/local"
mkdir -p "$APP_DIR"

# Copy config files
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$SCRIPT_DIR/splunk/inputs.conf" "$APP_DIR/inputs.conf"
cp "$SCRIPT_DIR/splunk/props.conf" "$APP_DIR/props.conf"
cp "$SCRIPT_DIR/splunk/indexes.conf" "$APP_DIR/indexes.conf"

# Install the CCDC War Room dashboard
VIEWS_DIR="$SPLUNK_HOME/etc/apps/wazuh_ccdc/local/data/ui/views"
NAV_DIR="$SPLUNK_HOME/etc/apps/wazuh_ccdc/local/data/ui/nav"
mkdir -p "$VIEWS_DIR" "$NAV_DIR"

if [[ -f "$SCRIPT_DIR/splunk/ccdc_warroom.xml" ]]; then
    cp "$SCRIPT_DIR/splunk/ccdc_warroom.xml" "$VIEWS_DIR/ccdc_warroom.xml"
    cat > "$NAV_DIR/default.xml" <<'NAVEOF'
<nav>
  <view name="ccdc_warroom" default="true"/>
</nav>
NAVEOF
    echo "[*] CCDC War Room dashboard installed."
fi

echo "[*] Config files installed to $APP_DIR"

# Create the app.conf
cat > "$SPLUNK_HOME/etc/apps/wazuh_ccdc/local/app.conf" <<'EOF'
[install]
is_configured = true

[ui]
is_visible = true
label = Wazuh CCDC Alerts

[launcher]
version = 1.0.0
description = Receives and indexes Wazuh alerts for CCDC competition
EOF

# Open firewall port if firewalld is running
if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
    firewall-cmd --add-port=9000/tcp --permanent
    firewall-cmd --reload
    echo "[*] Firewall port 9000/tcp opened"
fi

# Restart Splunk
echo "[*] Restarting Splunk..."
"$SPLUNK_HOME/bin/splunk" restart

echo ""
echo "=========================================="
echo " Splunk receiver configured"
echo "=========================================="
echo " Listening on TCP port 9000 for Wazuh alerts"
echo " Index: wazuh"
echo " Sourcetype: wazuh-alerts"
echo ""
echo " Verify in Splunk Web:"
echo "   Search: index=wazuh | head 10"
echo ""
echo " Useful CCDC searches:"
echo '   index=wazuh rule.groups="ccdc*" | table _time agent.name rule.description rule.level'
echo '   index=wazuh rule.level>=12 | table _time agent.name rule.description'
echo '   index=wazuh rule.groups="ccdc_webshell" | table _time agent.name syscheck.path'
echo "=========================================="
