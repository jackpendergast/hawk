#!/usr/bin/env bash
# ============================================================================
# setup-wazuh-ccdc.sh  -  Deploy CCDC detection config to Wazuh Manager
# Run on: Ubuntu Wks (Wazuh Manager/Dashboard)
# Usage:  sudo bash setup-wazuh-ccdc.sh [SPLUNK_IP]
#
# This script:
#   1. Installs custom CCDC detection rules
#   2. Deploys centralized agent.conf (pushed to all agents)
#   3. Configures syslog forwarding to Splunk
#   4. Tunes alert levels and enables all detection modules
#   5. Restarts the Wazuh manager
# ============================================================================
set -euo pipefail

SPLUNK_IP="${1:-172.20.242.20}"
WAZUH_DIR="/var/ossec"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=========================================="
echo " Wazuh CCDC Config Deployment"
echo " Splunk IP: ${SPLUNK_IP}"
echo "=========================================="

# ---------------------------------------------------------------------------
# 1. Install custom CCDC detection rules
# ---------------------------------------------------------------------------
echo "[*] Installing CCDC custom rules..."
cp "$SCRIPT_DIR/rules/ccdc_rules.xml" "$WAZUH_DIR/etc/rules/ccdc_rules.xml"
chown wazuh:wazuh "$WAZUH_DIR/etc/rules/ccdc_rules.xml"
chmod 640 "$WAZUH_DIR/etc/rules/ccdc_rules.xml"

# ---------------------------------------------------------------------------
# 2. Deploy centralized agent.conf
#    This gets pushed to all agents in the "default" group automatically.
# ---------------------------------------------------------------------------
echo "[*] Deploying centralized agent.conf..."
cp "$SCRIPT_DIR/manager/agent.conf" "$WAZUH_DIR/etc/shared/default/agent.conf"
chown wazuh:wazuh "$WAZUH_DIR/etc/shared/default/agent.conf"
chmod 640 "$WAZUH_DIR/etc/shared/default/agent.conf"

# ---------------------------------------------------------------------------
# 3. Configure syslog output to Splunk
#    Adds <syslog_output> block if not already present.
# ---------------------------------------------------------------------------
echo "[*] Configuring syslog output to Splunk at ${SPLUNK_IP}:9000..."
OSSEC_CONF="$WAZUH_DIR/etc/ossec.conf"

if ! grep -q "syslog_output" "$OSSEC_CONF"; then
    sed -i "/<\/ossec_config>/i\\
  <syslog_output>\\
    <server>${SPLUNK_IP}</server>\\
    <port>9000</port>\\
    <format>json</format>\\
    <level>1</level>\\
  </syslog_output>" "$OSSEC_CONF"
    echo "[*] Syslog output block added."
else
    # Update existing syslog_output with correct Splunk IP
    sed -i "/<syslog_output>/,/<\/syslog_output>/s|<server>.*</server>|<server>${SPLUNK_IP}</server>|" "$OSSEC_CONF"
    echo "[*] Existing syslog output updated."
fi

# ---------------------------------------------------------------------------
# 4. Tune alert levels - lower threshold to catch more activity
# ---------------------------------------------------------------------------
echo "[*] Tuning alert levels..."
if grep -q '<log_alert_level>' "$OSSEC_CONF"; then
    sed -i 's|<log_alert_level>[0-9]*</log_alert_level>|<log_alert_level>1</log_alert_level>|' "$OSSEC_CONF"
else
    sed -i '/<alerts>/a\    <log_alert_level>1</log_alert_level>' "$OSSEC_CONF"
fi

# ---------------------------------------------------------------------------
# 5. Enable logall_json for full log capture
# ---------------------------------------------------------------------------
if ! grep -q '<logall_json>' "$OSSEC_CONF"; then
    sed -i '/<global>/a\    <logall_json>yes</logall_json>' "$OSSEC_CONF"
fi

# ---------------------------------------------------------------------------
# 6. Add the custom rules file to the ruleset if not already referenced
# ---------------------------------------------------------------------------
if ! grep -q 'ccdc_rules.xml' "$OSSEC_CONF"; then
    # Find the closing </ruleset> tag and add our include before it
    sed -i '/<\/ruleset>/i\    <include>rules/ccdc_rules.xml</include>' "$OSSEC_CONF" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 7. Enable vulnerability detection if not already
# ---------------------------------------------------------------------------
if ! grep -q '<vulnerability-detector>' "$OSSEC_CONF"; then
    echo "[*] Adding vulnerability detection config..."
    sed -i "/<\/ossec_config>/i\\
  <vulnerability-detector>\\
    <enabled>yes</enabled>\\
    <interval>5m</interval>\\
    <run_on_start>yes</run_on_start>\\
    <provider name=\"canonical\">\\
      <enabled>yes</enabled>\\
      <os>jammy</os>\\
      <update_interval>1h</update_interval>\\
    </provider>\\
    <provider name=\"redhat\">\\
      <enabled>yes</enabled>\\
      <os>9</os>\\
      <update_interval>1h</update_interval>\\
    </provider>\\
    <provider name=\"msu\">\\
      <enabled>yes</enabled>\\
      <update_interval>1h</update_interval>\\
    </provider>\\
    <provider name=\"nvd\">\\
      <enabled>yes</enabled>\\
      <update_interval>1h</update_interval>\\
    </provider>\\
  </vulnerability-detector>" "$OSSEC_CONF"
fi

# ---------------------------------------------------------------------------
# 8. Validate config before restart
# ---------------------------------------------------------------------------
echo "[*] Validating configuration..."
if "$WAZUH_DIR/bin/wazuh-analysisd" -t 2>&1 | grep -q "Configuration OK"; then
    echo "[*] Config validation passed."
else
    echo "[!] Config validation had warnings (may still work). Check output above."
fi

# ---------------------------------------------------------------------------
# 9. Restart Wazuh manager
# ---------------------------------------------------------------------------
echo "[*] Restarting Wazuh manager..."
systemctl restart wazuh-manager

# Wait for it to come up
sleep 5
if systemctl is-active --quiet wazuh-manager; then
    echo "[*] Wazuh manager is running."
else
    echo "[!] Wazuh manager may have failed to start. Check:"
    echo "    sudo journalctl -u wazuh-manager -n 50"
    echo "    sudo cat /var/ossec/logs/ossec.log | tail -30"
fi

echo ""
echo "=========================================="
echo " CCDC Config Deployment Complete"
echo "=========================================="
echo ""
echo " What was deployed:"
echo "   - Custom CCDC rules: $WAZUH_DIR/etc/rules/ccdc_rules.xml"
echo "   - Centralized agent config: $WAZUH_DIR/etc/shared/default/agent.conf"
echo "   - Syslog forwarding to Splunk at ${SPLUNK_IP}:9000"
echo "   - Alert level lowered to 1 (catch everything)"
echo "   - Vulnerability detection enabled"
echo ""
echo " The agent.conf is pushed to agents automatically."
echo " Agents may need 1-2 minutes to pick up the new config."
echo " Force push:  $WAZUH_DIR/bin/agent_control -R -a"
echo ""
echo " Dashboard: Review alerts at Security Events > CCDC rules"
echo "   Filter by: rule.groups:ccdc*"
echo ""
echo " Next: Run setup-splunk-receiver.sh on the Splunk box."
echo "=========================================="
