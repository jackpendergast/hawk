#!/usr/bin/env bash
# ============================================================================
# 04-verify-linux.sh  --  Gather evidence for the inject deliverables
# Run on each Linux agent to produce ClamAV proof.
# Usage:  sudo bash 04-verify-linux.sh
# ============================================================================

HOSTNAME=$(hostname)
echo "===== Evidence for: ${HOSTNAME} ====="
echo ""

echo "--- ClamAV daemon listening (ss -ltnp | grep :3310) ---"
ss -ltnp | grep :3310 || echo "(not listening on 3310 -- check clamd config)"
echo ""

echo "--- ClamAV service status ---"
systemctl status clamav-daemon --no-pager 2>/dev/null || \
systemctl status clamd@scan --no-pager 2>/dev/null || \
systemctl status clamd --no-pager 2>/dev/null || \
echo "(no clamav service found)"
echo ""

echo "--- ClamAV scan timer ---"
systemctl list-timers clamav-scan.timer --no-pager
echo ""

echo "--- Wazuh agent status ---"
systemctl status wazuh-agent --no-pager 2>/dev/null || echo "(wazuh-agent not found)"
echo ""

echo "--- Wazuh agent connection to manager ---"
/var/ossec/bin/agent-control -i 000 2>/dev/null || \
cat /var/ossec/var/run/wazuh-agentd.state 2>/dev/null || \
echo "(could not check agent state)"
echo ""
echo "===== End evidence for: ${HOSTNAME} ====="
