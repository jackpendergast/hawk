#!/usr/bin/env bash
# ============================================================================
# 01-manager-setup.sh  --  Wazuh 4.7 All-in-One (Indexer + Server + Dashboard)
# Target: Ubuntu Wks (Desktop 24.04, DHCP)
# Usage:  sudo bash 01-manager-setup.sh
# ============================================================================
set -euo pipefail

WAZUH_VERSION="4.7"
NODE_NAME="wazuh-aio"        # arbitrary single-node name
DASHBOARD_PORT=443

# ---------------------------------------------------------------------------
# Detect the IP that will be used by agents to reach this manager.
# Since this box is DHCP, we grab the current IP on the default route iface.
# ---------------------------------------------------------------------------
MANAGER_IP=$(ip -4 addr show "$(ip route show default | awk '{print $5; exit}')" \
             | awk '/inet / {split($2,a,"/"); print a[1]; exit}')

echo "=========================================="
echo " Wazuh All-in-One Installer"
echo " Detected manager IP: ${MANAGER_IP}"
echo "=========================================="
echo ""
read -rp "Use ${MANAGER_IP} as the manager address? [Y/n] " confirm
if [[ "${confirm,,}" == "n" ]]; then
    read -rp "Enter the correct IP: " MANAGER_IP
fi

# ---------------------------------------------------------------------------
# 1. Download installer and default config
# ---------------------------------------------------------------------------
cd /tmp
curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"
curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/config.yml"
chmod +x wazuh-install.sh

# ---------------------------------------------------------------------------
# 2. Patch config.yml for single-node all-in-one
#    Replace placeholder IPs with our detected IP and set node names.
# ---------------------------------------------------------------------------
cat > config.yml <<CFGEOF
nodes:
  indexer:
    - name: ${NODE_NAME}
      ip: "${MANAGER_IP}"

  server:
    - name: ${NODE_NAME}
      ip: "${MANAGER_IP}"

  dashboard:
    - name: ${NODE_NAME}
      ip: "${MANAGER_IP}"
CFGEOF

echo "[*] config.yml written for single-node deployment at ${MANAGER_IP}"

# ---------------------------------------------------------------------------
# 3. Generate certificates and config files
# ---------------------------------------------------------------------------
echo "[*] Generating config files and certificates..."
bash wazuh-install.sh --generate-config-files

# ---------------------------------------------------------------------------
# 4. Install components in order
# ---------------------------------------------------------------------------
echo "[*] Installing Wazuh Indexer..."
bash wazuh-install.sh --wazuh-indexer "${NODE_NAME}"

echo "[*] Starting Indexer cluster..."
bash wazuh-install.sh --start-cluster

echo "[*] Installing Wazuh Server..."
bash wazuh-install.sh --wazuh-server "${NODE_NAME}"

echo "[*] Installing Wazuh Dashboard..."
bash wazuh-install.sh --wazuh-dashboard "${NODE_NAME}"

# ---------------------------------------------------------------------------
# 5. Extract default admin credentials
# ---------------------------------------------------------------------------
echo ""
echo "=========================================="
echo " INSTALLATION COMPLETE"
echo "=========================================="
echo " Dashboard URL:  https://${MANAGER_IP}:${DASHBOARD_PORT}"
echo ""
echo " Extracting admin password from install files..."
# The installer stores passwords in wazuh-install-files.tar
if [[ -f /tmp/wazuh-install-files.tar ]]; then
    tar -xf /tmp/wazuh-install-files.tar ./wazuh-install-files/wazuh-passwords.txt -O 2>/dev/null \
        | grep -i "admin" || echo " (check /tmp/wazuh-install-files.tar manually)"
fi
echo ""
echo " Manager IP for agents: ${MANAGER_IP}"
echo "=========================================="
echo ""
echo " NEXT STEPS:"
echo "   On Linux agents:  sudo bash 02-linux-agent.sh ${MANAGER_IP}"
echo "   On Windows hosts: .\\03-windows-agent.ps1 -ManagerIP ${MANAGER_IP}"
echo ""
