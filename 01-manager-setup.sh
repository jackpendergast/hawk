#!/usr/bin/env bash
# ============================================================================
# 01-manager-setup.sh  --  Wazuh 4.7 All-in-One (Indexer + Server + Dashboard)
# Target: Ubuntu Wks (Desktop 24.04, DHCP)
# Usage:  sudo bash 01-manager-setup.sh
# ============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
echo "[*] Checking dependencies..."
for cmd in curl tar; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "[*] Installing missing dependency: $cmd"
        apt-get update -qq && apt-get install -y "$cmd"
    fi
done

WAZUH_VERSION="4.7"
NODE_NAME="wazuh-aio"        # arbitrary single-node name
DASHBOARD_PORT=443
AUTH_PASSWORD="ja|ZtS72E'&tEQ46=P=B"

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
bash wazuh-install.sh --generate-config-files -i

# ---------------------------------------------------------------------------
# 4. Install components in order
# ---------------------------------------------------------------------------
echo "[*] Installing Wazuh Indexer..."
bash wazuh-install.sh --wazuh-indexer "${NODE_NAME}" -i

echo "[*] Starting Indexer cluster..."
bash wazuh-install.sh --start-cluster -i

echo "[*] Installing Wazuh Server..."
bash wazuh-install.sh --wazuh-server "${NODE_NAME}" -i

echo "[*] Installing Wazuh Dashboard..."
bash wazuh-install.sh --wazuh-dashboard "${NODE_NAME}" -i

# ---------------------------------------------------------------------------
# 5. Configure manager to require password authentication
# ---------------------------------------------------------------------------
echo "[*] Configuring Wazuh manager to require authd password..."

OSSEC_CONF="/var/ossec/etc/ossec.conf"

if grep -q "<auth>" "$OSSEC_CONF"; then
    sed -i 's|<use_password>.*</use_password>|<use_password>yes</use_password>|' "$OSSEC_CONF"
else
    sed -i '/<\/ossec_config>/i \
  <auth>\n\
    <use_password>yes</use_password>\n\
  </auth>' "$OSSEC_CONF"
fi

echo "[*] Creating authd password file..."
echo "${AUTH_PASSWORD}" > /var/ossec/etc/authd.pass
chmod 640 /var/ossec/etc/authd.pass
chown root:wazuh /var/ossec/etc/authd.pass

echo "[*] Restarting Wazuh manager..."
systemctl restart wazuh-manager

# ---------------------------------------------------------------------------
# 6. Extract default admin credentials
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

# ===========================================================================
# PHASE 2: CCDC Defense Config Deployment
# ===========================================================================
echo "=========================================="
echo " PHASE 2: CCDC Defense Configuration"
echo "=========================================="
echo ""
echo " This will:"
echo "   - Install custom CCDC detection rules (webshells, persistence, etc.)"
echo "   - Deploy centralized agent config (FIM, rootcheck, service monitoring)"
echo "   - Configure log forwarding to Splunk (172.20.242.20:9000)"
echo "   - Lower alert thresholds to catch all red team activity"
echo "   - Enable vulnerability detection"
echo ""
echo " Make sure agents are connecting before proceeding."
echo " Check the dashboard at https://${MANAGER_IP}:${DASHBOARD_PORT}"
echo ""
read -rp "Press ENTER to deploy CCDC defense config (or Ctrl+C to skip)..."

# ---------------------------------------------------------------------------
# Determine where the config files are.
# If we're running from the cloned repo, use local files.
# Otherwise, download them from GitHub.
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_URL="https://raw.githubusercontent.com/jackpendergast/hawk/main"
CCDC_DIR=""

if [[ -d "${SCRIPT_DIR}/wazuh-ccdc-config" ]]; then
    echo "[*] Found local wazuh-ccdc-config directory."
    CCDC_DIR="${SCRIPT_DIR}/wazuh-ccdc-config"
else
    echo "[*] Downloading CCDC config script from GitHub..."
    CCDC_DIR="/tmp/wazuh-ccdc-config"
    mkdir -p "${CCDC_DIR}"

    curl -sO --output-dir "${CCDC_DIR}" "${REPO_URL}/wazuh-ccdc-config/setup-wazuh-ccdc.sh"
    chmod +x "${CCDC_DIR}/setup-wazuh-ccdc.sh"

    echo "[*] Download complete."
fi

# ---------------------------------------------------------------------------
# Run the CCDC config deployment
# ---------------------------------------------------------------------------
SPLUNK_IP="172.20.242.20"
echo "[*] Deploying CCDC defense config (Splunk IP: ${SPLUNK_IP})..."
bash "${CCDC_DIR}/setup-wazuh-ccdc.sh" "${SPLUNK_IP}"

echo ""
echo "=========================================="
echo " ALL DONE - Manager + CCDC Config"
echo "=========================================="
echo ""
echo " Dashboard:   https://${MANAGER_IP}:${DASHBOARD_PORT}"
echo " Manager IP:  ${MANAGER_IP}"
echo ""
echo " Remaining manual step:"
echo "   On the Splunk box (${SPLUNK_IP}), run:"
echo "     git clone https://github.com/jackpendergast/hawk.git"
echo "     cd hawk/wazuh-ccdc-config"
echo "     sudo bash setup-splunk-receiver.sh"
echo ""
echo " Then verify in Splunk Web with:  index=wazuh | head 10"
echo "=========================================="
