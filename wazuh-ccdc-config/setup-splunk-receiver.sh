#!/usr/bin/env bash
# ============================================================================
# setup-splunk-receiver.sh  -  Configure Splunk to receive Wazuh alerts
# Run on: Splunk / Oracle Linux box (172.20.242.20)
# Usage:  sudo bash setup-splunk-receiver.sh
#
# Self-contained: all config files are generated inline.
# No external files needed.
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

# Create app directory
APP_DIR="$SPLUNK_HOME/etc/apps/wazuh_ccdc/local"
VIEWS_DIR="$APP_DIR/data/ui/views"
NAV_DIR="$APP_DIR/data/ui/nav"
mkdir -p "$APP_DIR" "$VIEWS_DIR" "$NAV_DIR"

# ---------------------------------------------------------------------------
# inputs.conf - TCP listener on port 9000
# ---------------------------------------------------------------------------
echo "[*] Writing inputs.conf..."
cat > "$APP_DIR/inputs.conf" <<'EOF'
[tcp://9000]
connection_host = ip
sourcetype = wazuh-alerts
index = wazuh
disabled = false
EOF

# ---------------------------------------------------------------------------
# props.conf - JSON parsing for Wazuh alerts
# ---------------------------------------------------------------------------
echo "[*] Writing props.conf..."
cat > "$APP_DIR/props.conf" <<'EOF'
[wazuh-alerts]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = "timestamp"\s*:\s*"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%z
MAX_TIMESTAMP_LOOKAHEAD = 40
TRUNCATE = 65535
KV_MODE = json
CHARSET = UTF-8
EOF

# ---------------------------------------------------------------------------
# indexes.conf - Create the wazuh index
# ---------------------------------------------------------------------------
echo "[*] Writing indexes.conf..."
cat > "$APP_DIR/indexes.conf" <<'EOF'
[wazuh]
coldPath = $SPLUNK_DB/wazuh/colddb
homePath = $SPLUNK_DB/wazuh/db
thawedPath = $SPLUNK_DB/wazuh/thaweddb
maxTotalDataSizeMB = 5000
EOF

# ---------------------------------------------------------------------------
# app.conf
# ---------------------------------------------------------------------------
echo "[*] Writing app.conf..."
cat > "$APP_DIR/app.conf" <<'EOF'
[install]
is_configured = true

[ui]
is_visible = true
label = Wazuh CCDC Alerts

[launcher]
version = 1.0.0
description = Receives and indexes Wazuh alerts for CCDC competition
EOF

# ---------------------------------------------------------------------------
# Navigation
# ---------------------------------------------------------------------------
cat > "$NAV_DIR/default.xml" <<'EOF'
<nav>
  <view name="ccdc_warroom" default="true"/>
</nav>
EOF

# ---------------------------------------------------------------------------
# CCDC War Room Dashboard
# ---------------------------------------------------------------------------
echo "[*] Writing CCDC War Room dashboard..."
cat > "$VIEWS_DIR/ccdc_warroom.xml" <<'DASHEOF'
<dashboard>
  <label>CCDC War Room</label>
  <description>Real-time Wazuh alerts for CCDC competition defense</description>

  <row>
    <panel>
      <single>
        <title>Critical Alerts (Level 12+)</title>
        <search>
          <query>index=wazuh rule.level>=12 earliest=-15m | stats count</query>
          <earliest>-15m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
        </search>
        <option name="colorBy">value</option>
        <option name="rangeColors">["0x53a051","0xf8be34","0xdc4e41"]</option>
        <option name="rangeValues">[0,5]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>CCDC Rule Hits (Last 15m)</title>
        <search>
          <query>index=wazuh rule.groups="ccdc*" earliest=-15m | stats count</query>
          <earliest>-15m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
        </search>
        <option name="colorBy">value</option>
        <option name="rangeColors">["0x53a051","0xf8be34","0xdc4e41"]</option>
        <option name="rangeValues">[0,3]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>FIM Changes (Last 15m)</title>
        <search>
          <query>index=wazuh syscheck.event=* earliest=-15m | stats count</query>
          <earliest>-15m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
        </search>
      </single>
    </panel>
    <panel>
      <single>
        <title>Auth Failures (Last 15m)</title>
        <search>
          <query>index=wazuh rule.groups="authentication_failed" earliest=-15m | stats count</query>
          <earliest>-15m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
        </search>
        <option name="colorBy">value</option>
        <option name="rangeColors">["0x53a051","0xf8be34","0xdc4e41"]</option>
        <option name="rangeValues">[0,10]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>Active Agents</title>
        <search>
          <query>index=wazuh earliest=-5m | stats dc(agent.name) as agents</query>
          <earliest>-5m</earliest>
          <latest>now</latest>
          <refresh>60s</refresh>
        </search>
      </single>
    </panel>
  </row>

  <row>
    <panel>
      <chart>
        <title>Alert Timeline (Level 10+)</title>
        <search>
          <query>index=wazuh rule.level>=10 | timechart span=2m count by agent.name</query>
          <earliest>-60m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Top Attacked Hosts</title>
        <search>
          <query>index=wazuh rule.level>=8 | stats count by agent.name | sort -count</query>
          <earliest>-60m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
  </row>

  <row>
    <panel>
      <table>
        <title>CCDC Rule Alerts (Webshells, Persistence, Disruption)</title>
        <search>
          <query>index=wazuh rule.groups="ccdc*"
| table _time agent.name rule.id rule.description rule.level syscheck.path
| sort -_time</query>
          <earliest>-4h</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
        </search>
        <option name="drilldown">none</option>
        <option name="count">15</option>
      </table>
    </panel>
  </row>

  <row>
    <panel>
      <table>
        <title>Recent File Changes</title>
        <search>
          <query>index=wazuh syscheck.event=*
| table _time agent.name syscheck.event syscheck.path syscheck.sha256_after
| sort -_time</query>
          <earliest>-60m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
        </search>
        <option name="drilldown">none</option>
        <option name="count">10</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Top Brute Force Sources</title>
        <search>
          <query>index=wazuh (rule.groups="authentication_failed" OR rule.groups="ccdc_bruteforce")
| stats count by srcip agent.name
| sort -count</query>
          <earliest>-60m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
        </search>
        <option name="drilldown">none</option>
        <option name="count">10</option>
      </table>
    </panel>
  </row>

  <row>
    <panel>
      <table>
        <title>Critical/High Vulnerabilities Detected</title>
        <search>
          <query>index=wazuh rule.groups="vulnerability-detector" (data.vulnerability.severity="Critical" OR data.vulnerability.severity="High")
| stats count by agent.name data.vulnerability.cve data.vulnerability.severity data.vulnerability.package.name
| sort data.vulnerability.severity -count</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
          <refresh>300s</refresh>
        </search>
        <option name="drilldown">none</option>
        <option name="count">15</option>
      </table>
    </panel>
  </row>

  <row>
    <panel>
      <event>
        <title>Live Alert Feed (Level 8+)</title>
        <search>
          <query>index=wazuh rule.level>=8 | sort -_time</query>
          <earliest>-30m</earliest>
          <latest>now</latest>
          <refresh>15s</refresh>
        </search>
        <option name="count">20</option>
        <option name="list.drilldown">none</option>
      </event>
    </panel>
  </row>

</dashboard>
DASHEOF

echo "[*] All config files written."

# ---------------------------------------------------------------------------
# Open firewall port if firewalld is running
# ---------------------------------------------------------------------------
if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
    firewall-cmd --add-port=9000/tcp --permanent
    firewall-cmd --reload
    echo "[*] Firewall port 9000/tcp opened"
fi

# ---------------------------------------------------------------------------
# Restart Splunk
# ---------------------------------------------------------------------------
echo "[*] Restarting Splunk..."
"$SPLUNK_HOME/bin/splunk" restart

echo ""
echo "=========================================="
echo " Splunk receiver configured"
echo "=========================================="
echo " Listening on TCP port 9000 for Wazuh alerts"
echo " Index: wazuh"
echo " Sourcetype: wazuh-alerts"
echo " Dashboard: CCDC War Room (default view)"
echo ""
echo " Verify in Splunk Web:"
echo "   Search: index=wazuh | head 10"
echo ""
echo " Useful CCDC searches:"
echo '   index=wazuh rule.groups="ccdc*" | table _time agent.name rule.description rule.level'
echo '   index=wazuh rule.level>=12 | table _time agent.name rule.description'
echo '   index=wazuh rule.groups="ccdc_webshell" | table _time agent.name syscheck.path'
echo "=========================================="
