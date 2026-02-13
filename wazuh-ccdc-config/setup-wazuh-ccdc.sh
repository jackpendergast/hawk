#!/usr/bin/env bash
# ============================================================================
# setup-wazuh-ccdc.sh  -  Deploy CCDC detection config to Wazuh Manager
# Run on: Ubuntu Wks (Wazuh Manager/Dashboard)
# Usage:  sudo bash setup-wazuh-ccdc.sh [SPLUNK_IP]
#
# Self-contained: all config files are generated inline.
# No external files needed.
# ============================================================================
set -euo pipefail

SPLUNK_IP="${1:-172.20.242.20}"
WAZUH_DIR="/var/ossec"

echo "=========================================="
echo " Wazuh CCDC Config Deployment"
echo " Splunk IP: ${SPLUNK_IP}"
echo "=========================================="

# ---------------------------------------------------------------------------
# 1. Install custom CCDC detection rules
# ---------------------------------------------------------------------------
echo "[*] Installing CCDC custom rules..."

cat > "$WAZUH_DIR/etc/rules/ccdc_rules.xml" <<'RULESEOF'
<!--
  CCDC Custom Detection Rules
  Rule ID range: 100100 - 100199
-->
<group name="ccdc,">

  <!-- WEBSHELL DETECTION -->
  <rule id="100100" level="14">
    <if_sid>554</if_sid>
    <match type="pcre2">\.php$|\.phtml$|\.php[345]$</match>
    <field name="syscheck.path" type="pcre2">/var/www|/srv/www|/var/html|inetpub|wwwroot</field>
    <description>CCDC: New PHP file in web directory - possible webshell [$(syscheck.path)]</description>
    <group>ccdc_webshell,attack.persistence,</group>
  </rule>

  <rule id="100101" level="14">
    <if_sid>554</if_sid>
    <match type="pcre2">\.asp$|\.aspx$|\.ashx$|\.asmx$</match>
    <field name="syscheck.path" type="pcre2">inetpub|wwwroot</field>
    <description>CCDC: New ASP/ASPX file in IIS web directory - possible webshell [$(syscheck.path)]</description>
    <group>ccdc_webshell,attack.persistence,</group>
  </rule>

  <rule id="100102" level="14">
    <if_sid>554</if_sid>
    <match type="pcre2">\.jsp$|\.jspx$|\.war$</match>
    <field name="syscheck.path" type="pcre2">/var/www|/opt/tomcat|/srv|webapps</field>
    <description>CCDC: New JSP/WAR file in web directory - possible webshell [$(syscheck.path)]</description>
    <group>ccdc_webshell,attack.persistence,</group>
  </rule>

  <!-- WEB CONTENT MODIFICATION (DEFACEMENT) -->
  <rule id="100103" level="12">
    <if_sid>550,553</if_sid>
    <field name="syscheck.path" type="pcre2">index\.(html?|php|asp|aspx)|default\.(html?|asp|aspx)</field>
    <description>CCDC: Web index file modified - possible defacement [$(syscheck.path)]</description>
    <group>ccdc_defacement,attack.impact,</group>
  </rule>

  <!-- PERSISTENCE DETECTION -->
  <rule id="100110" level="12">
    <if_sid>554</if_sid>
    <field name="syscheck.path" type="pcre2">/etc/cron|/var/spool/cron|/etc/systemd/system|/etc/init\.d</field>
    <description>CCDC: New persistence mechanism detected [$(syscheck.path)]</description>
    <group>ccdc_persistence,attack.persistence,</group>
  </rule>

  <rule id="100111" level="13">
    <if_sid>550,553,554</if_sid>
    <field name="syscheck.path" type="pcre2">authorized_keys</field>
    <description>CCDC: SSH authorized_keys modified or added [$(syscheck.path)]</description>
    <group>ccdc_persistence,attack.persistence,</group>
  </rule>

  <rule id="100112" level="12">
    <if_sid>550,553</if_sid>
    <field name="syscheck.path" type="pcre2">/etc/passwd$|/etc/shadow$</field>
    <description>CCDC: Password/shadow file modified - possible new account or credential change</description>
    <group>ccdc_persistence,attack.persistence,</group>
  </rule>

  <rule id="100113" level="12">
    <if_sid>550,553</if_sid>
    <field name="syscheck.path" type="pcre2">/etc/sudoers</field>
    <description>CCDC: Sudoers modified - possible privilege escalation setup</description>
    <group>ccdc_privesc,attack.privilege_escalation,</group>
  </rule>

  <!-- Windows persistence -->
  <rule id="100114" level="12">
    <if_sid>750,751</if_sid>
    <field name="syscheck.path" type="pcre2">CurrentVersion\\Run|CurrentVersion\\RunOnce</field>
    <description>CCDC: Windows Run key modified - possible persistence [$(syscheck.path)]</description>
    <group>ccdc_persistence,attack.persistence,</group>
  </rule>

  <rule id="100115" level="12">
    <if_sid>554</if_sid>
    <field name="syscheck.path" type="pcre2">Windows\\System32\\Tasks</field>
    <description>CCDC: New Windows scheduled task file - possible persistence [$(syscheck.path)]</description>
    <group>ccdc_persistence,attack.persistence,</group>
  </rule>

  <!-- SERVICE DISRUPTION -->
  <rule id="100120" level="13">
    <if_sid>550,553</if_sid>
    <field name="syscheck.path" type="pcre2">/etc/postfix/main\.cf|/etc/dovecot|/etc/mail</field>
    <description>CCDC: Mail service config modified - check SMTP/POP3 scoring [$(syscheck.path)]</description>
    <group>ccdc_service_disruption,</group>
  </rule>

  <rule id="100121" level="13">
    <if_sid>550,553</if_sid>
    <field name="syscheck.path" type="pcre2">/etc/bind|/var/named|/etc/named\.conf</field>
    <description>CCDC: DNS config/zone file modified - check DNS scoring [$(syscheck.path)]</description>
    <group>ccdc_service_disruption,</group>
  </rule>

  <rule id="100122" level="13">
    <if_sid>550,553</if_sid>
    <field name="syscheck.path" type="pcre2">/etc/apache2|/etc/httpd|/etc/nginx</field>
    <description>CCDC: Web server config modified - check HTTP/HTTPS scoring [$(syscheck.path)]</description>
    <group>ccdc_service_disruption,</group>
  </rule>

  <rule id="100123" level="13">
    <if_sid>550,553</if_sid>
    <field name="syscheck.path" type="pcre2">System32\\dns|System32\\inetsrv</field>
    <description>CCDC: Windows DNS/IIS config modified - check service scoring [$(syscheck.path)]</description>
    <group>ccdc_service_disruption,</group>
  </rule>

  <!-- BINARY REPLACEMENT / TROJAN DETECTION -->
  <rule id="100130" level="14">
    <if_sid>550,553</if_sid>
    <field name="syscheck.path" type="pcre2">^/(usr/)?(bin|sbin)/</field>
    <description>CCDC: System binary modified - possible trojan [$(syscheck.path)]</description>
    <group>ccdc_trojan,attack.persistence,</group>
  </rule>

  <!-- PAM BACKDOOR -->
  <rule id="100131" level="14">
    <if_sid>550,553,554</if_sid>
    <field name="syscheck.path" type="pcre2">/etc/pam\.d/|/lib.*security.*pam</field>
    <description>CCDC: PAM config or module modified - possible auth backdoor [$(syscheck.path)]</description>
    <group>ccdc_backdoor,attack.persistence,</group>
  </rule>

  <!-- BRUTE FORCE ESCALATION -->
  <rule id="100140" level="10" frequency="5" timeframe="60">
    <if_matched_sid>5710</if_matched_sid>
    <description>CCDC: Rapid SSH brute force (5 failures in 60s)</description>
    <group>ccdc_bruteforce,attack.credential_access,</group>
  </rule>

  <rule id="100141" level="10" frequency="5" timeframe="60">
    <if_matched_sid>18100</if_matched_sid>
    <description>CCDC: Rapid Windows logon failures (5 in 60s)</description>
    <group>ccdc_bruteforce,attack.credential_access,</group>
  </rule>

  <!-- REVERSE SHELL DETECTION -->
  <rule id="100150" level="12">
    <if_sid>530</if_sid>
    <match type="pcre2">nc\s+-[le]|ncat\s|socat\s|/dev/tcp|bash\s+-i|python.*socket|perl.*socket</match>
    <description>CCDC: Possible reverse shell command detected</description>
    <group>ccdc_reverseshell,attack.execution,</group>
  </rule>

  <!-- WINDOWS-SPECIFIC ATTACKS -->
  <rule id="100160" level="12">
    <if_sid>60106</if_sid>
    <description>CCDC: New Windows user account created (EventID 4720)</description>
    <group>ccdc_persistence,attack.persistence,</group>
  </rule>

  <rule id="100161" level="14">
    <if_sid>60144</if_sid>
    <description>CCDC: User added to Administrators group (EventID 4732)</description>
    <group>ccdc_privesc,attack.privilege_escalation,</group>
  </rule>

  <rule id="100162" level="10">
    <if_sid>60010</if_sid>
    <description>CCDC: New Windows service installed - check for persistence</description>
    <group>ccdc_persistence,attack.persistence,</group>
  </rule>

  <rule id="100163" level="12">
    <if_sid>91801</if_sid>
    <match type="pcre2">Invoke-Expression|IEX|Invoke-WebRequest|DownloadString|EncodedCommand|-enc\s|-e\s|FromBase64|Net\.WebClient</match>
    <description>CCDC: Suspicious PowerShell execution detected</description>
    <group>ccdc_execution,attack.execution,</group>
  </rule>

</group>
RULESEOF

chown wazuh:wazuh "$WAZUH_DIR/etc/rules/ccdc_rules.xml"
chmod 640 "$WAZUH_DIR/etc/rules/ccdc_rules.xml"

# ---------------------------------------------------------------------------
# 2. Deploy centralized agent.conf
# ---------------------------------------------------------------------------
echo "[*] Deploying centralized agent.conf..."

cat > "$WAZUH_DIR/etc/shared/default/agent.conf" <<'AGENTEOF'
<agent_config>
  <syscheck>
    <disabled>no</disabled>
    <frequency>120</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
  </syscheck>
</agent_config>

<!-- LINUX AGENTS -->
<agent_config os="Linux">
  <syscheck>
    <directories realtime="yes" check_sha256="yes">/var/www</directories>
    <directories realtime="yes" check_sha256="yes">/var/www/html</directories>
    <directories realtime="yes" check_sha256="yes">/srv/www</directories>
    <directories realtime="yes" check_sha256="yes">/usr/bin,/usr/sbin,/bin,/sbin</directories>
    <directories realtime="yes">/etc/passwd,/etc/shadow,/etc/group</directories>
    <directories realtime="yes">/etc/sudoers,/etc/sudoers.d</directories>
    <directories realtime="yes">/etc/ssh</directories>
    <directories realtime="yes" restrict=".ssh">/root</directories>
    <directories realtime="yes">/etc/crontab,/etc/cron.d,/etc/cron.daily,/etc/cron.hourly</directories>
    <directories realtime="yes">/var/spool/cron</directories>
    <directories realtime="yes">/etc/systemd/system</directories>
    <directories realtime="yes">/usr/lib/systemd/system</directories>
    <directories realtime="yes">/etc/postfix</directories>
    <directories realtime="yes">/etc/dovecot</directories>
    <directories realtime="yes">/etc/bind</directories>
    <directories realtime="yes">/var/named</directories>
    <directories realtime="yes">/etc/pam.d</directories>
    <directories realtime="yes">/etc/hosts,/etc/resolv.conf</directories>
    <directories realtime="yes">/etc/iptables</directories>
    <directories realtime="yes">/etc/nftables.conf</directories>
    <ignore>/var/log</ignore>
    <ignore>/var/ossec/logs</ignore>
    <ignore>/var/ossec/queue</ignore>
    <ignore type="sregex">.log$|.tmp$|.swp$|.journal$</ignore>
  </syscheck>

  <syscollector>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <scan_on_start>yes</scan_on_start>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>yes</processes>
    <network>yes</network>
  </syscollector>

  <rootcheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
  </rootcheck>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/secure</location>
  </localfile>
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/httpd/access_log</location>
  </localfile>
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/httpd/error_log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/mail.log</location>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>ss -tlnp | grep -cE ':(80|443|25|110|53|21|3306)\s'</command>
    <alias>linux_service_port_count</alias>
    <frequency>60</frequency>
  </localfile>
  <localfile>
    <log_format>full_command</log_format>
    <command>find / -perm -4000 -type f 2>/dev/null | sort | sha256sum</command>
    <alias>suid_hash_check</alias>
    <frequency>300</frequency>
  </localfile>
  <localfile>
    <log_format>full_command</log_format>
    <command>ps -eo user,pid,ppid,cmd --sort=-%cpu | grep -vE '^(root|www-data|postfix|dovecot|named|bind|nobody|syslog|daemon|messagebus|_chrony|wazuh|clamav|USER)' | head -20</command>
    <alias>suspicious_user_processes</alias>
    <frequency>120</frequency>
  </localfile>
  <localfile>
    <log_format>full_command</log_format>
    <command>ss -tnp state established | grep -vE '(172\.20\.24[02]\.|127\.0\.0\.1|::1)' | grep -v 'sshd' | head -20</command>
    <alias>outbound_connections</alias>
    <frequency>60</frequency>
  </localfile>
  <localfile>
    <log_format>full_command</log_format>
    <command>for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | grep -v '^#' | grep -v '^$' | sed "s/^/$u: /"; done</command>
    <alias>crontab_audit</alias>
    <frequency>120</frequency>
  </localfile>
  <localfile>
    <log_format>full_command</log_format>
    <command>find /home /root -name authorized_keys -exec sh -c 'echo "=== {} ==="; cat {}' \; 2>/dev/null | sha256sum</command>
    <alias>ssh_keys_hash</alias>
    <frequency>120</frequency>
  </localfile>
</agent_config>

<!-- WINDOWS AGENTS -->
<agent_config os="Windows">
  <syscheck>
    <directories realtime="yes" check_sha256="yes">C:\inetpub\wwwroot</directories>
    <directories realtime="yes" check_sha256="yes">C:\Windows\System32\drivers\etc</directories>
    <directories realtime="yes">C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup</directories>
    <directories realtime="yes">C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp</directories>
    <directories realtime="yes">C:\Windows\System32\Tasks</directories>
    <directories realtime="yes">C:\Windows\System32\WindowsPowerShell\v1.0</directories>
    <directories realtime="yes">C:\Windows\System32\dns</directories>
    <directories realtime="yes">C:\inetpub\ftproot</directories>
    <directories realtime="yes">C:\Users</directories>
    <ignore>C:\Windows\Temp</ignore>
    <ignore type="sregex">.log$|.tmp$|.etl$</ignore>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies</windows_registry>
  </syscheck>

  <syscollector>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <scan_on_start>yes</scan_on_start>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>yes</processes>
    <network>yes</network>
    <hotfixes>yes</hotfixes>
  </syscollector>

  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID != 5145 and EventID != 5156 and EventID != 4689]</query>
  </localfile>
  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>DNS Server</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>powershell -Command "Get-Service W3SVC,DNS,IISADMIN,FTPSVC,WinRM,WazuhSvc -ErrorAction SilentlyContinue | Select Status,Name | ConvertTo-Json -Compress"</command>
    <alias>win_service_check</alias>
    <frequency>60</frequency>
  </localfile>
  <localfile>
    <log_format>full_command</log_format>
    <command>powershell -Command "Get-ScheduledTask | Where-Object {$_.State -eq 'Ready' -and $_.Author -ne 'Microsoft Corporation'} | Select TaskName,Author | ConvertTo-Json -Compress"</command>
    <alias>win_scheduled_tasks</alias>
    <frequency>120</frequency>
  </localfile>
  <localfile>
    <log_format>full_command</log_format>
    <command>powershell -Command "Get-NetTCPConnection -State Established | Where-Object {$_.RemoteAddress -notmatch '^(172\.20\.24|127\.0\.0\.1|::1)'} | Select RemoteAddress,RemotePort,OwningProcess | ConvertTo-Json -Compress"</command>
    <alias>win_outbound_connections</alias>
    <frequency>60</frequency>
  </localfile>
  <localfile>
    <log_format>full_command</log_format>
    <command>powershell -Command "Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Select Name,ObjectClass | ConvertTo-Json -Compress"</command>
    <alias>win_local_admins</alias>
    <frequency>120</frequency>
  </localfile>
</agent_config>
AGENTEOF

chown wazuh:wazuh "$WAZUH_DIR/etc/shared/default/agent.conf"
chmod 640 "$WAZUH_DIR/etc/shared/default/agent.conf"

# ---------------------------------------------------------------------------
# 3. Configure syslog output to Splunk
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
    sed -i "/<syslog_output>/,/<\/syslog_output>/s|<server>.*</server>|<server>${SPLUNK_IP}</server>|" "$OSSEC_CONF"
    echo "[*] Existing syslog output updated."
fi

# ---------------------------------------------------------------------------
# 4. Tune alert levels
# ---------------------------------------------------------------------------
echo "[*] Tuning alert levels..."
if grep -q '<log_alert_level>' "$OSSEC_CONF"; then
    sed -i 's|<log_alert_level>[0-9]*</log_alert_level>|<log_alert_level>1</log_alert_level>|' "$OSSEC_CONF"
else
    sed -i '/<alerts>/a\    <log_alert_level>1</log_alert_level>' "$OSSEC_CONF"
fi

# ---------------------------------------------------------------------------
# 5. Enable logall_json
# ---------------------------------------------------------------------------
if ! grep -q '<logall_json>' "$OSSEC_CONF"; then
    sed -i '/<global>/a\    <logall_json>yes</logall_json>' "$OSSEC_CONF"
fi

# ---------------------------------------------------------------------------
# 6. Add custom rules to ruleset
# ---------------------------------------------------------------------------
if ! grep -q 'ccdc_rules.xml' "$OSSEC_CONF"; then
    sed -i '/<\/ruleset>/i\    <include>rules/ccdc_rules.xml</include>' "$OSSEC_CONF" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 7. Enable vulnerability detection
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
# 8. Validate config
# ---------------------------------------------------------------------------
echo "[*] Validating configuration..."
if "$WAZUH_DIR/bin/wazuh-analysisd" -t 2>&1 | grep -q "Configuration OK"; then
    echo "[*] Config validation passed."
else
    echo "[!] Config validation had warnings (may still work)."
fi

# ---------------------------------------------------------------------------
# 9. Restart Wazuh manager
# ---------------------------------------------------------------------------
echo "[*] Restarting Wazuh manager..."
systemctl restart wazuh-manager

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
