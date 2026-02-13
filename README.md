# Wazuh CCDC Defense Configuration

Detection rules, agent configs, and Splunk integration for the 2026 MWCCDC Qualifier.

## What This Provides

**File Integrity Monitoring** across all agents, targeting:
- Web roots (defacement/webshell detection)
- System binaries (trojaned binary detection)
- SSH keys, cron jobs, systemd services (persistence detection)
- Mail/DNS/HTTP configs (service disruption detection)
- Windows registry Run keys, scheduled tasks, services (Windows persistence)
- PAM modules (Linux auth backdoors)

**Custom CCDC Detection Rules** (100100-100163):
- Webshell upload detection (PHP, ASP, JSP in web directories)
- Web content modification / defacement alerts
- Persistence mechanism creation (cron, systemd, SSH keys, registry, scheduled tasks)
- System binary replacement / trojan detection
- PAM backdoor detection
- Brute force escalation (tighter thresholds for competition)
- Reverse shell command detection
- Windows account creation, privilege escalation, suspicious PowerShell
- Service config tampering (Postfix, Dovecot, BIND, Apache, IIS, DNS)

**Service Disruption Monitoring** via command checks every 60 seconds:
- Critical port monitoring (80, 443, 25, 110, 53, 21)
- Windows service status checks (W3SVC, DNS, FTPSVC, etc.)
- Outbound connection monitoring (reverse shell detection)
- SUID binary auditing
- Unauthorized user process detection

**Pre-existing Threat Detection:**
- Rootcheck (rootkit scanning) every 5 minutes
- Vulnerability detection against NVD/vendor databases
- Security Configuration Assessment (SCA)
- Full system inventory (packages, ports, processes)

**Log Forwarding to Splunk** via JSON syslog on TCP 9000.

## File Structure

```
wazuh-ccdc-config/
  setup-wazuh-ccdc.sh           # Deploy everything to Wazuh manager
  setup-splunk-receiver.sh      # Deploy Splunk receiver config
  manager/
    ossec.conf                  # Reference manager config (review, don't blindly replace)
    agent.conf                  # Centralized agent config (pushed to all agents)
  rules/
    ccdc_rules.xml              # Custom CCDC detection rules
  splunk/
    inputs.conf                 # Splunk TCP input on port 9000
    props.conf                  # JSON parsing for Wazuh alerts
    indexes.conf                # Create 'wazuh' index
```

## Deployment Order

### Step 1: Wazuh Manager (Ubuntu Wks)

After the Wazuh all-in-one install is complete and the dashboard is accessible:

```bash
git clone https://github.com/jackpendergast/hawk.git
cd hawk/wazuh-ccdc-config    # (or wherever you place these files)
sudo bash setup-wazuh-ccdc.sh 172.20.242.20
```

The script installs rules, deploys agent.conf, configures Splunk forwarding, and restarts the manager. The agent.conf is automatically pushed to all connected agents within a minute or two.

### Step 2: Splunk Server (Oracle Linux 172.20.242.20)

```bash
# Copy the config files to the Splunk box, then:
sudo bash setup-splunk-receiver.sh
```

Or manually on the Splunk box:

```bash
# Create the app directory
sudo mkdir -p /opt/splunk/etc/apps/wazuh_ccdc/local

# Copy the three config files
sudo cp splunk/inputs.conf /opt/splunk/etc/apps/wazuh_ccdc/local/
sudo cp splunk/props.conf /opt/splunk/etc/apps/wazuh_ccdc/local/
sudo cp splunk/indexes.conf /opt/splunk/etc/apps/wazuh_ccdc/local/

# Restart Splunk
sudo /opt/splunk/bin/splunk restart
```

### Step 3: Verify

On the Splunk web UI (https://172.20.242.20:8000 or wherever it's served):

```
index=wazuh | head 10
```

If you see events, forwarding is working.

## How Wazuh-to-Splunk Forwarding Works

```
  Wazuh Agents          Wazuh Manager              Splunk
  +-----------+     +------------------+     +------------------+
  | Linux/Win | --> | Analyzes alerts  | --> | TCP 9000         |
  | agents    |1514 | Runs rules       |JSON | index=wazuh      |
  |           |     | ossec.conf has   |syslog| sourcetype=      |
  |           |     | <syslog_output>  |     |  wazuh-alerts    |
  +-----------+     +------------------+     +------------------+
```

The `<syslog_output>` block in the manager's ossec.conf sends every alert (level 1+) as a JSON-formatted syslog message to Splunk on TCP 9000. Splunk receives it via the `[tcp://9000]` input, parses it as JSON via props.conf, and stores it in the `wazuh` index.

No Universal Forwarder needed. No Splunk app needed. It just works.

## Useful Splunk Searches for Competition Day

```spl
# All CCDC-specific rule hits
index=wazuh rule.groups="ccdc*"
| table _time agent.name rule.id rule.description rule.level

# High severity alerts (level 12+)
index=wazuh rule.level>=12
| table _time agent.name rule.description rule.level
| sort -_time

# Webshell uploads
index=wazuh rule.groups="ccdc_webshell"
| table _time agent.name syscheck.path syscheck.sha256_after

# File integrity changes by host
index=wazuh rule.groups="syscheck"
| stats count by agent.name syscheck.path syscheck.event
| sort -count

# Brute force attempts
index=wazuh rule.groups="ccdc_bruteforce" OR rule.id=5763
| stats count by srcip agent.name
| sort -count

# Persistence mechanisms detected
index=wazuh rule.groups="ccdc_persistence"
| table _time agent.name rule.description syscheck.path

# Service config tampering
index=wazuh rule.groups="ccdc_service_disruption"
| table _time agent.name rule.description syscheck.path

# All authentication failures
index=wazuh rule.groups="authentication_failed"
| stats count by srcip agent.name
| sort -count

# New files created anywhere monitored
index=wazuh syscheck.event="added"
| table _time agent.name syscheck.path

# Vulnerability scan results
index=wazuh rule.groups="vulnerability-detector"
| table _time agent.name data.vulnerability.cve data.vulnerability.severity data.vulnerability.package.name
| sort data.vulnerability.severity

# Real-time alert dashboard (auto-refresh this)
index=wazuh rule.level>=10
| timechart span=1m count by rule.groups
```

## Scoring Engine Whitelist

The active-response config whitelists your internal subnets and infrastructure IPs so the scoring engine never gets blocked. If you discover the scoring engine's source IP during the competition, add it:

```bash
# On the Wazuh manager:
sudo nano /var/ossec/etc/ossec.conf

# Add inside a <global> block:
# <white_list>SCORING_ENGINE_IP</white_list>

sudo systemctl restart wazuh-manager
```

The current whitelist covers:
- 172.20.242.0/24 and 172.20.240.0/24 (your internal subnets)
- 172.25.22.0/24 (Team 2 public pool, update if team number changes)
- Router and firewall IPs
- Localhost

## Quick Reference: Rule IDs

| ID Range | What it detects |
|----------|----------------|
| 100100-100102 | Webshell uploads (PHP, ASP, JSP) |
| 100103 | Web index file modification (defacement) |
| 100110-100115 | Persistence (cron, systemd, SSH keys, registry, scheduled tasks) |
| 100120-100123 | Service config tampering (mail, DNS, web) |
| 100130-100131 | System binary replacement, PAM backdoors |
| 100140-100141 | Brute force escalation (SSH, Windows logon) |
| 100150 | Reverse shell detection |
| 100160-100163 | Windows attacks (new users, admin group, services, PowerShell) |

## Troubleshooting

**No alerts in Splunk:**
1. Check Wazuh manager is running: `sudo systemctl status wazuh-manager`
2. Check syslog output is in ossec.conf: `grep -A4 syslog_output /var/ossec/etc/ossec.conf`
3. Check Splunk is listening: On Splunk box, `ss -tlnp | grep 9000`
4. Check firewall: From manager, `nc -zv 172.20.242.20 9000`

**Agent not picking up new config:**
1. Force push: `sudo /var/ossec/bin/agent_control -R -a`
2. Check agent group: `sudo /var/ossec/bin/agent_groups -l`
3. Make sure agent is in "default" group

**Rules not firing:**
1. Verify rules loaded: `sudo /var/ossec/bin/wazuh-analysisd -t`
2. Check rule file permissions: `ls -la /var/ossec/etc/rules/ccdc_rules.xml`
3. Test a rule: modify a file in /var/www and check alerts in dashboard

**Active response blocking the scoring engine:**
1. Check blocked IPs: `sudo iptables -L -n | grep DROP`
2. Unblock an IP: `sudo /var/ossec/active-response/bin/firewall-drop delete - <IP> -`
3. Add to whitelist in ossec.conf and restart
