# CCDC Wazuh + ClamAV Rapid Deployment (Inject)

Wazuh deployment, ClamAV endpoint protection, CCDC defense rules, and Splunk integration.

## What This Provides

**Wazuh Manager + ClamAV** deployed across all Linux and Windows servers in under 20 minutes.

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

**Log Forwarding to Splunk** via JSON syslog on TCP 9000, with a pre-built War Room dashboard.

## Deployment

### On the Wazuh Manager (Ubuntu Wks)

`01-manager-setup.sh` handles everything. It installs Wazuh, then pauses. When you press ENTER it deploys all CCDC defense configs automatically.

```bash
git clone https://github.com/jackpendergast/hawk.git
cd hawk
sudo bash 01-manager-setup.sh
```

While the manager installs, kick off agents on the other machines (see below).

### On Each Linux Agent

```bash
curl -sO https://raw.githubusercontent.com/jackpendergast/hawk/main/02-linux-agent.sh
sudo bash 02-linux-agent.sh <MANAGER_IP>
```

Or use `wget` if `curl` is missing.

### On Each Windows Box (Elevated PowerShell)

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/jackpendergast/hawk/main/03-windows-agent.ps1" -OutFile "C:\03-windows-agent.ps1"
Set-ExecutionPolicy Bypass -Scope Process -Force
C:\03-windows-agent.ps1 -ManagerIP "<MANAGER_IP>"
```

### On the Splunk Box (Oracle Linux 172.20.242.20)

```bash
git clone https://github.com/jackpendergast/hawk.git
cd hawk/wazuh-ccdc-config
sudo bash setup-splunk-receiver.sh
```

### Verify

On the Splunk web UI:

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

The manager's `<syslog_output>` block sends every alert as JSON syslog to Splunk on TCP 9000. Splunk receives it, parses the JSON, and stores it in the `wazuh` index. No Universal Forwarder needed.

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

## File Reference

```
hawk/
  01-manager-setup.sh
  02-linux-agent.sh
  03-windows-agent.ps1
  04-verify-linux.sh
  README.md
  wazuh-ccdc-config/
    setup-wazuh-ccdc.sh
    setup-splunk-receiver.sh
    README.md
```

| File | Purpose | Where it runs |
|------|---------|---------------|
| `01-manager-setup.sh` | Installs Wazuh all-in-one (indexer, server, dashboard). Configures authd password. After install completes, pauses for ENTER, then automatically runs `setup-wazuh-ccdc.sh` to deploy all CCDC defense configs. Downloads the script from GitHub if not running from a cloned repo. | Ubuntu Wks (Wazuh Manager) |
| `02-linux-agent.sh` | Installs Wazuh agent + ClamAV. Auto-detects apt/dnf/yum. Creates systemd hourly scan timer and on-access scanning. Patches ossec.conf with FIM and syscollector. Checks for and installs `curl` if missing. | Ubuntu Ecom, Fedora Webmail, Oracle Linux Splunk |
| `03-windows-agent.ps1` | Installs Wazuh agent + ClamAV via MSI. Creates hourly scan task via schtasks.exe with a .bat wrapper to avoid path quoting issues. Patches ossec.conf with FIM, syscollector, and Windows event channel collection (Security, Sysmon, PowerShell). | AD/DNS Server 2019, Web Server 2019, FTP Server 2022, Win11 Wks |
| `04-verify-linux.sh` | Gathers evidence for inject deliverables: ClamAV listening on port 3310, service status, scan timer status, Wazuh agent connection status. | Each Linux agent |
| `wazuh-ccdc-config/setup-wazuh-ccdc.sh` | Self-contained script that generates and deploys all CCDC defense configs to the Wazuh manager: custom detection rules (ccdc_rules.xml with 20+ rules for webshells, persistence, service disruption, etc.), centralized agent.conf (pushed to all agents automatically for FIM, rootcheck, log collection, command monitoring), syslog forwarding to Splunk, lowered alert thresholds, and vulnerability detection. No external config files needed. | Called automatically by `01-manager-setup.sh` Phase 2 on the Wazuh Manager |
| `wazuh-ccdc-config/setup-splunk-receiver.sh` | Self-contained script that configures Splunk to receive Wazuh alerts. Generates all config files inline: TCP 9000 listener (inputs.conf), JSON parsing (props.conf), wazuh index (indexes.conf), Splunk app config, and the CCDC War Room dashboard with auto-refreshing panels for alerts, FIM changes, brute force, vulnerabilities, and a live feed. No external config files needed. | Oracle Linux Splunk box (172.20.242.20) |
