# CCDC Wazuh + ClamAV Rapid Deployment (Inject SVRA12T)

## Overview

Four scripts to deploy Wazuh Manager (all-in-one) + ClamAV across the full competition environment in under 20 minutes.

## Environment

| Host             | OS                 | IP              | Role                    |
|------------------|--------------------|-----------------|-------------------------|
| Ubuntu Wks       | Ubuntu 24.04 Desk  | DHCP            | Wazuh Manager/Dashboard |
| Ecom             | Ubuntu 24.04 Srv   | 172.20.242.30   | Agent + ClamAV          |
| Webmail          | Fedora 42          | 172.20.242.40   | Agent + ClamAV          |
| Splunk           | Oracle Linux 9.2   | 172.20.242.20   | Agent + ClamAV          |
| AD/DNS           | Server 2019        | 172.20.240.102  | Agent + ClamAV          |
| Web Server       | Server 2019        | 172.20.240.101  | Agent + ClamAV          |
| FTP Server       | Server 2022        | 172.20.240.104  | Agent + ClamAV          |
| Win11 Wks        | Windows 11         | 172.20.240.100  | Agent + ClamAV          |

## Scripts

| File                     | What it does                                   | Run where        |
|--------------------------|------------------------------------------------|------------------|
| `01-manager-setup.sh`    | Installs Wazuh indexer + server + dashboard    | Ubuntu Wks       |
| `02-linux-agent.sh`      | Installs Wazuh agent + ClamAV (apt/dnf aware)  | Each Linux agent |
| `03-windows-agent.ps1`   | Installs Wazuh agent + ClamAV via MSI          | Each Windows box |
| `04-verify-linux.sh`     | Gathers ClamAV + agent evidence for deliverable| Each Linux agent |

## Deployment Order (Target: ~18 minutes)

### Phase 1: Manager (minutes 0-10)

The all-in-one install takes the longest. Start it first.

```bash
# On Ubuntu Wks -- clone your repo, then:
git clone https://github.com/YOUR_REPO/wazuh-ccdc-deploy.git
cd wazuh-ccdc-deploy
sudo bash 01-manager-setup.sh
```

Note the manager IP it detects. You will need it for every agent.

### Phase 2: Agents in parallel (minutes 3-18)

While the manager is installing, open terminals to the other machines and start agent installs. They will register with the manager once it comes up.

**Linux agents (3 machines):**

```bash
# SCP or curl the script to each box, then:
curl -sO https://raw.githubusercontent.com/YOUR_REPO/wazuh-ccdc-deploy/main/02-linux-agent.sh
sudo bash 02-linux-agent.sh <MANAGER_IP>
```

**Windows agents (4 machines):**

```powershell
# Download the script, then:
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/YOUR_REPO/wazuh-ccdc-deploy/main/03-windows-agent.ps1" -OutFile "03-windows-agent.ps1"
.\03-windows-agent.ps1 -ManagerIP "<MANAGER_IP>"
```

### Phase 3: Verify + Screenshot (minutes 16-20)

1. Open the Wazuh dashboard at `https://<MANAGER_IP>:443`
2. Log in with the admin credentials printed by the manager script
3. Navigate to Agents -- all 7 should show green
4. Screenshot for the memo

Run verification on each Linux box:

```bash
sudo bash 04-verify-linux.sh
```

Run verification on each Windows box:

```powershell
Get-Service "ClamAV*" | Select Status, Name, DisplayName
```

## Key Details from the Inject

These are handled by the scripts, but worth knowing:

- **ClamAV on Windows**: MSI with `ADDLOCAL="ClamAV,FreshClam"`, hourly scheduled task, clamd service for on-access
- **ClamAV on Linux**: daemon + systemd timer for hourly scans, clamonacc for real-time where available
- **Wazuh agent ossec.conf modules**:
  - `syscollector` enabled
  - `FIM/syscheck` with `realtime="yes"` on `C:\Users` (Windows) and `/home`, `/etc`, `/var/www` (Linux)
  - Windows event channels: `Security` and `Microsoft-Windows-Sysmon/Operational`
- **Restart the agent** after config changes (scripts handle this)

## Deliverables Checklist

- [ ] Screenshot of Wazuh dashboard with all agents green
- [ ] Evidence of ClamAV on each Linux node: `sudo ss -ltnp | grep :3310`
- [ ] Evidence of ClamAV on each Windows node: `Get-Service "ClamAV*" | Select Status,Name,DisplayName`
- [ ] Business memo documenting successful install (write separately)

## Troubleshooting

**Agent not showing in dashboard:**
- Check agent can reach manager: `curl -k https://<MANAGER_IP>:1514` (will error, but should connect)
- Check firewall rules on Palo Alto / Cisco FTD for ports 1514 (agent enrollment) and 1515 (agent comms)
- Restart agent: `systemctl restart wazuh-agent` or `Restart-Service WazuhSvc`

**ClamAV not listening on 3310:**
- Check `clamd.conf` has `TCPSocket 3310` and `TCPAddr 127.0.0.1` (or `LocalSocket`)
- On RHEL-family: check `/etc/clamd.d/scan.conf`, remove the `Example` line

**Agents behind different firewalls:**
- Linux agents (172.20.242.x) are behind Palo Alto, Windows agents (172.20.240.x) are behind Cisco FTD
- Manager is on the Linux side (172.20.242.x DHCP), so Windows agents cross firewall boundaries
- Make sure routing and firewall rules allow 172.20.240.x -> manager IP on ports 1514-1515
