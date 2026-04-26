# Victim VM setup

The victim VM is the Windows endpoint that gets attacked during Phase 3 detection validation. It must be:

- Reachable from the self-hosted runner via WinRM
- Forwarding logs to the lab Splunk
- Pre-loaded with Invoke-AtomicRedTeam (IART) and the atomics library
- Snapshottable via Proxmox so we can revert to a clean state between tests
- Network-isolated from production lab segments

This document is the build runbook. Do this once, snapshot a baseline, and reference that baseline forever.

## Specs

| Item | Value |
|---|---|
| OS | Windows 10 Pro 22H2 (or Windows 11 Pro 23H2) |
| vCPUs | 4 |
| RAM | 4 GB |
| Disk | 60 GB thin-provisioned |
| Network | dedicated `CORP-DETONATION` VLAN, no internet egress |
| Domain | `deltacode.local` (member, not DC) |
| Hostname | `WIN10-VICTIM` |
| Local admin | `detonator` |
| VMID (Proxmox) | record this — orchestrator needs it |

## Network design

The victim must NOT be on the same VLAN as production assets. Recommended layout:

```
                 ┌──────────────────────────────┐
                 │ MGMT VLAN (self-hosted runner)│
                 └──────────┬───────────────────┘
                            │ WinRM 5985, Proxmox API 8006, Splunk 8089
                            ▼
                 ┌──────────────────────────────┐
                 │ CORP-DETONATION VLAN          │
                 │  - WIN10-VICTIM               │
                 │  - DC replica (read-only)     │
                 └──────────┬───────────────────┘
                            │ Sysmon → UF → Splunk
                            ▼
                 ┌──────────────────────────────┐
                 │ SOC VLAN (Splunk indexer)    │
                 └──────────────────────────────┘
```

pfSense rules:
- Allow MGMT → CORP-DETONATION on TCP 5985 (WinRM HTTP) only
- Allow CORP-DETONATION → SOC on TCP 9997 (UF) only
- Block all other inter-VLAN
- Block CORP-DETONATION → internet entirely (atomics that fetch payloads should fail loudly, not silently succeed)

## Build steps

### 1. Install Windows and join domain

Standard install. Join `deltacode.local`. Reboot.

### 2. Configure Sysmon

Use the SwiftOnSecurity sysmon-config or Olaf Hartong's modular config. **Pre-stage the binary on the image** so the snapshot baseline includes a running Sysmon — orchestrator runs assume Sysmon is already up.

```powershell
# As local admin, from elevated PowerShell
$sysmonZip = "C:\install\Sysmon.zip"
Expand-Archive $sysmonZip -DestinationPath "C:\Program Files\Sysmon"
Invoke-WebRequest "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" `
  -OutFile "C:\Program Files\Sysmon\sysmonconfig.xml" -UseBasicParsing
& "C:\Program Files\Sysmon\Sysmon64.exe" -accepteula -i "C:\Program Files\Sysmon\sysmonconfig.xml"
```

Verify:
```powershell
Get-Service Sysmon64
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5
```

### 3. Install Splunk Universal Forwarder

Forward to `splunk.deltacode.local:9997` with the index `windows`. Sample `inputs.conf`:

```ini
[WinEventLog://Security]
disabled = 0
index = windows
sourcetype = WinEventLog:Security

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = windows
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
renderXml = true
```

Verify events are landing in Splunk:
```spl
index=windows host=WIN10-VICTIM | head 10
```

### 4. Configure WinRM for the runner

```powershell
# As local admin
Enable-PSRemoting -Force
winrm quickconfig -force
winrm set winrm/config/service/auth '@{Basic="false";Kerberos="true";Negotiate="true";Certificate="false";CredSSP="false"}'

# Allow only the runner subnet (replace with your MGMT VLAN CIDR)
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -RemoteAddress 10.10.1.0/24
```

Use Kerberos auth in production. NTLM is acceptable for the lab if the runner is domain-joined.

### 5. Install Invoke-AtomicRedTeam

```powershell
# Run as the 'detonator' local admin account
Set-ExecutionPolicy -Scope CurrentUser Bypass -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Import-Module Invoke-AtomicRedTeam -Force

# Verify
Get-AtomicTechnique -Path C:\AtomicRedTeam\atomics\T1003.001
```

### 6. Pre-cache atomic prereqs

This step matters for CI runtime. Walk through every test number listed in `tests/atomics/atomic_mapping.yml` and run `-GetPrereqs` once on the build machine, so the snapshot baseline already has tools downloaded:

```powershell
$tests = @(
  @{ tech = 'T1003.001'; num = 1 },
  @{ tech = 'T1059.001'; num = 2 },
  @{ tech = 'T1059.001'; num = 4 },
  @{ tech = 'T1003.006'; num = 1 },
  @{ tech = 'T1218.011'; num = 1 },
  @{ tech = 'T1218.011'; num = 6 }
)
foreach ($t in $tests) {
  Invoke-AtomicTest $t.tech -TestNumbers $t.num -GetPrereqs
}
```

Without this, the first CI run will spend 5+ minutes downloading procdump, mimikatz, etc. while you watch.

### 7. Disable Defender real-time protection

Defender will block half the atomics by design. For a detection-validation lab, that defeats the point — your *detections* are doing the protecting. Disable in elevated PowerShell:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -SubmitSamplesConsent NeverSend
Set-MpPreference -MAPSReporting Disabled
Add-MpPreference -ExclusionPath 'C:\AtomicRedTeam'
```

### 8. Take the baseline snapshot

This is the snapshot the orchestrator clones from for every test:

```bash
# From the Proxmox host
qm snapshot <vmid> dac-baseline --description "Phase 3 detection validation baseline" --vmstate 1
```

The orchestrator's per-test snapshots are taken from the *running* state, but the baseline is your safety net if anything ever drifts. You can always `qm rollback <vmid> dac-baseline` to recover.

## Verification checklist

Before connecting this VM to the orchestrator, confirm from the runner:

```bash
# WinRM reachable
nc -zv win10-victim.deltacode.local 5985

# Proxmox API reachable
curl -k https://pve.deltacode.local:8006/api2/json/version

# Splunk events flowing
# (run from anywhere with Splunk access)
# index=windows host=WIN10-VICTIM EventCode=1 | stats count by host
```

## Hardening (post-build)

- **Service account, not local admin:** `detonator` should be a local admin only by necessity (some atomics require elevation). Don't use Domain Admin.
- **Egress block:** confirm pfSense egress rule denies CORP-DETONATION → internet. Test with `Invoke-WebRequest http://example.com` from the victim — should fail.
- **Auto-revert if drift detected:** consider a scheduled task on the Proxmox host that compares running state against the baseline weekly and emails you if drifted.
- **Retire after N detonations:** rebuild from the baseline image monthly. Atomics leave residue even after cleanup.
