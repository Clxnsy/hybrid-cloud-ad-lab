# Lab Setup Guide — On-Premises AD to Microsoft Entra ID Hybrid Identity

Build order for the whole lab, from bare VM to a synced user signing into a cloud application.
Every value here is fictional; substitute your own.

**Estimated time:** 4–6 hours including reboots and the first sync cycle.

---

## 0. Lab topology and prerequisites

### Virtual machines

| VM name | Role | vCPU | RAM | Disk | OS |
|---|---|---|---|---|---|
| `DC01` | Domain Controller, DNS | 2 | 4 GB | 60 GB | Windows Server 2022 Standard (Desktop Experience) |
| `SRV-SYNC01` | Microsoft Entra Connect | 2 | 8 GB | 80 GB | Windows Server 2022 Standard |
| `WKS-IT-01` | Domain-joined test client | 2 | 4 GB | 60 GB | Windows 11 Enterprise |

> Entra Connect **can** be installed on a Domain Controller, and Microsoft supports it for small
> deployments. I deliberately used a separate member server because installing the sync engine — which
> reaches out to the internet on port 443 — on a Tier 0 asset breaks the tiering model this lab is
> supposed to demonstrate.

### Networking plan

| Item | Value |
|---|---|
| Lab subnet | `192.168.56.0/24` (internal / host-only) |
| `DC01` | `192.168.56.10` — static |
| `SRV-SYNC01` | `192.168.56.20` — static |
| `WKS-IT-01` | DHCP from DC01 |
| DNS for all members | `192.168.56.10` (DC01) **only** |
| Forwarder on DC01 | `1.1.1.1` |
| AD DS domain (internal) | `adlab.local` |
| NetBIOS name | `ADLAB` |
| Routable UPN suffix | `adlab.io` |
| Entra tenant | `adlabio.onmicrosoft.com` (custom domain `adlab.io` verified) |

> **Critical DNS rule:** domain members point at the DC for DNS and **nothing else**. Adding a public
> resolver as a secondary DNS server on a member is the number one cause of intermittent, maddening
> Kerberos and GPO failures — the client occasionally asks the public resolver for `_ldap._tcp.dc._msdcs`,
> gets NXDOMAIN, and fails. See `troubleshooting-scenarios.md` Scenario 2.

### Accounts you will need

| Account | Purpose |
|---|---|
| `ADLAB\Administrator` | Domain setup |
| `admin@adlabio.onmicrosoft.com` | Entra Global Administrator (cloud-only, for Entra Connect setup) |
| `ADLAB\svc-adsync` | On-prem AD DS Connector account (created automatically by Express install) |

---

## 1. Prepare `DC01` before promotion

```powershell
# Rename first: renaming AFTER promotion is a painful, unsupported-ish mess.
Rename-Computer -NewName 'DC01' -Restart

# --- after reboot ---

# Static IP. A DC MUST have a static address; DHCP on a DC breaks DNS SRV registration.
New-NetIPAddress -InterfaceAlias 'Ethernet' `
                 -IPAddress 192.168.56.10 `
                 -PrefixLength 24 `
                 -DefaultGateway 192.168.56.1

# Point the DC at itself for DNS. Post-promotion this becomes 127.0.0.1 automatically.
Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses 192.168.56.10

# Time matters: Kerberos rejects tickets with >5 minutes of clock skew.
w32tm /config /manualpeerlist:'time.windows.com,0x9' /syncfromflags:manual /reliable:yes /update
Restart-Service w32time
w32tm /resync

Get-NetIPConfiguration
```

---

## 2. Promote `DC01` to a Domain Controller (`adlab.local`)

```powershell
# Install the role plus management tools (RSAT). Without -IncludeManagementTools
# you get the role but no ADUC/GPMC, which is a confusing first hour.
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

Import-Module ADDSDeployment

# Pre-flight check. Run this before the real thing - it validates prerequisites
# (name conflicts, DNS delegation, disk space) without changing anything.
Test-ADDSForestInstallation -DomainName 'adlab.local' -InstallDNS
```

Now the promotion itself:

```powershell
$safeModePassword = Read-Host -AsSecureString 'DSRM password'

Install-ADDSForest `
    -DomainName                    'adlab.local' `
    -DomainNetbiosName             'ADLAB' `
    -ForestMode                    'WinThreshold' `   # 2016 functional level
    -DomainMode                    'WinThreshold' `
    -InstallDns                    $true `
    -DatabasePath                  'C:\Windows\NTDS' `
    -LogPath                       'C:\Windows\NTDS' `
    -SysvolPath                    'C:\Windows\SYSVOL' `
    -SafeModeAdministratorPassword $safeModePassword `
    -NoRebootOnCompletion:$false `
    -Force:$true
```

**Why these choices:**

- **`adlab.local`** — a fictional, non-routable name chosen deliberately so this lab demonstrates the
  *real-world* problem of a `.local` internal domain that cannot be verified in Entra ID. The fix (adding
  a routable UPN suffix) is in Step 4, and it is the single most common hybrid-identity gotcha.
- **`WinThreshold` (2016) functional level** — enables Privileged Access Management features and modern
  Kerberos behaviour. Nothing in the lab requires 2016+, but there is no reason to start behind.
- **DSRM password** — Directory Services Restore Mode. Store it in a password manager immediately; you
  need it for authoritative restores and you will not be able to reset it easily without it.
- **NTDS/SYSVOL on C:** — acceptable in a lab. In production, separate spindles for the database and logs.

### Verify the promotion

```powershell
# After the automatic reboot, log in as ADLAB\Administrator.
Get-ADDomain    | Select-Object DNSRoot, NetBIOSName, DomainMode, DistinguishedName
Get-ADForest    | Select-Object Name, ForestMode, GlobalCatalogs, SchemaMaster
Get-Service     ADWS, KDC, Netlogon, DNS | Format-Table Name, Status

# The single most important health check on a new DC.
dcdiag /v /c /e | Select-String 'failed|passed test' | Select-Object -First 40

# SYSVOL and NETLOGON must both be shared, or Group Policy silently does nothing.
Get-SmbShare | Where-Object Name -in 'SYSVOL','NETLOGON'

# DNS SRV records - if these are missing, nothing will ever find the DC.
Resolve-DnsName -Name '_ldap._tcp.dc._msdcs.adlab.local' -Type SRV
```

Every `dcdiag` test should report **passed**. A failing `SysVolCheck` or `NetLogons` means Group Policy
will not apply — fix it now, not after you have built three more machines on top of it.

---

## 3. Build the OU structure and populate test users

```powershell
cd C:\repo\hybrid-cloud-ad-lab\powershell

# ALWAYS dry-run first.
.\Set-OUStructure.ps1 -WhatIf -Verbose
.\Set-OUStructure.ps1 -Verbose

.\New-EmployeeOnboarding.ps1 -CsvPath ..\sample-data\employees.csv -WhatIf -Verbose
.\New-EmployeeOnboarding.ps1 -CsvPath ..\sample-data\employees.csv -Verbose

Get-ADUser -Filter * -SearchBase 'OU=Departments,OU=ADLab,DC=adlab,DC=local' -Properties Department, Title |
    Format-Table SamAccountName, Name, Department, Title, Enabled -AutoSize
```

Creating users **before** installing Entra Connect is deliberate: the initial full sync then has real
objects to move, which makes it obvious whether sync is genuinely working.

---

## 4. Add a routable UPN suffix (do this BEFORE installing Entra Connect)

This is the step people skip, and it causes the most confusing hybrid problem there is.

**The problem:** `adlab.local` cannot be verified in Microsoft Entra ID — Microsoft will not let you prove
ownership of a non-routable TLD. If users sync with `mdelgado@adlab.local`, Entra ID silently rewrites
their UPN to `mdelgado@adlabio.onmicrosoft.com`. Users then sign into cloud apps with a completely
different username than they use on-premises, single sign-on breaks, and the fix afterwards is a bulk UPN
change that invalidates cached credentials for everyone.

**The fix — add `adlab.io` as an alternative UPN suffix and stamp it on every user:**

```powershell
# 1. Register the routable suffix in the forest.
Get-ADForest | Set-ADForest -UPNSuffixes @{ Add = 'adlab.io' }
(Get-ADForest).UPNSuffixes    # confirm

# 2. Repoint existing users. -WhatIf first, always.
Get-ADUser -Filter * -SearchBase 'OU=Departments,OU=ADLab,DC=adlab,DC=local' -Properties UserPrincipalName |
    ForEach-Object {
        $newUpn = '{0}@adlab.io' -f $_.SamAccountName
        Set-ADUser -Identity $_ -UserPrincipalName $newUpn -WhatIf
    }

# 3. Verify - nothing should still end in .local.
Get-ADUser -Filter * -SearchBase 'OU=Departments,OU=ADLab,DC=adlab,DC=local' -Properties UserPrincipalName |
    Select-Object SamAccountName, UserPrincipalName
```

`New-EmployeeOnboarding.ps1` already stamps `@adlab.io` via its `-UpnSuffix` parameter, so accounts created
by the script are correct from birth.

### Verify the custom domain in Entra ID

1. Entra admin center → **Identity → Settings → Domain names → + Add custom domain** → `adlab.io`.
2. Add the supplied `TXT` record at your public DNS registrar.
3. Click **Verify**. Status must read **Verified** before Entra Connect runs, otherwise sync falls back to
   `.onmicrosoft.com` and you get to do Step 4 twice.

---

## 5. Prepare `SRV-SYNC01`

```powershell
Rename-Computer -NewName 'SRV-SYNC01' -Restart

# --- after reboot ---
New-NetIPAddress -InterfaceAlias 'Ethernet' -IPAddress 192.168.56.20 -PrefixLength 24 -DefaultGateway 192.168.56.1
Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses 192.168.56.10

Add-Computer -DomainName 'adlab.local' -Credential (Get-Credential 'ADLAB\Administrator') -Restart

# --- after reboot, verify outbound connectivity ---
# Entra Connect needs 443 outbound to these endpoints. Proxy/firewall problems here
# produce a generic "unable to validate credentials" during setup, which is unhelpful.
'login.microsoftonline.com','graph.windows.net','adminwebservice.microsoftonline.com' |
    ForEach-Object { Test-NetConnection -ComputerName $_ -Port 443 } |
    Format-Table ComputerName, TcpTestSucceeded -AutoSize

# Clock skew breaks token validation as surely as it breaks Kerberos.
w32tm /query /status
```

Also install **.NET Framework 4.7.2+** and set **TLS 1.2 as default** — recent Entra Connect builds refuse
to install otherwise:

```powershell
$paths = @(
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319',
    'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
)
foreach ($p in $paths) {
    New-ItemProperty -Path $p -Name 'SystemDefaultTlsVersions' -Value 1 -PropertyType DWord -Force
    New-ItemProperty -Path $p -Name 'SchUseStrongCrypto'       -Value 1 -PropertyType DWord -Force
}
Restart-Computer
```

---

## 6. Install Microsoft Entra Connect with Password Hash Synchronisation

Download **Microsoft Entra Connect** (formerly Azure AD Connect) from the Microsoft Download Center and run
`AzureADConnect.msi` on `SRV-SYNC01`.

Choose **Customize**, not Express. Express hides the choices that matter and enables features you may not
want.

### Wizard walkthrough

| Page | Choice | Reasoning |
|---|---|---|
| Required components | Leave all boxes unticked (use the default LocalDB) | LocalDB handles up to ~100k objects. A full SQL Server is unnecessary complexity for a lab. |
| User sign-in | **Password Hash Synchronization** + **Enable single sign-on** | PHS is the most resilient option — see the note below. Seamless SSO gives domain-joined users silent sign-in. |
| Connect to Entra ID | `admin@adlabio.onmicrosoft.com` (Global Administrator) | Used once, during setup, to create the sync service principal. |
| Connect your directories | Forest `adlab.local`, **Create new AD account** | Lets the wizard create `ADLAB\svc-adsync` with exactly the right permissions — better than a hand-built account with too many rights. |
| Entra sign-in configuration | USER PRINCIPAL NAME → `userPrincipalName` | Because Step 4 gave everyone a routable UPN. If a warning about unverified domains appears, stop and fix Step 4. |
| Domain/OU filtering | **Sync selected domains and OUs** → tick `OU=ADLab` only | Never sync the whole directory. Service accounts, computer objects and built-in containers do not belong in the cloud. |
| Uniquely identifying your users | Users are represented once; Source Anchor = **let Azure manage** (`ms-DS-ConsistencyGuid`) | `ms-DS-ConsistencyGuid` is writable, so an object can be re-matched after an AD migration. `objectGUID` cannot, and locks you in. |
| Filter users and devices | Synchronize all users and devices | OU filtering already scoped it. |
| Optional features | **Password writeback** ✔ | Lets a cloud SSPR password reset flow back into on-prem AD, so users have one password everywhere. |
| Enable single sign-on | Provide Domain Admin credentials | Used once to create the `AZUREADSSOACC` computer object. Not stored. |
| Ready to configure | ✔ Start the synchronization process | |

### Why Password Hash Synchronisation

- **Resilience** — if the on-prem DC or the internet link dies, cloud authentication keeps working because
  Entra ID validates the hash itself. Pass-through Authentication and ADFS both hard-depend on on-prem
  availability; the DC going down takes Microsoft 365 with it.
- **Simplicity** — no additional agents, no certificates to renew, no federation farm.
- **Security features** — enables Entra ID Protection leaked-credential detection, which compares synced
  hashes against known-breached credentials. PTA and ADFS cannot do this.
- **What actually syncs** — *not* the password, and *not* the NTLM hash. The hash is itself hashed again
  (SHA-256, 1,000 rounds of PBKDF2-HMAC-SHA256, per-user salt) before transmission. The result cannot be
  used to authenticate against on-prem AD, so a tenant compromise does not hand over usable domain
  credentials.

---

## 7. Verify sync health

```powershell
Import-Module ADSync

# Are the scheduler and its intervals healthy? Default delta is every 30 minutes.
Get-ADSyncScheduler

# Connectors: expect one AD connector and one Entra connector.
Get-ADSyncConnector | Format-Table Name, Type, Version -AutoSize

# Force a full sync now rather than waiting for the scheduler.
#   Initial   = full import + full sync (use after changing filtering/rules)
#   Delta     = changes only (normal operation)
Start-ADSyncSyncCycle -PolicyType Initial

# Is a cycle currently running?
(Get-ADSyncScheduler).SyncCycleInProgress
```

### Check the run results

Open **Synchronization Service Manager** (`C:\Program Files\Microsoft Azure AD Sync\UIShell\miisclient.exe`)
→ **Operations** tab. Every run should show `success`. Investigate any `completed-export-errors` or
`stopped-*` result immediately.

```powershell
# Recent run history, newest first.
Get-ADSyncRunProfileResult -NumberRequested 10 |
    Select-Object RunProfileName, Result, StartDate, EndDate |
    Format-Table -AutoSize

# Export errors are the ones that mean objects did NOT reach the cloud.
Get-ADSyncRunProfileResult -RunHistoryId (Get-ADSyncRunProfileResult -NumberRequested 1).RunHistoryId -RunStepDetails |
    Select-Object StepResult, StageNoChange, StageAdd, StageUpdate, ExportAdd, ExportUpdate
```

### Confirm the objects landed in Entra ID

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Connect-MgGraph -Scopes 'User.Read.All','Directory.Read.All','Organization.Read.All'

# OnPremisesSyncEnabled = True proves the object came from Entra Connect, not the cloud.
Get-MgUser -Filter "endswith(userPrincipalName,'@adlab.io')" `
           -Property DisplayName, UserPrincipalName, OnPremisesSyncEnabled, OnPremisesSamAccountName, AccountEnabled `
           -ConsistencyLevel eventual -CountVariable c |
    Select-Object DisplayName, UserPrincipalName, OnPremisesSyncEnabled, AccountEnabled |
    Format-Table -AutoSize

# Tenant-level sync health: how recently did a sync complete?
Get-MgOrganization | Select-Object -ExpandProperty OnPremisesLastSyncDateTime
```

Expected result: all five sample employees present, `OnPremisesSyncEnabled = True`, UPNs ending `@adlab.io`,
and a last-sync timestamp within the last 30 minutes.

### Portal checks

- **Entra admin center → Identity → Hybrid management → Microsoft Entra Connect → Connect Sync**: status
  **Healthy**, *Password Hash Sync* **Enabled**, last sync **< 1 hour ago**.
- **Entra Connect Health** (if licensed): no active alerts.

---

## 8. Test a synced user signing into a cloud application

The whole point of the exercise. A user object appearing in the portal is not proof of hybrid identity —
authenticating with the on-prem password is.

1. **Assign a licence** (or use a free app): Entra admin center → Users → `mdelgado@adlab.io` → Licenses →
   assign Microsoft 365 E3/E5 (or a trial).
2. **Set a known password on-premises** so you can prove the hash travelled:

   ```powershell
   # On DC01
   Set-ADAccountPassword -Identity mdelgado -Reset `
       -NewPassword (Read-Host -AsSecureString 'New password')
   Set-ADUser -Identity mdelgado -ChangePasswordAtLogon $false   # cloud sign-in cannot satisfy a forced change

   # Push the hash immediately instead of waiting for the 2-minute PHS cycle.
   Start-ADSyncSyncCycle -PolicyType Delta
   ```

3. **Sign in from a non-domain-joined machine** (or a private browser window) at
   <https://myapps.microsoft.com> as `mdelgado@adlab.io` using the **on-premises password**.
4. **Expected result:** sign-in succeeds. The password was never typed into the cloud portal before — it
   worked because Entra ID validated the synced hash. That is hybrid identity proven end to end.
5. **Test Seamless SSO** from the domain-joined `WKS-IT-01`: browse to <https://myapps.microsoft.com> while
   logged in as `ADLAB\mdelgado`. You should reach the portal without a password prompt.

### Inspect the sign-in log

Entra admin center → **Monitoring → Sign-in logs** → select the event:

| Field | Expected value |
|---|---|
| Status | Success |
| Authentication requirement | Single-factor (until CA policies are enabled) |
| Conditional Access | Not applied (or the policies from `conditional-access-examples.md`) |
| Authentication details | *Password Hash Sync* / *Seamless SSO* |
| Cross-tenant access type | None |

### Test password writeback (bidirectional proof)

```powershell
# 1. Reset the password in the cloud via https://aka.ms/sspr as mdelgado@adlab.io
# 2. On DC01, confirm the change flowed BACK on-premises:
Get-ADUser -Identity mdelgado -Properties PasswordLastSet | Select-Object Name, PasswordLastSet
# 3. Log into WKS-IT-01 with the NEW password. One identity, one password, both directions.
```

---

## 9. Post-build validation checklist

| # | Check | Command / location | Pass criteria |
|---|---|---|---|
| 1 | DC health | `dcdiag /v /c /e` | All tests passed |
| 2 | DNS SRV records | `Resolve-DnsName _ldap._tcp.dc._msdcs.adlab.local -Type SRV` | Returns DC01 |
| 3 | SYSVOL/NETLOGON shared | `Get-SmbShare` | Both present |
| 4 | OU structure | `Get-ADOrganizationalUnit -Filter *` | Matches Set-OUStructure.ps1 |
| 5 | Users created | `Get-ADUser -Filter * -SearchBase 'OU=Departments,...'` | 5 enabled users |
| 6 | Routable UPNs | `Get-ADUser -Filter * -Properties UserPrincipalName` | No `.local` suffixes |
| 7 | Custom domain verified | Entra → Domain names | `adlab.io` = Verified |
| 8 | Sync scheduler | `Get-ADSyncScheduler` | `SyncCycleEnabled = True` |
| 9 | Sync runs clean | Synchronization Service Manager → Operations | All `success` |
| 10 | Objects in cloud | `Get-MgUser ...` | `OnPremisesSyncEnabled = True` |
| 11 | PHS working | Cloud sign-in with on-prem password | Success |
| 12 | Seamless SSO | Browse from domain-joined client | No password prompt |
| 13 | Password writeback | SSPR reset, then on-prem logon | New password works on-prem |
| 14 | Health report | `.\Get-ADHealthReport.ps1 -Verbose` | Runs clean, exports CSV |

---

## 10. Common setup failures

| Symptom during setup | Likely cause | Fix |
|---|---|---|
| Entra Connect: "unable to validate credentials" | Outbound 443 blocked, or TLS 1.2 not enabled | Re-run the `Test-NetConnection` checks and the TLS registry keys from Step 5 |
| Users sync as `@adlabio.onmicrosoft.com` | UPN suffix step skipped, or custom domain unverified | Complete Step 4, then `Start-ADSyncSyncCycle -PolicyType Initial` |
| "The specified domain does not exist" joining `SRV-SYNC01` | Member pointing at a public DNS server | Set DNS to `192.168.56.10` only |
| Sync completes but no users appear | OU filtering excludes the OU the users live in | Entra Connect wizard → Configure → Customize synchronization options → OU filtering |
| Seamless SSO does not work | `AZUREADSSOACC` computer object missing, or Entra URLs not in the Intranet zone | Re-run the SSO step; push the intranet-zone URLs via GPO |
| Password change on-prem does not reach the cloud | PHS not enabled, or the sync account lost *Replicate Directory Changes* | Wizard → Change user sign-in; verify the AD DS connector account permissions |

---

## 11. Tear-down

```powershell
# Stop the scheduler first so a sync cycle does not fight the uninstall.
Set-ADSyncScheduler -SyncCycleEnabled $false

# Remove Entra Connect from Programs and Features on SRV-SYNC01, then disable
# directory synchronisation in the tenant. NOTE: this can take up to 72 hours to
# fully take effect, and synced objects become cloud-only rather than disappearing.
Update-MgOrganization -OrganizationId (Get-MgOrganization).Id -OnPremisesSyncEnabled:$false
```

Snapshot the VMs before tearing anything down — rebuilding a DC to test one setting is a poor use of an
evening.

---

> **Disclaimer:** `adlab.local`, `adlab.io`, all IP addresses, hostnames and user accounts in this guide are
> fictional and belong to a personal home lab. No production configuration or real tenant identifier is
> included.
