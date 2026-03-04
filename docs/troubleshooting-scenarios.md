# Troubleshooting Scenarios

Five failures I reproduced (some deliberately, some not) in the `adlab.local` / `adlab.io` hybrid lab,
written up in **Symptom → Diagnosis → Resolution** format with the commands I actually used.

Each scenario ends with the prevention step, because the point of a runbook is to eventually not need it.

---

## Scenario 1 — Account lockout loop

### Symptom

`praghunathan` (Finance) is locked out within 2–3 minutes of every unlock. The service desk unlocks the
account, she works for a few minutes, and it locks again. She insists she is typing her password
correctly — and she is. `Get-ADHealthReport.ps1` shows her with a `BadLogonCount` climbing steadily and a
`LastBadPasswordAttempt` that keeps advancing even while she is not at her desk.

### Diagnosis

A lockout loop with a *correct* password almost always means a **stale cached credential** somewhere:
a mapped drive, a scheduled task, a service, a mobile mail profile, or an RDP session on a machine she
forgot about. Something is replaying the old password on a timer.

The first job is to find *which machine* is generating the bad passwords. Event ID **4740** on the PDC
emulator records the lockout and, critically, the **caller computer name**.

```powershell
# 1. Confirm state and read the lockout policy - is the threshold sane?
Get-ADUser -Identity praghunathan -Properties LockedOut, BadPwdCount, LastBadPasswordAttempt,
                                              PasswordLastSet, LockoutTime |
    Format-List Name, LockedOut, BadPwdCount, LastBadPasswordAttempt, PasswordLastSet

Get-ADDefaultDomainPasswordPolicy |
    Select-Object LockoutThreshold, LockoutDuration, LockoutObservationWindow, MaxPasswordAge

# 2. The PDC emulator is authoritative for lockouts - query THAT DC, not a random one.
$pdc = (Get-ADDomain).PDCEmulator
$pdc

# 3. Event 4740 = "A user account was locked out". The Caller Computer Name is the answer.
Get-WinEvent -ComputerName $pdc -FilterHashtable @{
        LogName = 'Security'; ID = 4740; StartTime = (Get-Date).AddHours(-6)
    } |
    ForEach-Object {
        $x = [xml]$_.ToXml()
        [pscustomobject]@{
            Time         = $_.TimeCreated
            User         = ($x.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
            CallerComputer = ($x.Event.EventData.Data | Where-Object Name -eq 'TargetDomainName').'#text'
        }
    } | Where-Object User -eq 'praghunathan' | Format-Table -AutoSize

# 4. Event 4771 (Kerberos pre-auth failed) / 4625 (logon failure) give the source IP.
Get-WinEvent -ComputerName $pdc -FilterHashtable @{
        LogName = 'Security'; ID = 4771; StartTime = (Get-Date).AddHours(-6)
    } |
    ForEach-Object {
        $x = [xml]$_.ToXml()
        [pscustomobject]@{
            Time     = $_.TimeCreated
            User     = ($x.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
            ClientIP = ($x.Event.EventData.Data | Where-Object Name -eq 'IpAddress').'#text'
            FailCode = ($x.Event.EventData.Data | Where-Object Name -eq 'Status').'#text'
        }
    } | Where-Object User -eq 'praghunathan' | Sort-Object Time -Descending | Select-Object -First 20
```

Failure code `0x18` = wrong password. `0x12` = account disabled/expired/locked.

**Finding in this lab:** every 4771 came from `192.168.56.51` — an old test VM (`WKS-FIN-OLD`) with a
scheduled task running under her account. The task had been created before her last password change and was
retrying every 60 seconds. Three retries per lockout window, threshold of 5, and the account never stayed
unlocked long.

### Resolution

```powershell
# 1. Stop the source. Find credentials cached on the offending machine.
Invoke-Command -ComputerName WKS-FIN-OLD -ScriptBlock {
    schtasks /query /fo LIST /v | Select-String -Pattern 'TaskName|Run As User'
    cmdkey /list
    Get-CimInstance Win32_Service |
        Where-Object { $_.StartName -like '*praghunathan*' } |
        Select-Object Name, StartName, State
}

# 2. Remove the stale cached credential / fix the task's stored password.
Invoke-Command -ComputerName WKS-FIN-OLD -ScriptBlock {
    cmdkey /delete:ADLAB\praghunathan
}

# 3. Now unlock. Unlocking BEFORE removing the source just restarts the loop.
Unlock-ADAccount -Identity praghunathan

# 4. Verify it stays unlocked.
Start-Sleep -Seconds 300
Get-ADUser -Identity praghunathan -Properties LockedOut, BadPwdCount |
    Select-Object Name, LockedOut, BadPwdCount
```

The scheduled task was rewritten to run under a **group Managed Service Account** (`gMSA`), which rotates
its own password and therefore cannot cause this failure again.

### Hybrid note

If the source is a mobile device, the bad passwords often arrive through Exchange ActiveSync — which
`CA-002` (block legacy authentication) already blocks in this tenant. Check Entra **sign-in logs → Legacy
authentication clients** as well as the on-prem event log; in a hybrid environment the attacker or the
stale credential may never touch a domain controller directly.

### Prevention

- Service and scheduled-task identities must be **gMSAs**, never human accounts.
- Add `Get-ADHealthReport.ps1` to a daily schedule — Section 1 surfaces repeat lockouts before the user calls.
- Enable *Audit Logon* / *Audit Account Lockout* success+failure via GPO on all DCs; without it, 4740 and 4771
  are not written and you are guessing.

---

## Scenario 2 — Kerberos authentication failure

### Symptom

`mdelgado` can log into `WKS-IT-01` but gets **"The target account name is incorrect"** when opening
`\\SRV-SYNC01\Reports$`. Browsing by IP address (`\\192.168.56.20\Reports$`) works fine and prompts for
credentials. The System event log on the client shows **Event ID 4** from `Kerberos-Key-Distribution-Center`:
*"The Kerberos client received a KRB_AP_ERR_MODIFIED error."*

### Diagnosis

The "works by IP, fails by name" split is the classic Kerberos fingerprint. Authentication by IP falls back
to NTLM, which does not care about Service Principal Names. Authentication by hostname requires Kerberos,
which requires the SPN to be registered to exactly one account.

`KRB_AP_ERR_MODIFIED` means the KDC issued a ticket encrypted with a key the target service could not
decrypt — almost always a **duplicate SPN** (two accounts claim the same service) or a **broken secure
channel** (the computer account password is out of sync with the DC).

```powershell
# 1. Duplicate SPNs across the forest. Any output here is a defect.
setspn -X

# 2. What SPNs does the target actually hold?
setspn -L SRV-SYNC01

# 3. Is the computer's secure channel healthy?
Test-ComputerSecureChannel -Server DC01 -Verbose        # run ON SRV-SYNC01

# 4. Clock skew - Kerberos rejects anything beyond 5 minutes by default.
w32tm /monitor /computers:DC01,SRV-SYNC01,WKS-IT-01
Invoke-Command -ComputerName DC01,SRV-SYNC01,WKS-IT-01 -ScriptBlock { Get-Date }

# 5. What tickets does the client hold right now?
klist
klist sessions

# 6. DNS sanity - does the name resolve to the machine you think it does?
Resolve-DnsName SRV-SYNC01.adlab.local
nltest /dsgetdc:adlab.local
```

**Finding in this lab:** `setspn -X` reported `HOST/SRV-SYNC01` registered on **both** the `SRV-SYNC01`
computer object and a leftover service account (`svc-oldreports`) where someone had manually added the SPN
months earlier. The KDC picked the wrong account's key, and the real server could not decrypt the ticket.

A close second cause, seen earlier in the same lab: `WKS-IT-01` had been restored from an old snapshot, so its
computer account password no longer matched AD and `Test-ComputerSecureChannel` returned `False`.

### Resolution

```powershell
# --- Fix A: duplicate SPN ---
setspn -D HOST/SRV-SYNC01 svc-oldreports
setspn -D HOST/SRV-SYNC01.adlab.local svc-oldreports
setspn -X                                  # must now return no duplicates
setspn -L SRV-SYNC01                       # correct SPNs still present on the computer object

# --- Fix B: broken secure channel (run on the affected member) ---
Test-ComputerSecureChannel -Repair -Credential (Get-Credential 'ADLAB\Administrator')
# If repair fails, rejoin properly (never just "leave and rejoin" via the GUI without cleanup):
Reset-ComputerMachinePassword -Server DC01 -Credential (Get-Credential 'ADLAB\Administrator')

# --- Fix C: clock skew ---
w32tm /config /syncfromflags:domhier /update
Restart-Service w32time
w32tm /resync /force

# --- Then clear stale tickets on the client and retry ---
klist purge
klist purge -li 0x3e7      # also purge the SYSTEM (computer) ticket cache
Test-Path \\SRV-SYNC01\Reports$
```

### Hybrid note

The same root causes break **Seamless SSO**, which depends on the `AZUREADSSOACC` computer object holding the
SPNs `HTTP/autologon.microsoftazuread-sso.com` and `HTTP/aadg.windows.net.nsatc.net`. If users are suddenly
prompted for a password on domain-joined machines, check that object's SPNs and rotate its Kerberos decryption
key (Microsoft recommends every 30 days) with `Update-AzureADSSOForest`.

### Prevention

- Never add SPNs by hand for services that register their own. Use `setspn -X` as a scheduled monthly check.
- Do not restore domain members from snapshots older than the machine password age (30 days by default).
- Domain hierarchy time sync only — no member should have a manual NTP peer.

---

## Scenario 3 — Group Policy not applying

### Symptom

A new GPO, **"IT — Drive Mappings"**, is linked to `OU=IT,OU=Departments,OU=ADLab,DC=adlab,DC=local` but the
mapped drive never appears for `evandermeer`. `gpupdate /force` reports success. Other GPOs on the same
machine apply correctly.

### Diagnosis

Work down the GPO processing chain in order — link → scope → security filtering → WMI filter → inheritance
→ replication. Guessing wastes time; `gpresult` tells you exactly where it stopped.

```powershell
# 1. Authoritative view: what actually applied, and what was filtered out?
gpresult /r /scope:user
gpresult /h C:\Temp\gpreport.html /f ; Start-Process C:\Temp\gpreport.html

# The HTML report's "Denied GPOs" section names the reason - read it before anything else.

# 2. Is the link enabled, and is it where you think it is?
Import-Module GroupPolicy
Get-GPInheritance -Target 'OU=IT,OU=Departments,OU=ADLab,DC=adlab,DC=local' |
    Select-Object -ExpandProperty GpoLinks |
    Format-Table DisplayName, Enabled, Enforced, Order -AutoSize

# 3. Security filtering: the user/computer needs BOTH Read AND Apply Group Policy.
Get-GPPermission -Name 'IT - Drive Mappings' -All |
    Format-Table @{n='Trustee';e={$_.Trustee.Name}}, Permission, Denied -AutoSize

# 4. Is the user half of the GPO disabled? (Very easy to do by accident.)
(Get-GPO -Name 'IT - Drive Mappings') | Select-Object DisplayName, GpoStatus

# 5. WMI filter - a filter that evaluates false silently skips the GPO.
(Get-GPO -Name 'IT - Drive Mappings').WmiFilter

# 6. Is the object even in the linked OU?
Get-ADUser -Identity evandermeer -Properties DistinguishedName | Select-Object DistinguishedName

# 7. Is blocked inheritance stopping it higher up?
Get-GPInheritance -Target 'OU=Departments,OU=ADLab,DC=adlab,DC=local' |
    Select-Object GpoInheritanceBlocked

# 8. SYSVOL replication - version mismatch between AD and SYSVOL means clients read stale policy.
Get-GPOReport -Name 'IT - Drive Mappings' -ReportType Xml |
    Select-String -Pattern 'version'
dfsrdiag ReplicationState /member:DC01
```

**Finding in this lab:** two problems stacked.

1. `GpoStatus` was `UserSettingsDisabled` — the drive mapping is a *user* preference, so the entire user half
   was being skipped. That alone explained the silence.
2. After fixing that, security filtering still had only `SG-Role-Server-Admins-L1` with *Apply Group Policy*;
   `Authenticated Users` had been removed (a well-intentioned hardening step) and `evandermeer` was not in the
   remaining group.

A third trap worth knowing: since MS16-072, GPOs are retrieved in the **computer's** security context. If you
remove `Authenticated Users` from a user-targeted GPO, the *computer* loses Read and the policy fails even
when the user is correctly filtered. The fix is to leave `Authenticated Users` with **Read** (not Apply) and
scope Apply to your target group.

### Resolution

```powershell
# 1. Re-enable the user half of the policy.
(Get-GPO -Name 'IT - Drive Mappings').GpoStatus = 'AllSettingsEnabled'

# 2. Correct the filtering: Authenticated Users keeps READ (MS16-072 requirement),
#    the target group gets APPLY.
Set-GPPermission -Name 'IT - Drive Mappings' `
                 -TargetName 'Authenticated Users' -TargetType Group `
                 -PermissionLevel GpoRead -Replace

Set-GPPermission -Name 'IT - Drive Mappings' `
                 -TargetName 'SG-Dept-IT' -TargetType Group `
                 -PermissionLevel GpoApply

# 3. Confirm.
Get-GPPermission -Name 'IT - Drive Mappings' -All |
    Format-Table @{n='Trustee';e={$_.Trustee.Name}}, Permission -AutoSize

# 4. Refresh and re-verify from the client. Log off/on for user policy to fully apply.
gpupdate /force /target:user
gpresult /r /scope:user | Select-String 'IT - Drive Mappings'
```

### Prevention

- After creating any GPO, run `gpresult /h` from a real target machine. "It should work" is not verification.
- Keep `Authenticated Users` = **Read** on every GPO; never delete the entry outright.
- Name GPOs by scope and function (`IT — Drive Mappings`) so a mislink is obvious in the GPMC tree.
- Turn on **Group Policy operational logging** (`Applications and Services Logs → Microsoft → Windows →
  GroupPolicy → Operational`) for the timing and filtering detail `gpresult` omits.

---

## Scenario 4 — User synced to Entra ID but cannot sign into a cloud app

### Symptom

`aokonkwo` appears in the Entra admin center and `Get-MgUser` returns her object, but signing into
<https://myapps.microsoft.com> with her on-premises password fails with
**"Your account or password is incorrect"** (error `AADSTS50126`). Other synced users sign in fine.

### Diagnosis

Object presence proves the *sync* worked. Sign-in requires four more things to be true: the UPN must be
routable and verified, the password hash must have synced, the account must be enabled in the cloud, and no
Conditional Access policy may be blocking it.

```powershell
Connect-MgGraph -Scopes 'User.Read.All','Directory.Read.All','AuditLog.Read.All'

# 1. What does the cloud object actually look like?
Get-MgUser -UserId 'aokonkwo@adlab.io' `
           -Property DisplayName, UserPrincipalName, AccountEnabled, OnPremisesSyncEnabled,
                     OnPremisesSamAccountName, OnPremisesImmutableId, OnPremisesLastSyncDateTime,
                     UserType, AssignedLicenses |
    Format-List

# 2. Is the UPN suffix a VERIFIED domain? An unverified suffix silently becomes .onmicrosoft.com.
Get-MgDomain | Format-Table Id, IsVerified, IsDefault, AuthenticationType -AutoSize

# 3. On-prem side: is the UPN routable, is the account enabled, has the password changed since sync?
Get-ADUser -Identity aokonkwo -Properties UserPrincipalName, Enabled, PasswordLastSet,
                                          PasswordNeverExpires, msDS-ConsistencyGuid |
    Format-List

# 4. Is PHS actually turned on and running? (On SRV-SYNC01.)
Import-Module ADSync
$c = Get-ADSyncConnector | Where-Object { $_.Name -like '*onmicrosoft.com*' }
Get-ADSyncAADPasswordSyncConfiguration -SourceConnector (Get-ADSyncConnector | Where-Object Type -eq 'AD').Name

# 5. Read the actual failure reason - the sign-in log is far more specific than the UI error.
Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'aokonkwo@adlab.io'" -Top 10 |
    Select-Object CreatedDateTime, AppDisplayName,
                  @{n='Error';e={$_.Status.ErrorCode}},
                  @{n='Reason';e={$_.Status.FailureReason}},
                  @{n='CA';e={($_.AppliedConditionalAccessPolicies | ForEach-Object { "$($_.DisplayName)=$($_.Result)" }) -join '; '}} |
    Format-Table -AutoSize
```

Common error codes and what they actually mean:

| Code | Meaning | Real cause |
|---|---|---|
| `AADSTS50126` | Invalid username or password | Password hash never synced, or UPN mismatch |
| `AADSTS50057` | User account is disabled | Disabled on-prem and synced as disabled |
| `AADSTS50053` | Account locked | Smart lockout in Entra ID (separate from AD lockout) |
| `AADSTS53003` | Blocked by Conditional Access | A CA policy denied the sign-in |
| `AADSTS50055` | Password expired | On-prem password expired; PHS syncs the expired state |
| `AADSTS700016` | App not found in directory | App registration/consent issue, not identity |

**Finding in this lab:** `aokonkwo` had `ChangePasswordAtLogon = $true` — left over from
`New-EmployeeOnboarding.ps1`, exactly as designed. When `pwdLastSet = 0`, **Password Hash Sync does not sync a
hash at all**, because there is no current password to hash. The cloud object existed with no usable
credential, which surfaces as the generic "incorrect password" error. She had never logged into a domain
workstation to complete the initial change.

### Resolution

```powershell
# --- Root cause fix: the user must set a real password on-premises first. ---
# Option A (correct process): user logs into a domain-joined workstation and changes the password.
# Option B (service desk): reset it and clear the forced-change flag so a hash can be generated.
Set-ADAccountPassword -Identity aokonkwo -Reset -NewPassword (Read-Host -AsSecureString 'New password')
Set-ADUser -Identity aokonkwo -ChangePasswordAtLogon $false

# Confirm pwdLastSet is no longer 0.
Get-ADUser -Identity aokonkwo -Properties pwdLastSet, PasswordLastSet |
    Select-Object Name, pwdLastSet, PasswordLastSet

# --- Force the hash to sync now rather than waiting. ---
# On SRV-SYNC01:
Start-ADSyncSyncCycle -PolicyType Delta

# If hashes are stale across the board, force a FULL password resync for the connector.
# (Only needed when PHS has been broken for a while - it re-sends every hash.)
$adConnector   = (Get-ADSyncConnector | Where-Object Type -eq 'AD').Name
$aadConnector  = (Get-ADSyncConnector | Where-Object Type -eq 'Extensible2').Name
Set-ADSyncAADPasswordSyncConfiguration -SourceConnector $adConnector `
                                       -TargetConnector $aadConnector `
                                       -Enable $true

# --- Verify from the cloud side. ---
Get-MgUser -UserId 'aokonkwo@adlab.io' -Property OnPremisesLastSyncDateTime, AccountEnabled |
    Format-List
```

Other fixes for the same symptom, in order of how often I have hit them:

1. **UPN still `.local`** → add the routable suffix and repoint the user (`lab-setup-guide.md` Step 4), then
   `Start-ADSyncSyncCycle -PolicyType Initial`.
2. **No licence assigned** → the user authenticates but has no app to land in; assign a licence.
3. **CA policy blocking** → check `AppliedConditionalAccessPolicies` in the sign-in log; if it is CA-003, the
   device is not compliant, which is the policy working correctly.
4. **Account disabled on-prem** → PHS faithfully syncs the disabled state. Fix on-prem, not in the cloud.
5. **Duplicate/soft-deleted cloud object** → an old cloud-only object holding the same UPN blocks the synced
   one. Check `Get-MgDirectoryDeletedItemAsUser` and purge it.

### Prevention

- Add a post-onboarding step: the new hire's first action is an on-prem password change on a domain-joined
  machine, *then* cloud access is validated.
- Alert on `OnPremisesLastSyncDateTime` older than 3 hours.
- Do not test cloud sign-in for an account that still has `ChangePasswordAtLogon = $true` — it will always fail,
  and it is not a sync problem.

---

## Scenario 5 — MFA lockout

### Symptom

`tnyberg` (Sales) is on the road. His phone was stolen, taking the Microsoft Authenticator app with it. He
knows his password but cannot complete MFA, and `CA-005` prevents him from registering a new method from an
untrusted network. He needs access to a customer quote in the next hour.

### Diagnosis

This is not a fault — it is the security model working exactly as designed. The risk here is the *recovery
process*, not the lockout: an attacker who has phished a password will call the service desk with this exact
story. Verifying identity is the whole job.

```powershell
Connect-MgGraph -Scopes 'UserAuthenticationMethod.Read.All','User.Read.All','AuditLog.Read.All','Policy.Read.All'

# 1. What methods does he currently have registered?
Get-MgUserAuthenticationMethod -UserId 'tnyberg@adlab.io' |
    Select-Object Id, AdditionalProperties |
    ForEach-Object {
        [pscustomobject]@{
            Id   = $_.Id
            Type = $_.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', ''
            Detail = $_.AdditionalProperties['displayName']
        }
    } | Format-Table -AutoSize

# 2. What is actually failing, and which policy is involved?
Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'tnyberg@adlab.io'" -Top 10 |
    Select-Object CreatedDateTime, IPAddress,
                  @{n='Error';e={$_.Status.ErrorCode}},
                  @{n='Reason';e={$_.Status.FailureReason}},
                  @{n='CA';e={($_.AppliedConditionalAccessPolicies | ForEach-Object { "$($_.DisplayName)=$($_.Result)" }) -join '; '}} |
    Format-Table -AutoSize

# 3. Is this a genuine lockout or Entra smart lockout after repeated failures?
#    AADSTS50053 = smart lockout; AADSTS50074 = strong auth required but not satisfiable.
```

| Code | Meaning |
|---|---|
| `AADSTS50074` | Strong authentication required and the user cannot satisfy it |
| `AADSTS50076` | MFA required for this resource (CA), no method available |
| `AADSTS50158` | External security challenge not satisfied |
| `AADSTS53003` | Blocked by Conditional Access (e.g. CA-005 registration restriction) |
| `AADSTS50053` | Smart lockout after repeated failed attempts |

**Finding:** `AADSTS50076` plus `CA-005 = failure`. He had exactly one method registered (the lost phone) and
no fallback. Single-method registration is the actual defect.

### Resolution

**Step 1 — Verify identity out of band. This is the security control; everything else is mechanics.**

The lab's documented standard (and the reason MFA resets are not self-service):

1. Call the user back on the number in the **HR record**, not a number supplied in the request.
2. Confirm at least two non-public HR facts (manager's name, start date, office location).
3. Where possible, the line manager confirms the request over a separate channel (Teams video call).
4. Log the ticket number, verification method and approver. No verbal-only approvals.

> The most common real-world compromise of this flow is a helpdesk technician being socially engineered into
> resetting MFA for an attacker. Skipping Step 1 undoes every policy in `conditional-access-examples.md`.

**Step 2 — Revoke the lost device's methods.**

```powershell
# List methods, identify the one tied to the stolen phone, and delete it.
$methods = Get-MgUserAuthenticationMethod -UserId 'tnyberg@adlab.io'
$methods | ForEach-Object { "{0}  {1}" -f $_.Id, $_.AdditionalProperties['@odata.type'] }

# Remove the Authenticator registration on the stolen device.
Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod `
    -UserId 'tnyberg@adlab.io' `
    -MicrosoftAuthenticatorAuthenticationMethodId '<method-id>'

# Kill every live session so the stolen phone's existing tokens stop working immediately.
# WHY: revoking the method does not invalidate tokens already issued.
Revoke-MgUserSignInSession -UserId 'tnyberg@adlab.io'
```

**Step 3 — Give a time-boxed path back in.** Two options, in order of preference:

```powershell
# Option A (preferred): issue a Temporary Access Pass - a time-limited, one-time-use
# passcode that satisfies MFA exactly once so the user can register a NEW method.
# WHY better than excluding him from CA: it is scoped, expires by itself, and is fully audited.
$tapBody = @{
    lifetimeInMinutes = 60
    isUsableOnce      = $true
}
New-MgUserAuthenticationTemporaryAccessPassMethod -UserId 'tnyberg@adlab.io' -BodyParameter $tapBody
# Read the returned temporaryAccessPass value to the user over the verified phone call.
# Never send it by email or chat.

# Option B (only if TAP is unavailable): add the user to SG-CA-Exclude-NewHire-Onboarding,
# which automation empties nightly. Time-boxed by design; still requires the identity check.
Add-ADGroupMember -Identity 'SG-CA-Exclude-NewHire-Onboarding' -Members tnyberg
# Then: Start-ADSyncSyncCycle -PolicyType Delta   (and remove membership the moment he is back in)
```

**Step 4 — Have the user register at least two methods.**

While on the phone, walk him through <https://aka.ms/mysecurityinfo>:

- Microsoft Authenticator on the replacement phone (primary), **and**
- A FIDO2 security key or a second device (backup).

**Step 5 — Verify and close.**

```powershell
# Confirm two or more methods now exist and the TAP was consumed.
Get-MgUserAuthenticationMethod -UserId 'tnyberg@adlab.io' |
    ForEach-Object { $_.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', '' }

# Confirm a clean, MFA-satisfied sign-in.
Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'tnyberg@adlab.io'" -Top 3 |
    Select-Object CreatedDateTime,
                  @{n='Status';e={$_.Status.ErrorCode}},
                  @{n='AuthRequirement';e={$_.AuthenticationRequirement}}

# Remove any temporary CA exclusion immediately.
Remove-ADGroupMember -Identity 'SG-CA-Exclude-NewHire-Onboarding' -Members tnyberg -Confirm:$false
```

### The break-glass boundary

If a CA misconfiguration locks out **every** administrator (not just one user), this runbook does not apply —
use a break-glass account (`policies/rbac-role-definitions.md` §4), fix the offending policy, and file an
incident review. Break-glass accounts are never used for individual user lockouts; every sign-in by one raises
a high-severity alert.

### Prevention

- **Require two registered methods** via Authentication Methods policy / registration campaign. One method is
  one stolen phone away from a ticket like this.
- **Push phishing-resistant methods** (FIDO2, Windows Hello for Business) for admins — a security key is not
  lost with a phone and cannot be phished.
- **Report on single-method users monthly:**

  ```powershell
  Get-MgReportAuthenticationMethodUserRegistrationDetail -All |
      Where-Object { $_.MethodsRegistered.Count -lt 2 } |
      Select-Object UserPrincipalName, IsMfaRegistered, MethodsRegistered
  ```

- **Rehearse the reset flow quarterly** so the service desk follows the verification script under pressure
  rather than improvising.

---

## Quick reference — first commands by symptom

| Symptom | First command |
|---|---|
| Account keeps locking | `Get-WinEvent -ComputerName (Get-ADDomain).PDCEmulator -FilterHashtable @{LogName='Security';ID=4740}` |
| "Target account name is incorrect" | `setspn -X` then `Test-ComputerSecureChannel -Verbose` |
| GPO not applying | `gpresult /h C:\Temp\gp.html /f` |
| Synced user cannot sign in | `Get-MgAuditLogSignIn -Filter "userPrincipalName eq '<upn>'" -Top 5` |
| MFA lockout | `Get-MgUserAuthenticationMethod -UserId '<upn>'` |
| Sync appears stalled | `Get-ADSyncScheduler` then `Get-ADSyncRunProfileResult -NumberRequested 5` |
| General identity hygiene | `.\powershell\Get-ADHealthReport.ps1 -Verbose` |

---

> **Disclaimer:** all domains, hostnames, IP addresses, usernames and error scenarios above come from a
> fictional personal lab (`adlab.local` / `adlab.io`). No real users, tenant identifiers or production
> incident data appear in this repository.
