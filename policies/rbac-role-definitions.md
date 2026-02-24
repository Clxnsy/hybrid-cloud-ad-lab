# RBAC Role Definitions — Least-Privilege Delegation Model

> **Scope:** `adlab.local` (fictional lab domain) and the paired `adlab.io` Microsoft Entra ID tenant.
> **Principle:** nobody uses Domain Admin for daily work. Every routine task maps to a group that
> holds the *minimum* delegated permissions needed to complete it, and nothing else.

---

## 1. Why this model exists

In most small environments the helpdesk ends up in **Domain Admins** because "they need to unlock
accounts". That single shortcut means a phishing email against a service-desk technician becomes a
full domain compromise. The design below breaks the work into four roles, each delegated at the
**OU level** with the narrowest possible permission set.

Three rules govern everything in this document:

1. **Delegate on OUs, never on the domain root.** A permission granted at the root is inherited by
   `Domain Controllers`, `AdminSDHolder`-protected accounts and every future OU. OU-level delegation
   fails closed.
2. **Permissions go to groups, never to users.** A user's access is changed by editing group
   membership — which is logged, reviewable and reversible in one action at offboarding.
3. **Privileged accounts are separate accounts.** A technician has `mdelgado` for email and
   `mdelgado-adm` for administration. The admin account is never used to read mail or browse.

---

## 2. Group naming convention

| Prefix | Meaning | Example |
|---|---|---|
| `SG-Dept-` | Departmental membership group, populated by onboarding automation | `SG-Dept-Finance` |
| `SG-Role-` | Job-function role granting delegated rights | `SG-Role-Helpdesk-Operators` |
| `SG-App-` | Application access group, synced to Entra ID for app assignment | `SG-App-FinanceReporting` |
| `SG-CA-` | Conditional Access targeting/exclusion group | `SG-CA-Exclude-BreakGlass` |

All role groups are **Global security groups** created in `OU=Security Groups,OU=ADLab,DC=adlab,DC=local`.
Global scope is correct in a single-domain forest and syncs cleanly to Microsoft Entra ID.

---

## 3. Role definitions

### 3.1 `SG-Role-Helpdesk-Operators`

**Who:** Tier 1 service desk. First line for password and lockout tickets.
**Delegated at:** `OU=Departments,OU=ADLab,DC=adlab,DC=local` (and children).

| Permission | Object scope | Reasoning |
|---|---|---|
| Reset password | Descendant User objects | The single highest-volume ticket. Delegating it removes ~70% of escalations to Tier 2. |
| Force password change at next logon (`Write pwdLastSet`) | Descendant User objects | A reset without this leaves the temporary password in place indefinitely. |
| Unlock account (`Read/Write lockoutTime`) | Descendant User objects | Lockouts are time-critical; waiting for Tier 2 costs real productivity. |
| Read all user properties | Descendant User objects | Needed to verify identity (department, manager, title) before performing a reset. |
| Write `telephoneNumber`, `mobile`, `streetAddress`, `l`, `st`, `postalCode` | Descendant User objects | Contact-detail corrections are trivial and safe; escalating them wastes Tier 2 time. |

**Explicitly NOT granted — and why:**

- **Create/Delete user objects** — account creation must go through `New-EmployeeOnboarding.ps1` so
  that OU placement, UPN suffix and group membership stay consistent. Ad-hoc creation is how orphan
  accounts appear.
- **Write `memberOf` / modify group membership** — group membership *is* authorisation. Letting Tier 1
  add users to groups is equivalent to letting them grant themselves any permission in the domain.
- **Write `userAccountControl`** — this attribute controls `PASSWD_NOTREQD`, `DONT_EXPIRE_PASSWORD`
  and delegation flags. It is a privilege-escalation primitive, not a helpdesk field.
- **Any rights over the `IT` OU** — Tier 1 must not be able to reset the password of a Tier 2 admin
  account. That is a lateral-movement path straight to the top.

---

### 3.2 `SG-Role-UserAccount-Admins`

**Who:** Tier 2 identity administrators. Own the account lifecycle end to end.
**Delegated at:** `OU=Departments` and `OU=Disabled Users`.

| Permission | Object scope | Reasoning |
|---|---|---|
| Create / Delete User objects | `OU=Departments` and children | Owns onboarding and (rare) genuine deletions. |
| Full control over descendant User objects | `OU=Departments` and children | Needs to correct any user attribute without escalation. |
| Move objects between OUs (`Write Distinguished Name` on source + `Create Child` on target) | Departments ↔ Disabled Users | Required by the offboarding script's relocation step. |
| Modify membership of `SG-Dept-*` groups only | `OU=Security Groups` | Department membership is business data, not a security boundary. |
| Create / Delete Group objects | `OU=Security Groups` | New departments need new groups without a change request to Domain Admins. |

**Explicitly NOT granted — and why:**

- **Membership control over `SG-Role-*` groups** — a Tier 2 admin must not be able to add themselves
  to `SG-Role-Server-Admins-L1`. Role-group membership is changed only by
  `SG-Role-Identity-Governance` under an approved change record. Self-service privilege escalation is
  the thing this whole model exists to prevent.
- **Any rights on `OU=Servers` or `OU=Workstations`** — user administration and machine administration
  are different blast radii and stay separated.
- **GPO link or edit rights** — a GPO edit can deploy a scheduled task to every machine in scope. That
  is a change-controlled activity.

---

### 3.3 `SG-Role-Server-Admins-L1`

**Who:** Infrastructure engineers who patch, restart services and troubleshoot member servers.
**Granted via:** Restricted Groups / Group Policy Preferences pushing this group into the local
`Administrators` group on machines in `OU=Servers` — **not** via Domain Admins.

| Permission | Scope | Reasoning |
|---|---|---|
| Local Administrator on member servers | `OU=Servers` (excludes Domain Controllers) | Enough for services, patching, event logs and installs. |
| Log on as a service / batch job | `OU=Servers` | Needed for scheduled maintenance jobs. |
| Read all computer object properties | `OU=Servers` | Inventory, OS version and last-boot checks. |
| Reset computer account / rejoin domain | `OU=Servers` | Fixes broken secure channels without escalation. |
| Read-only access to GPOs linked to `OU=Servers` | `OU=Servers` | Must be able to *see* applied policy to diagnose it; changing it is separate. |

**Explicitly NOT granted — and why:**

- **Any rights on Domain Controllers** — local admin on a DC *is* Domain Admin. There is no such thing
  as a "tier 1 DC admin"; DC access belongs exclusively to Tier 0.
- **Create/Delete computer objects in the domain** — domain join is handled by a delegated join
  account with a quota, so a compromised engineer account cannot flood the directory.
- **User object rights of any kind** — a server admin has no business resetting user passwords. Cross-tier
  permission creep is how a server compromise becomes an identity compromise.

---

### 3.4 `SG-Role-ReadOnly-Auditors`

**Who:** Security/compliance reviewers, and the service account that runs `Get-ADHealthReport.ps1`.
**Delegated at:** domain root, **read-only**.

| Permission | Scope | Reasoning |
|---|---|---|
| Read all properties on User, Group, Computer and OU objects | Domain-wide | Access reviews need full visibility; visibility is not authority. |
| Read `userAccountControl`, `pwdLastSet`, `lastLogonTimestamp`, `msDS-UserPasswordExpiryTimeComputed` | Domain-wide | Exactly the attributes the health report audits. |
| Read Group Policy Objects and links | Domain-wide | Policy review without the ability to change policy. |
| Read the Security event log on Domain Controllers | Domain Controllers | Lockout (4740) and logon-failure (4625) investigation. |
| Generate RSoP (Planning) | Domain-wide | Model policy outcomes without applying anything. |

**Explicitly NOT granted — and why:**

- **Write access to anything, anywhere.** An auditor that can change the thing it audits invalidates
  the audit. This role is deliberately incapable of remediation — findings are handed to the owning role.
- **Read access to `ms-Mcs-AdmPwd` (LAPS)** — plaintext local admin passwords are not audit data. Only
  `SG-Role-Server-Admins-L1` and Tier 0 can read them.

---

### 3.5 `SG-Role-Identity-Governance` (Tier 0 adjacent)

**Who:** Two named senior engineers. Owns membership of every `SG-Role-*` group.
**Access model:** eligible-only via Entra Privileged Identity Management (PIM) where licensing allows;
otherwise a separate `-adm` account with a hardware security key.

| Permission | Scope | Reasoning |
|---|---|---|
| Modify membership of `SG-Role-*` groups | `OU=Security Groups` | Creates a single, auditable choke point for privilege changes. |
| Approve/deny PIM activation requests | Entra ID | Human approval on every privileged elevation. |
| Read all delegated ACLs | Domain-wide | Must be able to detect permission drift. |

**Explicitly NOT granted:** Domain Admin by default. Membership is *requested*, time-bound and approved.

---

## 4. Cloud role mapping (Microsoft Entra ID)

On-premises groups sync to Entra ID via Entra Connect and are used for **app assignment and Conditional
Access targeting**. Entra *directory roles* are assigned separately, cloud-only, and are never granted
to a synced group — a compromised on-prem group must never be able to confer a cloud admin role.

| On-prem group | Cloud usage | Entra directory role | Assignment method |
|---|---|---|---|
| `SG-Role-Helpdesk-Operators` | CA policy target (MFA on every sign-in) | Password Administrator | PIM, eligible, 4-hour max |
| `SG-Role-UserAccount-Admins` | CA policy target | User Administrator | PIM, eligible, 4-hour max, approval required |
| `SG-Role-Server-Admins-L1` | CA policy target (compliant device required) | *(none)* | n/a — on-prem role only |
| `SG-Role-ReadOnly-Auditors` | CA policy target | Global Reader + Security Reader | Permanent (read-only is low risk) |
| `SG-Role-Identity-Governance` | CA policy target (phishing-resistant MFA) | Privileged Role Administrator | PIM, eligible, approval + justification |
| `SG-CA-Exclude-BreakGlass` | Excluded from all CA policies | Global Administrator ×2 | Cloud-only, permanent, monitored |

### Break-glass accounts

Two cloud-only Global Administrator accounts (`bg-admin-01@adlab.io`, `bg-admin-02@adlab.io`) exist
outside every Conditional Access policy. This looks like a violation of everything above, and it is —
deliberately. If a CA policy misconfiguration or a federation outage locks out every admin, these are
the only way back in. Controls that make it acceptable:

- Long random passwords split across two sealed envelopes in separate physical locations.
- Excluded from *all* CA policies (including MFA) so no cloud dependency can block them.
- Sign-in alerting: **any** authentication by these accounts raises a high-severity alert immediately.
- Credentials rotated every 90 days and after every use.
- Quarterly documented test to prove they still work.

---

## 5. Access review cadence

| Group | Review frequency | Reviewer | Action on no-response |
|---|---|---|---|
| `SG-Role-Identity-Governance` | Monthly | IT Director | Remove membership |
| `SG-Role-UserAccount-Admins` | Quarterly | Identity Governance | Remove membership |
| `SG-Role-Server-Admins-L1` | Quarterly | Infrastructure Lead | Remove membership |
| `SG-Role-Helpdesk-Operators` | Quarterly | Service Desk Manager | Remove membership |
| `SG-Role-ReadOnly-Auditors` | Semi-annually | Compliance | Retain, flag for follow-up |
| `SG-Dept-*` | Continuous (automated) | Onboarding/offboarding scripts | n/a |

Default outcome of an unanswered review is **removal**, not retention. Access that nobody will vouch
for is access nobody needs.

---

## 6. Verifying the delegation

```powershell
# What ACEs are actually applied to the Departments OU?
$ou = 'AD:\OU=Departments,OU=ADLab,DC=adlab,DC=local'
(Get-Acl -Path $ou).Access |
    Where-Object { $_.IdentityReference -like '*SG-Role-*' } |
    Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType, ObjectType -AutoSize

# Who is in each role group right now? (compare against this document)
Get-ADGroup -Filter 'Name -like "SG-Role-*"' -SearchBase 'OU=Security Groups,OU=ADLab,DC=adlab,DC=local' |
    ForEach-Object {
        [pscustomobject]@{
            Group   = $_.Name
            Members = (Get-ADGroupMember -Identity $_ | Select-Object -ExpandProperty SamAccountName) -join ', '
        }
    } | Format-Table -AutoSize

# Catch the classic mistake: humans sitting directly in Domain Admins.
Get-ADGroupMember -Identity 'Domain Admins' -Recursive |
    Select-Object Name, SamAccountName, objectClass
```

If the last command returns anything other than the built-in `Administrator` and approved break-glass
identities, the model has drifted and needs remediation.

---

> **Disclaimer:** `adlab.local` / `adlab.io` are fictional domains used in a personal home lab. No real
> tenant identifiers, employee data or production configuration appears in this repository.
