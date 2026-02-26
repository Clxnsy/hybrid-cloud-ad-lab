# Conditional Access Policy Catalogue

> **Tenant:** `adlab.io` (fictional Microsoft Entra ID tenant paired with the on-premises
> `adlab.local` domain).
> **Format:** every policy is documented as **Intent → Conditions → Grant controls → Expected outcome**,
> plus the failure mode it defends against and how it was tested.

---

## Deployment ground rules

Before any of the policies below were switched on, four things were true:

1. **Two break-glass Global Administrator accounts exist** (`bg-admin-01@adlab.io`, `bg-admin-02@adlab.io`),
   are cloud-only, and are excluded from **every** policy in this catalogue. Without them, a single
   misconfigured policy locks every administrator out of the tenant permanently.
2. **Every policy starts in Report-only mode** for at least seven days. The *What If* tool models one
   sign-in; report-only mode shows what would happen to *all* of them, including the service account
   nobody remembered.
3. **Policies are additive and evaluated together.** Entra ID evaluates all matching policies and the
   grant controls are combined — the *most* restrictive set wins. A "require MFA" policy does not
   soften a "block" policy; block always wins.
4. **Named locations are defined first.** `Trusted-Office-Network` (the lab's public IP range) and
   `Approved-Countries` are prerequisites for policies CA-004.

Policy numbering is stable so incident tickets can reference `CA-002` unambiguously.

---

## CA-001 — Require MFA for all administrative roles

### Intent
Any account holding a privileged directory role must prove possession of a second factor on every
sign-in. Administrative credentials are the highest-value target in the tenant: a single reused
password on an unprotected Global Administrator is a full tenant compromise. Password-only admin
access is not defensible in 2026.

### Conditions

| Setting | Value |
|---|---|
| **Users — include** | Directory roles: Global Administrator, Privileged Role Administrator, User Administrator, Security Administrator, Exchange Administrator, SharePoint Administrator, Helpdesk (Password) Administrator, Conditional Access Administrator, Application Administrator, Cloud Application Administrator |
| **Users — exclude** | `SG-CA-Exclude-BreakGlass` (2 break-glass accounts) |
| **Target resources** | All cloud apps |
| **Network** | Any location (no trusted-network exemption — see note) |
| **Client apps** | All (browser, mobile/desktop, modern auth clients) |
| **Device platforms** | Any |
| **Sign-in risk** | Not configured |

> **Why no trusted-location exemption for admins:** "we're on the office network" is exactly the
> assumption an attacker with a foothold on an internal workstation relies on. Admin MFA is
> unconditional.

### Grant controls
- **Grant access** — **Require multifactor authentication**
- Additionally: **Require authentication strength → Phishing-resistant MFA** (FIDO2 security key or
  Windows Hello for Business) for Global Administrator and Privileged Role Administrator.
- Session: **Sign-in frequency = 4 hours**, **Persistent browser session = Never**.

### Expected outcome
- An administrator signing in with a correct password but no second factor is **blocked** and prompted
  to register/complete MFA.
- A stolen admin password alone is worthless.
- Global Administrators cannot satisfy the policy with SMS or a phone call — only a security key or
  Windows Hello, which defeats real-time phishing proxies (Evilginx-style AiTM).
- Admin sessions expire after four hours, so a stolen token/cookie has a short useful life.
- Break-glass accounts remain able to sign in with a password only.

### Tested by
Signing in as `mdelgado-adm@adlab.io` from a clean browser profile — sign-in blocked at the MFA prompt
until a FIDO2 key was presented. Entra sign-in log shows *Result: Success*, *Conditional Access: Success*,
*Authentication requirement: Multifactor authentication*, with CA-001 listed under applied policies.

---

## CA-002 — Block legacy authentication

### Intent
Legacy authentication protocols (POP3, IMAP4, SMTP AUTH, MAPI over HTTP with basic auth, older Office
clients, ActiveSync with basic auth) **cannot present an MFA challenge**. Any protocol that can only do
username + password is a permanent bypass around CA-001 — password spray attacks target exactly these
endpoints because they know MFA cannot be enforced there. Blocking legacy auth is the single highest
value-to-effort policy in the tenant.

### Conditions

| Setting | Value |
|---|---|
| **Users — include** | All users |
| **Users — exclude** | `SG-CA-Exclude-BreakGlass`, `SG-CA-Exclude-LegacyAuth-Approved` (currently: one scan-to-email MFP service account, documented exception with an expiry date) |
| **Target resources** | All cloud apps |
| **Client apps** | **Exchange ActiveSync clients** ✔ and **Other clients** ✔ (these two together = legacy auth) |
| **Network** | Any location |
| **Device platforms** | Any |

### Grant controls
- **Block access.** No exceptions, no "require MFA" fallback — a client that cannot do modern auth
  cannot do MFA, so "require MFA" would simply produce a confusing failure instead of a clean block.

### Expected outcome
- Password-spray attempts against `outlook.office365.com` over IMAP/POP fail at the Conditional Access
  layer, **even when the password is correct**. The sign-in log records *Failure — blocked by CA*, and
  the account is never marked as compromised because authentication never completed.
- Legacy Outlook clients (2010 and earlier) stop connecting and must be upgraded — this is the intended
  outcome, not a regression.
- The one approved MFP exception is scoped to a single service account with a strong unique password, an
  IP restriction, and a calendar reminder to re-evaluate at expiry.

### Tested by
Attempting an IMAP connection to the tenant with valid credentials for `praghunathan@adlab.io`:
connection rejected. Entra sign-in log (Legacy Authentication Clients filter) confirms
*Failure reason: Access has been blocked by Conditional Access policies.*

---

## CA-003 — Require a compliant or hybrid-joined device for sensitive applications

### Intent
MFA proves *who* is signing in; it says nothing about the security posture of the *machine* they are
using. A finance analyst authenticating correctly from a personal, unpatched, unencrypted laptop still
exposes financial data to whatever is running on that laptop. For the applications holding the most
sensitive data, the device must be known and healthy.

### Conditions

| Setting | Value |
|---|---|
| **Users — include** | `SG-Dept-Finance`, `SG-Dept-HR`, `SG-Role-Server-Admins-L1` |
| **Users — exclude** | `SG-CA-Exclude-BreakGlass` |
| **Target resources** | `SG-App-FinanceReporting`, `SG-App-HRIS`, Azure Management (Microsoft Azure Management app), SharePoint Online sites tagged *Confidential* |
| **Client apps** | All |
| **Device platforms** | Windows, macOS, iOS, Android |
| **Filter for devices** | Not configured |

### Grant controls
- **Grant access** — require **all** of the following:
  - **Require device to be marked as compliant** (Intune compliance policy: BitLocker on, Defender
    real-time protection on, OS build ≥ minimum, no jailbreak/root)
  - **OR Require Microsoft Entra hybrid joined device** (covers the domain-joined lab workstations that
    are hybrid-joined through Entra Connect but not Intune-enrolled)
  - **AND Require multifactor authentication**
- Session: **Use Conditional Access App Control → Block download on unmanaged devices** for browser
  sessions to SharePoint.

### Expected outcome
- A Finance user on a hybrid-joined lab workstation signs in normally after an MFA prompt.
- The same user on a personal phone or home PC is blocked with *"Your device is required to be managed
  to access this resource"* — even with a correct password and a successful MFA challenge. This is the
  key point: MFA alone does not open the door.
- BYOD access to non-sensitive apps (Teams chat, Outlook Web) is unaffected, so the policy does not push
  users toward workarounds.

### Tested by
Signing in as `praghunathan@adlab.io` to the Finance reporting app from (a) the hybrid-joined VM
`WKS-FIN-01` — success; (b) a non-joined VM — blocked with *Failure reason: Device is not compliant*.
The device state is visible in the sign-in log under *Device info*.

---

## CA-004 — Require MFA from unfamiliar or untrusted locations

### Intent
Catch the classic impossible-travel and credential-stuffing pattern: correct credentials arriving from a
country or network the organisation has never operated from. Rather than blocking outright (which breaks
legitimate travel and is a self-inflicted outage waiting to happen), raise the bar with a step-up
challenge that an attacker holding only a password cannot satisfy.

### Conditions

| Setting | Value |
|---|---|
| **Users — include** | All users |
| **Users — exclude** | `SG-CA-Exclude-BreakGlass` |
| **Target resources** | All cloud apps |
| **Network — include** | Any location |
| **Network — exclude** | Named location `Trusted-Office-Network` (lab static public IP, marked as trusted), named location `Approved-Countries` |
| **Sign-in risk** | Medium and High (Entra ID Protection, where licensed — P2) |
| **Client apps** | All |

### Grant controls
- **Grant access** — **Require multifactor authentication**
- Session: **Sign-in frequency = 1 hour** for risky sessions (re-authenticate more often when the
  context is unusual).
- Companion policy (P2 licensing): **High sign-in risk → Require password change + MFA**.

### Expected outcome
- A user at the office (inside `Trusted-Office-Network`) gets a normal password-only sign-in — no
  friction for the common case, which keeps users from seeking workarounds.
- The same account authenticating from an IP in an unlisted country is challenged for MFA. An attacker
  with a stolen password from a credential dump cannot complete the challenge and is blocked.
- A genuine traveller completes MFA and continues working — nobody has to file a ticket.
- Impossible-travel detections (sign-in from two continents within an hour) trigger the medium/high
  risk branch and force step-up.

### Tested by
Sign-in as `tnyberg@adlab.io` through a VPN egress in an unlisted country: MFA prompt appeared where the
same account on the lab network signed in with a password only. Sign-in log shows CA-004 applied and
*Location: <unlisted country>*.

---

## CA-005 — Require MFA registration from a trusted network only (secure the registration process)

### Intent
Closes the loop the other four policies leave open. If an attacker with a stolen password can *register
their own* authenticator app, every MFA requirement above becomes theatre — they simply enrol their own
second factor and satisfy the challenge. The security-info registration flow must therefore be protected
at least as strongly as the thing it protects.

### Conditions

| Setting | Value |
|---|---|
| **Users — include** | All users |
| **Users — exclude** | `SG-CA-Exclude-BreakGlass`, `SG-CA-Exclude-NewHire-Onboarding` (time-boxed, populated only on a new hire's first day and emptied nightly by automation) |
| **Target resources** | **User actions → Register security information** |
| **Network — include** | Any location |
| **Network — exclude** | Named location `Trusted-Office-Network` |
| **Client apps** | All |

### Grant controls
- **Grant access** — **Require multifactor authentication** *(i.e. registering a new factor from off-network
  requires an existing factor)*
- **AND Require Microsoft Entra hybrid joined device** for registration attempts from outside the trusted
  network.

### Expected outcome
- A new hire on their first day, sitting on the office network, registers the Authenticator app without
  friction.
- An attacker with a phished password attempting to register their own authenticator from a residential
  IP is blocked — they have no existing MFA method and no hybrid-joined device.
- A user who has lost their phone and is working remotely cannot self-serve; they must contact the
  service desk for an identity-verified reset. This is deliberate friction: the alternative is an
  MFA-reset flow that an attacker can social-engineer.

### Tested by
Attempting to add a new authentication method as `aokonkwo@adlab.io` from an external network with no
prior MFA method registered — blocked. The same action on the lab network succeeded. See
`docs/troubleshooting-scenarios.md` Scenario 5 for the resulting MFA-lockout runbook.

---

## Policy interaction matrix

What a given sign-in actually experiences, once all five policies are live:

| Scenario | CA-001 | CA-002 | CA-003 | CA-004 | Net result |
|---|---|---|---|---|---|
| Admin, office network, security key | ✔ applies | – | – | excluded (trusted) | Allowed after phishing-resistant MFA |
| Admin, home network, password only | ✔ applies | – | – | ✔ applies | **Blocked** — no second factor |
| Finance user, office, hybrid-joined PC | – | – | ✔ applies | excluded (trusted) | Allowed after MFA |
| Finance user, personal phone, correct password + MFA | – | – | ✔ applies | ✔ applies | **Blocked** — device not compliant |
| Any user, IMAP client, correct password | – | ✔ applies | – | – | **Blocked** — legacy auth |
| Sales user, foreign VPN, password only | – | – | – | ✔ applies | MFA challenge, then allowed |
| Break-glass account, anywhere | excluded | excluded | excluded | excluded | Allowed (alerts fire immediately) |

---

## Operational monitoring

| Signal | Where | Why it matters |
|---|---|---|
| Break-glass sign-in | Entra sign-in logs → alert rule, high severity | Should be zero outside a documented test or genuine emergency. |
| CA policy modified | Entra audit logs → alert on `Update conditional access policy` | Attackers disable CA before they use stolen credentials. |
| Spike in *blocked by CA* failures | Sign-in logs, weekly review | Either an attack, or a legitimate workflow the policy broke. |
| Users excluded from any policy | Monthly report | Exclusions accumulate silently and become permanent holes. |
| Legacy auth attempts after CA-002 | Sign-in logs, Legacy Authentication filter | Shows which clients/service accounts still need remediation. |

---

## Rollout order used in this lab

1. **CA-002 (block legacy auth)** — report-only 7 days, then enforced. Lowest user impact, highest value.
2. **CA-001 (admin MFA)** — enforced immediately after break-glass accounts were created and tested.
3. **CA-005 (protect registration)** — before broad user MFA, so registration cannot be hijacked.
4. **CA-004 (untrusted-location MFA)** — report-only 14 days to discover legitimate remote patterns.
5. **CA-003 (compliant device for sensitive apps)** — last, because it depends on Intune enrolment and
   hybrid join being complete for the target population.

Enabling these in the wrong order — for example CA-003 before hybrid join finished — is the fastest way
to lock out an entire department. Ask me how I know.

---

> **Disclaimer:** `adlab.io` and `adlab.local` are fictional. All users, groups, IP ranges and app names
> in this document are invented for a personal home lab. No real tenant IDs, object GUIDs or production
> policy exports appear in this repository.
