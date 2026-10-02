# Hybrid Cloud Identity & Access Lab

A home lab where I built the identity environment most companies actually run: on-premises Windows Server Active Directory synced to Microsoft Entra ID, then layered with the automation and policies a real identity team needs. Every script and policy here was written and tested against the lab, and every troubleshooting scenario is a failure I actually reproduced and fixed, including the ones I caused myself.

## The build
- **Windows Server 2022** Active Directory domain (`adlab.local`)
- **Microsoft Entra Connect** syncing to an Entra ID tenant: Password Hash Sync, Seamless SSO, password writeback, OU-scoped sync filtering
- **Departmental OU structure** designed so Group Policy and delegation actually have something sensible to target
- **PowerShell joiner/mover/leaver automation**: provisioning, access changes, and offboarding without manual ADUC clicking
- **Daily identity-hygiene audit** script: stale accounts, privileged group membership drift, anomalies worth a look
- **Least-privilege delegation model** that keeps day-to-day admins out of Domain Admins
- **Conditional Access catalogue**: blocking legacy authentication, enforcing phishing-resistant MFA for administrators

## How to use this repo
This documents a lab, not a product. The value is in the scripts, the policy definitions, and the troubleshooting runbooks. If you are studying for identity work or building your own lab, start with the architecture overview, then work through the provisioning automation and the Conditional Access policies. Adapting the PowerShell to your own OU structure is expected; the comments explain the assumptions.

## What this lab proves
Hybrid identity architecture (AD + Entra ID + Entra Connect), PowerShell automation for the full identity lifecycle, RBAC and least-privilege design, Conditional Access policy design, and the troubleshooting discipline of reproducing a failure before claiming to understand it. This is the skill set behind "the login broke and 200 people are locked out" actually getting fixed.
