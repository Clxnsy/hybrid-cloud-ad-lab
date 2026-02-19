#Requires -Modules ActiveDirectory
#Requires -Version 5.1

<#
.SYNOPSIS
    Performs a controlled, auditable offboarding of one or more Active Directory user
    accounts (disable, strip groups, relocate, expire, report).

.DESCRIPTION
    Implements the "disable, don't delete" leaver process. Deleting an account destroys
    the SID, which orphans file-system ACLs, breaks mailbox delegation and - in a hybrid
    tenant - triggers a soft-delete in Microsoft Entra ID that takes 30 days to purge.
    Disabling preserves everything while immediately revoking access.

    For each identity supplied, the script:

        1.  Resolves the account and captures a full "before" snapshot for the audit trail.
        2.  Disables the account (fastest possible access revocation).
        3.  Records then removes all group memberships except the primary group.
        4.  Moves the object to the Disabled Users OU.
        5.  Sets an account expiration date (default: today) as a second, independent lock.
        6.  Stamps the description/info attributes with who/when/why.
        7.  Optionally resets the password to a random value to kill cached credentials.
        8.  Writes a confirmation report to console and CSV.

    Destructive-by-nature, so ConfirmImpact is High: the script prompts before acting
    unless -Confirm:$false is passed, and fully supports -WhatIf.

.PARAMETER Identity
    One or more SamAccountNames, UPNs or distinguished names to offboard.
    Accepts pipeline input.

.PARAMETER Reason
    Free-text reason recorded on the object and in the report (e.g. 'Resignation - TICKET-4471').

.PARAMETER PerformedBy
    Who authorised/executed the offboarding. Defaults to the current user.

.PARAMETER DomainDN
    Domain root DN. Defaults to the current domain.

.PARAMETER RootOUName
    Top-level lab OU. Defaults to 'ADLab'.

.PARAMETER ExpirationDate
    Date the account expires. Defaults to now, i.e. immediate.

.PARAMETER ResetPassword
    Also scramble the password. Recommended: it invalidates cached credentials and any
    attempt to re-enable the account without a deliberate reset.

.PARAMETER KeepGroups
    Group names to preserve (e.g. a litigation-hold or mailbox-retention group).

.PARAMETER ReportPath
    Folder for the offboarding CSV report. Defaults to .\reports.

.EXAMPLE
    PS> .\Remove-EmployeeOffboarding.ps1 -Identity tnyberg -Reason 'Resignation - TICKET-4471' -WhatIf

    Dry run showing every change that would be made to tnyberg.

.EXAMPLE
    PS> .\Remove-EmployeeOffboarding.ps1 -Identity tnyberg -Reason 'Resignation - TICKET-4471' -ResetPassword -Verbose

    Full offboarding with an interactive confirmation prompt.

.EXAMPLE
    PS> 'tnyberg','evandermeer' | .\Remove-EmployeeOffboarding.ps1 -Reason 'Contract end - TICKET-4480' -Confirm:$false

    Unattended batch offboarding (suppressed prompts) for a scheduled leaver run.

.NOTES
    Author : Hybrid Cloud AD Lab (personal portfolio project)
    Domain : adlab.local (fictional)

    Hybrid consideration: after the next Entra Connect delta sync the disabled state
    replicates to Microsoft Entra ID, but existing OAuth refresh/access tokens can remain
    valid for up to an hour. For immediate cloud revocation also run
    Revoke-MgUserSignInSession in Microsoft Graph PowerShell.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('SamAccountName', 'UserPrincipalName')]
    [ValidateNotNullOrEmpty()]
    [string[]]$Identity,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Reason = 'Not specified',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PerformedBy = $env:USERNAME,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DomainDN = (Get-ADDomain -ErrorAction Stop).DistinguishedName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RootOUName = 'ADLab',

    [Parameter()]
    [datetime]$ExpirationDate = (Get-Date),

    [Parameter()]
    [switch]$ResetPassword,

    [Parameter()]
    [string[]]$KeepGroups = @(),

    [Parameter()]
    [string]$ReportPath = (Join-Path -Path $PSScriptRoot -ChildPath '..\reports')
)

begin {
    $ErrorActionPreference = 'Stop'
    Import-Module ActiveDirectory -ErrorAction Stop

    $script:Results     = [System.Collections.Generic.List[psobject]]::new()
    $script:DisabledOU  = "OU=Disabled Users,OU=$RootOUName,$DomainDN"

    # ---------------------------------------------------------------------------------
    # Verify the destination OU up front.
    # WHY: discovering the Disabled Users OU is missing AFTER stripping a user's groups
    # leaves the account in a half-offboarded state. Fail before any change is made.
    # ---------------------------------------------------------------------------------
    $disabledOUExists = Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$script:DisabledOU)" -ErrorAction SilentlyContinue
    if (-not $disabledOUExists) {
        throw "Disabled Users OU not found at '$script:DisabledOU'. Run Set-OUStructure.ps1 first."
    }

    Write-Verbose "Disabled Users OU verified : $script:DisabledOU"
    Write-Verbose "Reason                     : $Reason"
    Write-Verbose "Performed by               : $PerformedBy"

    function New-ScrambledPassword {
        # WHY: we never need to know this value again. It exists solely to guarantee the
        # old credential (and anything cached against it) can no longer be used.
        param([int]$Length = 32)
        $set = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+'
        -join (1..$Length | ForEach-Object { $set[(Get-Random -Minimum 0 -Maximum $set.Length)] })
    }
}

process {
    foreach ($id in $Identity) {

        $record = [ordered]@{
            Identity           = $id
            SamAccountName     = $null
            DisplayName        = $null
            OriginalOU         = $null
            NewOU              = $null
            Department         = $null
            Title              = $null
            LastLogonDate      = $null
            GroupsRemoved      = ''
            GroupsRetained     = ''
            AccountDisabled    = $false
            AccountMoved       = $false
            ExpirationSet      = $null
            PasswordReset      = $false
            Reason             = $Reason
            PerformedBy        = $PerformedBy
            OffboardedOn       = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Status             = 'Pending'
            Message            = ''
        }

        try {
            # -------------------------------------------------------------------------
            # STEP 1 - Resolve the account and snapshot its state.
            # WHY snapshot first: once groups are removed, the evidence of what the user
            # had access to is gone. This snapshot IS the audit artefact.
            # -------------------------------------------------------------------------
            $user = Get-ADUser -Identity $id -Properties MemberOf, Department, Title, DisplayName,
                                                          LastLogonDate, Description, Info, Enabled `
                               -ErrorAction Stop

            $record.SamAccountName = $user.SamAccountName
            $record.DisplayName    = $user.DisplayName
            $record.OriginalOU     = ($user.DistinguishedName -split ',', 2)[1]
            $record.Department     = $user.Department
            $record.Title          = $user.Title
            $record.LastLogonDate  = $user.LastLogonDate

            Write-Verbose "Resolved $($user.SamAccountName) in $($record.OriginalOU) (enabled=$($user.Enabled))"

            # -------------------------------------------------------------------------
            # Guard rail: refuse to offboard privileged accounts without an explicit -Force
            # style acknowledgement. WHY: fat-fingering an admin SamAccountName into a
            # leaver script is a self-inflicted outage.
            # -------------------------------------------------------------------------
            $protectedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
            $userGroupNames  = @($user.MemberOf | ForEach-Object { (($_ -split ',')[0] -replace '^CN=', '') })
            $privileged      = @($userGroupNames | Where-Object { $_ -in $protectedGroups })

            # WHY the -not $WhatIfPreference guard: ShouldContinue ignores -WhatIf and would
            # prompt during a dry run, which defeats the purpose of a dry run. In -WhatIf we
            # just warn loudly and continue planning.
            if ($privileged.Count) {
                Write-Warning "$($user.SamAccountName) is a member of privileged group(s): $($privileged -join ', ')."
                if (-not $WhatIfPreference -and -not $PSCmdlet.ShouldContinue(
                        "Account '$($user.SamAccountName)' holds privileged membership ($($privileged -join ', ')). Continue with offboarding?",
                        'Privileged account offboarding')) {
                    $record.Status  = 'Skipped'
                    $record.Message = 'Operator declined privileged-account offboarding.'
                    $script:Results.Add([pscustomobject]$record)
                    continue
                }
            }

            $target = "$($user.SamAccountName) ($($user.DisplayName))"

            # -------------------------------------------------------------------------
            # STEP 2 - Disable the account FIRST.
            # WHY order matters: disabling is the single fastest revocation of interactive
            # and network logon. Group removal and the OU move are housekeeping that can
            # safely take another few seconds; access must stop immediately.
            # -------------------------------------------------------------------------
            if ($PSCmdlet.ShouldProcess($target, 'Disable account')) {
                Disable-ADAccount -Identity $user -ErrorAction Stop
                $record.AccountDisabled = $true
                Write-Verbose "DISABLED : $($user.SamAccountName)"
            }

            # -------------------------------------------------------------------------
            # STEP 3 - Remove group memberships (recording them first).
            # WHY not the primary group: AD refuses to remove a user from their primary
            # group (normally Domain Users) and the attempt throws. We filter it out.
            # WHY record: re-hires and audits both need to know what was held.
            # -------------------------------------------------------------------------
            # WHY resolve by SID rather than filtering on primaryGroupToken: primaryGroupToken
            # is a *constructed* attribute, calculated per-request by the DC, and constructed
            # attributes cannot be used in an LDAP filter - such a filter silently returns
            # nothing. The reliable method is to rebuild the group SID as
            # <domain SID>-<primaryGroupID> and look the group up directly.
            # (In practice memberOf never lists the primary group, so this is belt-and-braces
            #  against a non-default primary group configuration.)
            $primaryGroupDN = $null
            try {
                $primaryGroupId = (Get-ADUser -Identity $user -Properties primaryGroupID -ErrorAction Stop).primaryGroupID
                if ($primaryGroupId) {
                    $domainSid      = (Get-ADDomain -ErrorAction Stop).DomainSID.Value
                    $primaryGroupDN = (Get-ADGroup -Identity "$domainSid-$primaryGroupId" -ErrorAction Stop).DistinguishedName
                    Write-Verbose "PRIMARY  : $primaryGroupDN (will not be removed)"
                }
            }
            catch {
                # Non-fatal: if we cannot resolve it, Remove-ADGroupMember will simply refuse
                # that one group and we record the failure per-group below.
                Write-Verbose "Could not resolve primary group for $($user.SamAccountName): $($_.Exception.Message)"
            }

            $removed  = [System.Collections.Generic.List[string]]::new()
            $retained = [System.Collections.Generic.List[string]]::new()

            foreach ($groupDN in $user.MemberOf) {
                $groupName = ($groupDN -split ',')[0] -replace '^CN=', ''

                if ($groupDN -eq $primaryGroupDN) {
                    $retained.Add("$groupName (primary group)")
                    continue
                }

                if ($groupName -in $KeepGroups) {
                    $retained.Add("$groupName (explicitly retained)")
                    Write-Verbose "RETAIN   : $groupName"
                    continue
                }

                if ($PSCmdlet.ShouldProcess("$target -> $groupName", 'Remove group membership')) {
                    try {
                        Remove-ADGroupMember -Identity $groupDN -Members $user -Confirm:$false -ErrorAction Stop
                        $removed.Add($groupName)
                        Write-Verbose "UNGROUP  : $groupName"
                    }
                    catch {
                        # WHY tolerate: a group may be in a different domain, be a
                        # dynamic/critical system group, or already have been changed.
                        # One stubborn group must not abort the rest of the offboarding.
                        Write-Warning "Could not remove '$($user.SamAccountName)' from '$groupName': $($_.Exception.Message)"
                        $retained.Add("$groupName (removal FAILED)")
                    }
                }
                else {
                    $removed.Add("$groupName (whatif)")
                }
            }

            $record.GroupsRemoved  = ($removed  -join '; ')
            $record.GroupsRetained = ($retained -join '; ')

            # -------------------------------------------------------------------------
            # STEP 4 - Set account expiration.
            # WHY in addition to disabling: expiration is a second, independent control.
            # If somebody re-enables the account without reading the ticket, the expiry
            # date still blocks logon. Defence in depth against well-meaning helpdesk.
            # -------------------------------------------------------------------------
            if ($PSCmdlet.ShouldProcess($target, "Set account expiration to $($ExpirationDate.ToString('yyyy-MM-dd HH:mm'))")) {
                Set-ADAccountExpiration -Identity $user -DateTime $ExpirationDate -ErrorAction Stop
                $record.ExpirationSet = $ExpirationDate.ToString('yyyy-MM-dd HH:mm')
                Write-Verbose "EXPIRES  : $($record.ExpirationSet)"
            }

            # -------------------------------------------------------------------------
            # STEP 5 - Optional password scramble.
            # WHY: kills cached credentials on any device the leaver still holds and
            # prevents a re-enabled account from being usable with the old password.
            # -------------------------------------------------------------------------
            if ($ResetPassword) {
                if ($PSCmdlet.ShouldProcess($target, 'Reset password to a random value')) {
                    $scrambled = ConvertTo-SecureString -String (New-ScrambledPassword) -AsPlainText -Force
                    Set-ADAccountPassword -Identity $user -NewPassword $scrambled -Reset -ErrorAction Stop
                    $record.PasswordReset = $true
                    Write-Verbose "PASSWORD : scrambled (value intentionally discarded)"
                }
            }

            # -------------------------------------------------------------------------
            # STEP 6 - Stamp the object with provenance, then move it.
            # WHY stamp BEFORE the move: after the move the DN changes, so writing
            # attributes first avoids a second lookup.
            # -------------------------------------------------------------------------
            $stamp = "OFFBOARDED $(Get-Date -Format 'yyyy-MM-dd') by $PerformedBy | Reason: $Reason | Prior OU: $($record.OriginalOU)"

            if ($PSCmdlet.ShouldProcess($target, 'Stamp description/info with offboarding metadata')) {
                Set-ADUser -Identity $user -Description $stamp -Replace @{ info = $stamp } -ErrorAction Stop
                Write-Verbose "STAMPED  : $stamp"
            }

            # -------------------------------------------------------------------------
            # STEP 7 - Move to the Disabled Users OU.
            # WHY last: the move changes the DN, and it is the step most likely to fail
            # (accidental-deletion protection on the source OU blocks moves). Doing it last
            # means a failure here still leaves a disabled, de-grouped, expired account.
            # -------------------------------------------------------------------------
            if ($PSCmdlet.ShouldProcess($target, "Move object to $script:DisabledOU")) {
                try {
                    Move-ADObject -Identity $user.DistinguishedName -TargetPath $script:DisabledOU -ErrorAction Stop
                    $record.AccountMoved = $true
                    $record.NewOU        = $script:DisabledOU
                    Write-Verbose "MOVED    : -> $script:DisabledOU"
                }
                catch {
                    # Common cause: ProtectedFromAccidentalDeletion on the USER object,
                    # which blocks the move. Surface the fix rather than a raw COM error.
                    throw "Move failed (check ProtectedFromAccidentalDeletion on the user object): $($_.Exception.Message)"
                }
            }
            else {
                $record.NewOU = "$script:DisabledOU (whatif)"
            }

            $record.Status  = if ($WhatIfPreference) { 'WhatIf' } else { 'Offboarded' }
            $record.Message = 'Disabled, groups removed, expiration set, object relocated.'
        }
        catch {
            $record.Status  = 'Failed'
            $record.Message = $_.Exception.Message
            Write-Warning "Offboarding '$id' failed: $($_.Exception.Message)"
        }
        finally {
            $script:Results.Add([pscustomobject]$record)
        }
    }
}

end {
    # ---------------------------------------------------------------------------------
    # Offboarding confirmation report - this is the artefact that gets attached to the
    # HR/security ticket to prove access was revoked, and when.
    # ---------------------------------------------------------------------------------
    Write-Host ''
    Write-Host '=========================================================' -ForegroundColor Cyan
    Write-Host ' Offboarding Confirmation Report'                          -ForegroundColor Cyan
    Write-Host '=========================================================' -ForegroundColor Cyan

    foreach ($r in $script:Results) {
        $statusColour = switch ($r.Status) {
            'Offboarded' { 'Green'  }
            'WhatIf'     { 'Yellow' }
            'Skipped'    { 'Yellow' }
            default      { 'Red'    }
        }

        Write-Host ''
        Write-Host ("  Account        : {0}" -f $r.SamAccountName)
        Write-Host ("  Display name   : {0}" -f $r.DisplayName)
        Write-Host ("  Department     : {0} / {1}" -f $r.Department, $r.Title)
        Write-Host ("  Last logon     : {0}" -f $r.LastLogonDate)
        Write-Host ("  Disabled       : {0}" -f $r.AccountDisabled)
        Write-Host ("  Expires        : {0}" -f $r.ExpirationSet)
        Write-Host ("  Password reset : {0}" -f $r.PasswordReset)
        Write-Host ("  Moved from     : {0}" -f $r.OriginalOU)
        Write-Host ("  Moved to       : {0}" -f $r.NewOU)
        Write-Host ("  Groups removed : {0}" -f $(if ($r.GroupsRemoved)  { $r.GroupsRemoved  } else { '(none)' }))
        Write-Host ("  Groups kept    : {0}" -f $(if ($r.GroupsRetained) { $r.GroupsRetained } else { '(none)' }))
        Write-Host ("  Reason         : {0}" -f $r.Reason)
        Write-Host ("  Performed by   : {0} on {1}" -f $r.PerformedBy, $r.OffboardedOn)
        Write-Host ("  Status         : {0}" -f $r.Status) -ForegroundColor $statusColour
        if ($r.Status -eq 'Failed') { Write-Host ("  Error          : {0}" -f $r.Message) -ForegroundColor Red }
    }

    Write-Host ''
    Write-Host '---------------------------------------------------------' -ForegroundColor Cyan
    Write-Host ("  Total processed : {0}" -f $script:Results.Count)
    Write-Host ("  Offboarded      : {0}" -f @($script:Results | Where-Object Status -eq 'Offboarded').Count) -ForegroundColor Green
    Write-Host ("  Failed          : {0}" -f @($script:Results | Where-Object Status -eq 'Failed').Count)     -ForegroundColor Red

    if ($script:Results.Count) {
        try {
            if (-not (Test-Path -Path $ReportPath)) {
                New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
            }

            $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
            $file  = Join-Path -Path $ReportPath -ChildPath "Offboarding-Report-$stamp.csv"
            $script:Results | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

            Write-Host ''
            Write-Host "  Report : $file" -ForegroundColor Cyan
        }
        catch {
            Write-Warning "Could not write report to '$ReportPath': $($_.Exception.Message)"
        }
    }

    Write-Host ''
    Write-Host 'Hybrid follow-up:' -ForegroundColor Gray
    Write-Host '  1. Force a delta sync so the disabled state reaches Entra ID: Start-ADSyncSyncCycle -PolicyType Delta' -ForegroundColor Gray
    Write-Host '  2. Revoke live cloud tokens immediately: Revoke-MgUserSignInSession -UserId <upn>' -ForegroundColor Gray
    Write-Host '  3. Reassign licences and convert the mailbox to shared if retention is required.' -ForegroundColor Gray
    Write-Host ''

    $script:Results
}
