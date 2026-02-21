#Requires -Modules ActiveDirectory
#Requires -Version 5.1

<#
.SYNOPSIS
    Produces a consolidated Active Directory identity hygiene report covering lockouts,
    disabled accounts, expiring passwords, weak password settings and stale computers.

.DESCRIPTION
    A single read-only pass over the directory that answers the five questions asked in
    almost every access review and security audit:

        1. Which accounts are currently locked out?          -> active incident / brute force
        2. Which accounts are disabled?                      -> licence waste, cleanup backlog
        3. Whose password expires in the next N days?         -> pre-empt helpdesk calls
        4. Which accounts have PASSWD_NOTREQD set?            -> genuine security finding
        5. Which computer objects are stale (90+ days)?       -> attack surface / cleanup

    The script is strictly READ-ONLY. It never modifies, disables or deletes anything -
    it produces evidence so a human can decide. That is intentional: an audit tool that
    also remediates is an audit tool nobody is allowed to run on a schedule.

    Password expiry is calculated from msDS-UserPasswordExpiryTimeComputed, a constructed
    attribute the DC calculates for us. WHY that instead of PasswordLastSet + MaxPasswordAge:
    the constructed attribute correctly accounts for Fine-Grained Password Policies, so a
    user under a different PSO is not reported incorrectly.

.PARAMETER SearchBase
    Optional DN to scope the report (e.g. 'OU=ADLab,DC=adlab,DC=local').
    Defaults to the whole domain.

.PARAMETER PasswordExpiryDays
    Report passwords expiring within this many days. Defaults to 7.

.PARAMETER StaleComputerDays
    Threshold in days for a computer object to count as stale. Defaults to 90.

.PARAMETER ReportPath
    Folder for CSV output. Defaults to .\reports.

.PARAMETER NoExport
    Display the report on screen only; skip CSV export.

.EXAMPLE
    PS> .\Get-ADHealthReport.ps1 -Verbose

    Full-domain audit with console tables and CSV export to .\reports.

.EXAMPLE
    PS> .\Get-ADHealthReport.ps1 -SearchBase 'OU=ADLab,DC=adlab,DC=local' -PasswordExpiryDays 14 -StaleComputerDays 60

    Scoped audit with a 14-day password warning window and a stricter 60-day stale threshold.

.EXAMPLE
    PS> $r = .\Get-ADHealthReport.ps1 -NoExport
    PS> $r.LockedOutAccounts | Where-Object Department -eq 'Finance'

    Capture the result object and slice it in the pipeline. The script returns a single
    object with one property per audit section.

.NOTES
    Author : Hybrid Cloud AD Lab (personal portfolio project)
    Domain : adlab.local (fictional)

    Scheduling: run daily as a scheduled task under a gMSA with read-only rights.
    Read-only is the whole point - there is nothing here that needs write access.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$SearchBase,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$PasswordExpiryDays = 7,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleComputerDays = 90,

    [Parameter()]
    [string]$ReportPath = (Join-Path -Path $PSScriptRoot -ChildPath '..\reports'),

    [Parameter()]
    [switch]$NoExport
)

begin {
    $ErrorActionPreference = 'Stop'
    Import-Module ActiveDirectory -ErrorAction Stop

    $runStamp = Get-Date
    # Collects non-fatal per-section failures so the summary can report partial results honestly.
    $script:SectionErrors = @()
    Write-Verbose "AD health report started $($runStamp.ToString('yyyy-MM-dd HH:mm:ss'))"

    # Splat reused by every query so -SearchBase is honoured consistently. Building it once
    # avoids the classic bug where one section silently reports on the whole domain.
    $scope = @{}
    if ($PSBoundParameters.ContainsKey('SearchBase') -and $SearchBase) {
        $scope['SearchBase'] = $SearchBase
        Write-Verbose "Scoped to SearchBase : $SearchBase"
    }
    else {
        Write-Verbose 'Scoped to entire domain.'
    }

    function Get-OUFromDN {
        # Small helper: the parent container is far more useful in a report than a full DN.
        param([string]$DistinguishedName)
        if (-not $DistinguishedName) { return '' }
        ($DistinguishedName -split ',', 2)[1]
    }
}

process {
    $domain = Get-ADDomain -ErrorAction Stop
    Write-Verbose "Domain : $($domain.DNSRoot)"

    # =================================================================================
    # SECTION 1 - Locked-out accounts
    # WHY FIRST: this is the only section that can represent an incident happening RIGHT
    # NOW (a brute-force attempt, or a stale credential on a phone hammering a DC).
    # Search-ADAccount queries the PDC emulator, which holds the authoritative lockout
    # state - a plain Get-ADUser against a random DC can return stale badPwdCount data.
    # =================================================================================
    Write-Verbose 'Section 1/5 : locked-out accounts'
    # WHY try/catch per section: a rights or connectivity failure in ONE query
    # (e.g. no permission to read computer objects) should degrade that section to
    # empty and carry on, not abort an audit that was otherwise producing findings.
    try {
        $lockedOut = @(
            Search-ADAccount -LockedOut -UsersOnly @scope -ErrorAction Stop |
                Get-ADUser -Properties LockedOut, LockoutTime, BadLogonCount, LastBadPasswordAttempt,
                                       Department, Title, EmailAddress, whenCreated -ErrorAction SilentlyContinue |
                ForEach-Object {
                    [pscustomobject]@{
                        Section           = 'LockedOut'
                        SamAccountName    = $_.SamAccountName
                        Name              = $_.Name
                        Department        = $_.Department
                        Title             = $_.Title
                        Enabled           = $_.Enabled
                        LockoutTime       = if ($_.LockoutTime) { [datetime]::FromFileTime($_.LockoutTime) } else { $null }
                        BadLogonCount     = $_.BadLogonCount
                        LastBadPassword   = $_.LastBadPasswordAttempt
                        OU                = Get-OUFromDN $_.DistinguishedName
                    }
                } | Sort-Object LockoutTime -Descending
        )
    }
    catch {
        Write-Warning "Section 'locked-out accounts' failed: $($_.Exception.Message)"
        $lockedOut = @()
        $script:SectionErrors += "locked-out accounts: $($_.Exception.Message)"
    }
    Write-Verbose "  found $($lockedOut.Count)"

    # =================================================================================
    # SECTION 2 - Disabled accounts
    # WHY IT MATTERS: in a hybrid tenant a disabled on-prem account still syncs to Entra ID
    # and can still hold an assigned licence. Disabled accounts sitting outside the
    # Disabled Users OU also indicate an offboarding process that was not followed.
    # =================================================================================
    Write-Verbose 'Section 2/5 : disabled accounts'
    # WHY try/catch per section: a rights or connectivity failure in ONE query
    # (e.g. no permission to read computer objects) should degrade that section to
    # empty and carry on, not abort an audit that was otherwise producing findings.
    try {
        $disabled = @(
            Search-ADAccount -AccountDisabled -UsersOnly @scope -ErrorAction Stop |
                Get-ADUser -Properties Department, Title, LastLogonDate, whenChanged, Description -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $ou = Get-OUFromDN $_.DistinguishedName
                    [pscustomobject]@{
                        Section        = 'Disabled'
                        SamAccountName = $_.SamAccountName
                        Name           = $_.Name
                        Department     = $_.Department
                        Title          = $_.Title
                        LastLogonDate  = $_.LastLogonDate
                        DaysSinceLogon = if ($_.LastLogonDate) { [math]::Round(((Get-Date) - $_.LastLogonDate).TotalDays) } else { 'Never' }
                        LastModified   = $_.whenChanged
                        # Flag accounts that were disabled but never relocated - a broken process.
                        InDisabledOU   = ($ou -like 'OU=Disabled Users,*')
                        OU             = $ou
                        Description    = $_.Description
                    }
                } | Sort-Object LastLogonDate
        )
    }
    catch {
        Write-Warning "Section 'disabled accounts' failed: $($_.Exception.Message)"
        $disabled = @()
        $script:SectionErrors += "disabled accounts: $($_.Exception.Message)"
    }
    Write-Verbose "  found $($disabled.Count)"

    # =================================================================================
    # SECTION 3 - Passwords expiring within N days
    # WHY the constructed attribute: msDS-UserPasswordExpiryTimeComputed is calculated by
    # the DC and honours Fine-Grained Password Policies. Doing the maths manually from
    # PasswordLastSet + domain MaxPasswordAge silently produces wrong answers for anyone
    # under a PSO.
    # Filtering out PasswordNeverExpires and disabled accounts avoids noise nobody acts on.
    # =================================================================================
    Write-Verbose "Section 3/5 : passwords expiring within $PasswordExpiryDays day(s)"
    $cutoff = (Get-Date).AddDays($PasswordExpiryDays)

    # WHY try/catch per section: a rights or connectivity failure in ONE query
    # (e.g. no permission to read computer objects) should degrade that section to
    # empty and carry on, not abort an audit that was otherwise producing findings.
    try {
        $expiring = @(
            Get-ADUser -Filter { Enabled -eq $true -and PasswordNeverExpires -eq $false } @scope `
                       -Properties 'msDS-UserPasswordExpiryTimeComputed', PasswordLastSet, Department,
                                   Title, EmailAddress, PasswordNeverExpires -ErrorAction Stop |
                ForEach-Object {
                    $raw = $_.'msDS-UserPasswordExpiryTimeComputed'

                    # 0        = must change at next logon (no expiry date yet)
                    # MaxValue = password never expires (belt and braces; already filtered)
                    if ($null -eq $raw -or $raw -eq 0 -or $raw -eq [int64]::MaxValue) { return }

                    $expiryDate = [datetime]::FromFileTime($raw)
                    if ($expiryDate -le $cutoff) {
                        [pscustomobject]@{
                            Section         = 'PasswordExpiring'
                            SamAccountName  = $_.SamAccountName
                            Name            = $_.Name
                            Department      = $_.Department
                            Title           = $_.Title
                            EmailAddress    = $_.EmailAddress
                            PasswordLastSet = $_.PasswordLastSet
                            ExpiryDate      = $expiryDate
                            DaysRemaining   = [math]::Round(($expiryDate - (Get-Date)).TotalDays, 1)
                            AlreadyExpired  = ($expiryDate -lt (Get-Date))
                            OU              = Get-OUFromDN $_.DistinguishedName
                        }
                    }
                } | Sort-Object ExpiryDate
        )
    }
    catch {
        Write-Warning "Section 'expiring passwords' failed: $($_.Exception.Message)"
        $expiring = @()
        $script:SectionErrors += "expiring passwords: $($_.Exception.Message)"
    }
    Write-Verbose "  found $($expiring.Count)"

    # =================================================================================
    # SECTION 4 - Accounts with "password not required" (PASSWD_NOTREQD, UAC bit 0x0020)
    # WHY THIS IS A REAL FINDING: this flag lets an account be set to a BLANK password,
    # bypassing every complexity and length rule in the domain policy. It is frequently
    # left behind by migration tools and old provisioning scripts. Any enabled account
    # with this bit set is a straightforward audit failure.
    # The LDAP bitwise filter (1.2.840.113556.1.4.803) matches the bit server-side, which
    # is far faster than pulling every user and testing userAccountControl in PowerShell.
    # =================================================================================
    Write-Verbose 'Section 4/5 : accounts with PASSWD_NOTREQD set'
    # WHY try/catch per section: a rights or connectivity failure in ONE query
    # (e.g. no permission to read computer objects) should degrade that section to
    # empty and carry on, not abort an audit that was otherwise producing findings.
    try {
        $passwordNotRequired = @(
            Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=32)' @scope `
                       -Properties PasswordNotRequired, PasswordLastSet, Department, Title,
                                   LastLogonDate, whenCreated, Enabled -ErrorAction Stop |
                ForEach-Object {
                    [pscustomobject]@{
                        Section         = 'PasswordNotRequired'
                        SamAccountName  = $_.SamAccountName
                        Name            = $_.Name
                        Enabled         = $_.Enabled
                        Department      = $_.Department
                        Title           = $_.Title
                        PasswordLastSet = $_.PasswordLastSet
                        LastLogonDate   = $_.LastLogonDate
                        Created         = $_.whenCreated
                        # Enabled + flag set = act today. Disabled + flag set = fix before re-enabling.
                        RiskLevel       = if ($_.Enabled) { 'HIGH' } else { 'Medium (disabled)' }
                        OU              = Get-OUFromDN $_.DistinguishedName
                    }
                } | Sort-Object RiskLevel, SamAccountName
        )
    }
    catch {
        Write-Warning "Section 'password-not-required accounts' failed: $($_.Exception.Message)"
        $passwordNotRequired = @()
        $script:SectionErrors += "password-not-required accounts: $($_.Exception.Message)"
    }
    Write-Verbose "  found $($passwordNotRequired.Count)"

    # =================================================================================
    # SECTION 5 - Stale computer objects (90+ days)
    # WHY PasswordLastSet and not LastLogonDate: domain-joined machines rotate their
    # computer account password automatically every 30 days. If that has not happened in
    # 90+ days the machine is genuinely gone (or off the domain), whereas LastLogonDate is
    # not replicated between DCs and gives inconsistent answers.
    # Stale computer objects matter because they keep a valid SID and can be resurrected.
    # =================================================================================
    Write-Verbose "Section 5/5 : computer objects stale for $StaleComputerDays+ days"
    $staleCutoff = (Get-Date).AddDays(-$StaleComputerDays)

    # WHY try/catch per section: a rights or connectivity failure in ONE query
    # (e.g. no permission to read computer objects) should degrade that section to
    # empty and carry on, not abort an audit that was otherwise producing findings.
    try {
        $staleComputers = @(
            Get-ADComputer -Filter * @scope `
                           -Properties PasswordLastSet, LastLogonDate, OperatingSystem,
                                       OperatingSystemVersion, whenCreated, Enabled, Description -ErrorAction Stop |
                ForEach-Object {
                    # Fall back to whenCreated for machines that never set a password.
                    $reference = if ($_.PasswordLastSet) { $_.PasswordLastSet } else { $_.whenCreated }
                    if ($reference -and $reference -lt $staleCutoff) {
                        [pscustomobject]@{
                            Section         = 'StaleComputer'
                            Name            = $_.Name
                            Enabled         = $_.Enabled
                            OperatingSystem = $_.OperatingSystem
                            OSVersion       = $_.OperatingSystemVersion
                            PasswordLastSet = $_.PasswordLastSet
                            LastLogonDate   = $_.LastLogonDate
                            DaysStale       = [math]::Round(((Get-Date) - $reference).TotalDays)
                            Created         = $_.whenCreated
                            OU              = Get-OUFromDN $_.DistinguishedName
                            Description     = $_.Description
                        }
                    }
                } | Sort-Object DaysStale -Descending
        )
    }
    catch {
        Write-Warning "Section 'stale computer objects' failed: $($_.Exception.Message)"
        $staleComputers = @()
        $script:SectionErrors += "stale computer objects: $($_.Exception.Message)"
    }
    Write-Verbose "  found $($staleComputers.Count)"

    # =================================================================================
    # CONSOLE OUTPUT
    # Format-Table per section rather than one flat table: the useful columns differ
    # completely between a lockout and a stale computer.
    # =================================================================================
    $line = '=' * 78

    Write-Host ''
    Write-Host $line -ForegroundColor Cyan
    Write-Host ' ACTIVE DIRECTORY HEALTH REPORT' -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  Domain      : {0}" -f $domain.DNSRoot)
    Write-Host ("  Scope       : {0}" -f $(if ($SearchBase) { $SearchBase } else { 'Entire domain' }))
    Write-Host ("  Generated   : {0}" -f $runStamp.ToString('yyyy-MM-dd HH:mm:ss'))
    Write-Host ("  Thresholds  : password expiry {0}d | stale computer {1}d" -f $PasswordExpiryDays, $StaleComputerDays)
    Write-Host ''

    # --- 1. Locked out -----------------------------------------------------------
    Write-Host '[1] LOCKED-OUT ACCOUNTS' -ForegroundColor Yellow
    if ($lockedOut.Count) {
        $lockedOut | Format-Table -AutoSize SamAccountName, Name, Department, LockoutTime, BadLogonCount, LastBadPassword |
            Out-String | Write-Host
        Write-Host "    -> Investigate repeat offenders with Get-ADUser <name> -Properties badPwdCount and DC Event ID 4740." -ForegroundColor DarkGray
    }
    else { Write-Host '    None. ' -ForegroundColor Green }

    # --- 2. Disabled -------------------------------------------------------------
    Write-Host ''
    Write-Host '[2] DISABLED ACCOUNTS' -ForegroundColor Yellow
    if ($disabled.Count) {
        $disabled | Format-Table -AutoSize SamAccountName, Name, Department, LastLogonDate, DaysSinceLogon, InDisabledOU |
            Out-String | Write-Host
        $misplaced = @($disabled | Where-Object { -not $_.InDisabledOU })
        if ($misplaced.Count) {
            Write-Host ("    -> {0} disabled account(s) are NOT in the Disabled Users OU: offboarding process was not followed." -f $misplaced.Count) -ForegroundColor Red
        }
    }
    else { Write-Host '    None.' -ForegroundColor Green }

    # --- 3. Expiring passwords ---------------------------------------------------
    Write-Host ''
    Write-Host ("[3] PASSWORDS EXPIRING WITHIN {0} DAY(S)" -f $PasswordExpiryDays) -ForegroundColor Yellow
    if ($expiring.Count) {
        $expiring | Format-Table -AutoSize SamAccountName, Name, Department, PasswordLastSet, ExpiryDate, DaysRemaining, AlreadyExpired |
            Out-String | Write-Host
        Write-Host '    -> Notify these users proactively; expiry-driven lockouts are the top helpdesk ticket source.' -ForegroundColor DarkGray
    }
    else { Write-Host '    None.' -ForegroundColor Green }

    # --- 4. Password not required ------------------------------------------------
    Write-Host ''
    Write-Host '[4] ACCOUNTS WITH "PASSWORD NOT REQUIRED"' -ForegroundColor Yellow
    if ($passwordNotRequired.Count) {
        $passwordNotRequired | Format-Table -AutoSize SamAccountName, Name, Enabled, RiskLevel, PasswordLastSet, LastLogonDate, OU |
            Out-String | Write-Host
        Write-Host '    -> SECURITY FINDING. These accounts may have a blank password.' -ForegroundColor Red
        Write-Host '       Remediate with: Set-ADUser <name> -PasswordNotRequired $false   (then force a reset)' -ForegroundColor DarkGray
    }
    else { Write-Host '    None. ' -ForegroundColor Green }

    # --- 5. Stale computers ------------------------------------------------------
    Write-Host ''
    Write-Host ("[5] STALE COMPUTER OBJECTS ({0}+ DAYS)" -f $StaleComputerDays) -ForegroundColor Yellow
    if ($staleComputers.Count) {
        $staleComputers | Format-Table -AutoSize Name, Enabled, OperatingSystem, PasswordLastSet, DaysStale, OU |
            Out-String | Write-Host
        Write-Host '    -> Recommended: disable and move to a quarantine OU for 30 days before deletion.' -ForegroundColor DarkGray
    }
    else { Write-Host '    None.' -ForegroundColor Green }

    # --- Scorecard ---------------------------------------------------------------
    Write-Host ''
    Write-Host $line -ForegroundColor Cyan
    Write-Host ' SUMMARY' -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  Locked out accounts        : {0}" -f $lockedOut.Count)
    Write-Host ("  Disabled accounts          : {0}" -f $disabled.Count)
    Write-Host ("  Passwords expiring <= {0}d  : {1}" -f $PasswordExpiryDays, $expiring.Count)
    Write-Host ("  Password-not-required      : {0}" -f $passwordNotRequired.Count) -ForegroundColor ($(if ($passwordNotRequired.Count) { 'Red' } else { 'Gray' }))
    Write-Host ("  Stale computers (>= {0}d)   : {1}" -f $StaleComputerDays, $staleComputers.Count)

    # WHY this matters: a section that failed reports zero findings, which looks identical
    # to a clean result. Saying so explicitly stops a permissions problem being mistaken
    # for a healthy directory.
    if ($script:SectionErrors.Count) {
        Write-Host ''
        Write-Host '  PARTIAL RESULTS - one or more sections failed to run:' -ForegroundColor Red
        $script:SectionErrors | ForEach-Object { Write-Host "    ! $_" -ForegroundColor Red }
        Write-Host '    Counts above are NOT a clean bill of health for those sections.' -ForegroundColor Red
    }

    Write-Host ''

    # =================================================================================
    # CSV EXPORT
    # One CSV per section (correct, non-lossy columns) plus a combined summary file that
    # is easy to trend over time in Excel or Power BI.
    # =================================================================================
    $exported = @()

    if (-not $NoExport) {
        try {
            if (-not (Test-Path -Path $ReportPath)) {
                New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
            }

            $stamp = $runStamp.ToString('yyyyMMdd-HHmmss')

            $sections = [ordered]@{
                'LockedOut'           = $lockedOut
                'Disabled'            = $disabled
                'PasswordExpiring'    = $expiring
                'PasswordNotRequired' = $passwordNotRequired
                'StaleComputers'      = $staleComputers
            }

            foreach ($name in $sections.Keys) {
                $data = $sections[$name]
                if (-not $data.Count) { continue }   # do not litter the folder with empty files

                $file = Join-Path -Path $ReportPath -ChildPath "ADHealth-$name-$stamp.csv"
                $data | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                $exported += $file
                Write-Verbose "Exported $($data.Count) row(s) -> $file"
            }

            # Combined scorecard - one row per run, ideal for trending.
            $summaryFile = Join-Path -Path $ReportPath -ChildPath "ADHealth-Summary-$stamp.csv"
            [pscustomobject]@{
                GeneratedOn         = $runStamp.ToString('yyyy-MM-dd HH:mm:ss')
                Domain              = $domain.DNSRoot
                Scope               = $(if ($SearchBase) { $SearchBase } else { 'Entire domain' })
                LockedOut           = $lockedOut.Count
                Disabled            = $disabled.Count
                PasswordExpiring    = $expiring.Count
                PasswordNotRequired = $passwordNotRequired.Count
                StaleComputers      = $staleComputers.Count
            } | Export-Csv -Path $summaryFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

            $exported += $summaryFile

            Write-Host '  CSV export:' -ForegroundColor Cyan
            $exported | ForEach-Object { Write-Host "    $_" }
            Write-Host ''
        }
        catch {
            Write-Warning "CSV export failed: $($_.Exception.Message)"
        }
    }

    # Return a structured object so the report can be consumed programmatically
    # (e.g. piped into an email digest or a monitoring system).
    [pscustomobject]@{
        GeneratedOn                = $runStamp
        Domain                     = $domain.DNSRoot
        Scope                      = $(if ($SearchBase) { $SearchBase } else { 'Entire domain' })
        LockedOutAccounts          = $lockedOut
        DisabledAccounts           = $disabled
        ExpiringPasswords          = $expiring
        PasswordNotRequiredAccounts = $passwordNotRequired
        StaleComputers             = $staleComputers
        ExportedFiles              = $exported
        SectionErrors              = $script:SectionErrors
        IsComplete                 = ($script:SectionErrors.Count -eq 0)
    }
}
