#Requires -Modules ActiveDirectory
#Requires -Version 5.1

<#
.SYNOPSIS
    Bulk-creates Active Directory user accounts from a CSV as part of a repeatable
    employee onboarding process.

.DESCRIPTION
    Reads a CSV with the columns FirstName, LastName, Department, JobTitle and, for each
    row, performs the full day-one identity provisioning sequence:

        1.  Validate the row (no blank names, department must be a known OU).
        2.  Build a SamAccountName as <first initial><lastname>, lowercased and sanitised.
        3.  Resolve collisions deterministically (mdelgado -> mdelgado2 -> mdelgado3 ...).
        4.  Create the user in the correct departmental OU.
        5.  Set a temporary password and force a change at next logon.
        6.  Add the user to the department security group (created on demand).
        7.  Enable the account.
        8.  Emit a per-user result object and a consolidated summary report (console + CSV).

    Why this exists: manual account creation is where inconsistent UPNs, missing group
    membership and orphaned accounts come from. In a hybrid environment those mistakes
    propagate to Microsoft Entra ID within one sync cycle, so the on-prem create step has
    to be right the first time.

    Hybrid-identity specifics baked in:
      * UserPrincipalName uses the *routable* suffix (adlab.io) rather than the internal
        .local domain, because Microsoft Entra ID cannot verify a .local domain and would
        otherwise fall back to <user>@<tenant>.onmicrosoft.com.
      * mail and proxyAddresses are left to be stamped by the directory/Exchange team;
        this script deliberately does not invent them.

.PARAMETER CsvPath
    Path to the onboarding CSV. Must contain FirstName, LastName, Department, JobTitle.

.PARAMETER DomainDN
    Domain root DN. Defaults to the current domain.

.PARAMETER RootOUName
    Top-level lab OU created by Set-OUStructure.ps1. Defaults to 'ADLab'.

.PARAMETER UpnSuffix
    Routable UPN suffix for hybrid sign-in. Defaults to 'adlab.io' (fictional).

.PARAMETER TemporaryPassword
    SecureString temporary password applied to every new account. If omitted, a unique
    random 16-character password is generated per user and included in the report so the
    service desk can hand it over through an approved channel.

.PARAMETER ReportPath
    Folder for the onboarding CSV report. Defaults to .\reports.

.EXAMPLE
    PS> .\New-EmployeeOnboarding.ps1 -CsvPath ..\sample-data\employees.csv -WhatIf

    Dry run. Shows every account that would be created, including the resolved username
    and target OU, without writing anything to the directory.

.EXAMPLE
    PS> .\New-EmployeeOnboarding.ps1 -CsvPath ..\sample-data\employees.csv -Verbose

    Creates all accounts with per-user generated temporary passwords and writes
    .\reports\Onboarding-Report-<timestamp>.csv.

.EXAMPLE
    PS> $pw = Read-Host -AsSecureString 'Temporary password'
    PS> .\New-EmployeeOnboarding.ps1 -CsvPath .\newhires.csv -TemporaryPassword $pw

    Uses one shared temporary password (acceptable only when every account is force-reset
    at first logon, which this script always enforces).

.NOTES
    Author : Hybrid Cloud AD Lab (personal portfolio project)
    Domain : adlab.local / adlab.io (fictional)
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateScript({
        if (-not (Test-Path -Path $_ -PathType Leaf)) { throw "CSV not found: $_" }
        $true
    })]
    [string]$CsvPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DomainDN = (Get-ADDomain -ErrorAction Stop).DistinguishedName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RootOUName = 'ADLab',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$UpnSuffix = 'adlab.io',

    [Parameter()]
    [System.Security.SecureString]$TemporaryPassword,

    [Parameter()]
    [string]$ReportPath = (Join-Path -Path $PSScriptRoot -ChildPath '..\reports')
)

begin {
    $ErrorActionPreference = 'Stop'
    Import-Module ActiveDirectory -ErrorAction Stop

    $script:Results = [System.Collections.Generic.List[psobject]]::new()

    # Cache of names claimed during THIS run. WHY: two "Marcus Delgado" rows in the same
    # CSV would both pass the AD existence check (the first is not committed yet under
    # -WhatIf, and under a real run there is a race), so we track locally as well.
    $script:ClaimedNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    function New-TemporaryPassword {
        <#
        .SYNOPSIS
            Generates a random password that satisfies default AD complexity rules.
        .DESCRIPTION
            WHY not just use a static "Welcome123!": shared static passwords are the single
            most common lab-to-production bad habit. Guaranteeing at least one character
            from each of the four categories avoids the "password does not meet complexity
            requirements" failure that otherwise leaves a half-created, disabled account.
        #>
        [CmdletBinding()]
        [OutputType([string])]
        param([int]$Length = 16)

        $upper   = 'ABCDEFGHJKLMNPQRSTUVWXYZ'   # I and O omitted to avoid transcription errors
        $lower   = 'abcdefghijkmnopqrstuvwxyz'  # l omitted for the same reason
        $digits  = '23456789'                   # 0 and 1 omitted
        $symbols = '!@#$%^&*-_=+?'

        $all = $upper + $lower + $digits + $symbols
        $chars = New-Object System.Collections.Generic.List[char]

        # One guaranteed character per category...
        foreach ($set in @($upper, $lower, $digits, $symbols)) {
            $chars.Add($set[(Get-Random -Minimum 0 -Maximum $set.Length)])
        }
        # ...then fill the remainder from the full alphabet.
        for ($i = $chars.Count; $i -lt $Length; $i++) {
            $chars.Add($all[(Get-Random -Minimum 0 -Maximum $all.Length)])
        }

        # Shuffle so the guaranteed characters are not always in positions 0-3.
        -join ($chars | Sort-Object { Get-Random })
    }

    function ConvertTo-SafeName {
        <#
        .SYNOPSIS
            Strips accents, spaces, hyphens and apostrophes from a name component.
        .DESCRIPTION
            WHY: SamAccountName has a 20-character limit and a restricted character set.
            "O'Brien-Nyberg" and "Raghunathan" must both produce a valid, predictable login.
            Normalising to FormD then dropping non-spacing marks turns "Ramírez" into
            "Ramirez" rather than mangling it or failing outright.
        #>
        [CmdletBinding()]
        [OutputType([string])]
        param([Parameter(Mandatory)][string]$Value)

        $normalized = $Value.Normalize([System.Text.NormalizationForm]::FormD)
        $sb = New-Object System.Text.StringBuilder

        foreach ($c in $normalized.ToCharArray()) {
            if ([System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($c) -ne
                [System.Globalization.UnicodeCategory]::NonSpacingMark) {
                [void]$sb.Append($c)
            }
        }

        # Keep letters and digits only; everything else is dropped.
        ($sb.ToString() -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
    }

    function Resolve-SamAccountName {
        <#
        .SYNOPSIS
            Produces a unique SamAccountName using the <first initial><lastname> convention.
        .DESCRIPTION
            WHY a collision loop: "Marcus Delgado" and "Maria Delgado" both want 'mdelgado'.
            Silently failing the second account is the worst outcome; appending an ordinal
            is boring, predictable and easy to explain to the service desk.
        #>
        [CmdletBinding()]
        [OutputType([string])]
        param(
            [Parameter(Mandatory)][string]$FirstName,
            [Parameter(Mandatory)][string]$LastName
        )

        $initial = (ConvertTo-SafeName -Value $FirstName)
        if (-not $initial) { throw "FirstName '$FirstName' contains no usable characters." }
        $initial = $initial.Substring(0, 1)

        $surname = ConvertTo-SafeName -Value $LastName
        if (-not $surname) { throw "LastName '$LastName' contains no usable characters." }

        # 20-char SamAccountName ceiling; leave 2 chars of headroom for a collision suffix.
        $base = ($initial + $surname)
        if ($base.Length -gt 18) { $base = $base.Substring(0, 18) }

        $candidate = $base
        $suffix    = 1

        while ($true) {
            $takenInAD = [bool](Get-ADUser -LDAPFilter "(sAMAccountName=$candidate)" -ErrorAction SilentlyContinue)
            $takenHere = $script:ClaimedNames.Contains($candidate)

            if (-not $takenInAD -and -not $takenHere) {
                [void]$script:ClaimedNames.Add($candidate)
                return $candidate
            }

            $suffix++
            $candidate = "$base$suffix"
            if ($suffix -gt 99) { throw "Could not find a free SamAccountName for base '$base'." }
        }
    }

    function Get-DepartmentGroupName {
        # WHY a helper rather than inline string building: the naming convention is
        # referenced by the offboarding script and the RBAC doc. One place to change it.
        param([Parameter(Mandatory)][string]$Department)
        "SG-Dept-$($Department -replace '\s', '')"
    }
}

process {
    # ---------------------------------------------------------------------------------
    # STEP 0 - Load and validate the CSV before touching AD.
    # WHY: failing fast on a malformed header is far cheaper than discovering it after
    # creating three of five accounts.
    # ---------------------------------------------------------------------------------
    Write-Verbose "Importing onboarding CSV: $CsvPath"
    $rows = @(Import-Csv -Path $CsvPath -ErrorAction Stop)

    if (-not $rows.Count) { throw "CSV '$CsvPath' contains no data rows." }

    $requiredColumns = @('FirstName', 'LastName', 'Department', 'JobTitle')
    $actualColumns   = $rows[0].PSObject.Properties.Name
    $missing         = $requiredColumns | Where-Object { $_ -notin $actualColumns }

    if ($missing) {
        throw "CSV is missing required column(s): $($missing -join ', '). Expected: $($requiredColumns -join ', ')."
    }

    Write-Verbose "Loaded $($rows.Count) row(s). Required columns present."

    $rootDN         = "OU=$RootOUName,$DomainDN"
    $departmentsDN  = "OU=Departments,$rootDN"
    $groupsDN       = "OU=Security Groups,$rootDN"

    $rowNumber = 1

    foreach ($row in $rows) {
        $rowNumber++   # +1 because row 1 is the CSV header, so errors match what the operator sees in Excel.

        $result = [ordered]@{
            Row               = $rowNumber
            FirstName         = $row.FirstName
            LastName          = $row.LastName
            Department        = $row.Department
            JobTitle          = $row.JobTitle
            SamAccountName    = $null
            UserPrincipalName = $null
            TargetOU          = $null
            SecurityGroup     = $null
            TemporaryPassword = $null
            Status            = 'Pending'
            Message           = ''
        }

        try {
            # -------------------------------------------------------------------------
            # STEP 1 - Row-level validation.
            # WHY: a blank Department would silently place a user in the wrong OU, and a
            # blank surname would produce a one-character username.
            # -------------------------------------------------------------------------
            foreach ($field in $requiredColumns) {
                if ([string]::IsNullOrWhiteSpace($row.$field)) {
                    throw "Column '$field' is empty."
                }
            }

            $department = $row.Department.Trim()
            $targetOU   = "OU=$department,$departmentsDN"

            # -------------------------------------------------------------------------
            # STEP 2 - Confirm the departmental OU exists.
            # WHY: creating the OU on the fly would let a typo ("Finanace") quietly become
            # a permanent container. Better to reject the row and fix the source data.
            # WHY this is NOT wrapped in ShouldProcess: reading the directory changes
            # nothing, so it must run in a dry run too - that is exactly when you want to
            # be told the target OU is missing. Under -WhatIf a missing OU is a warning
            # rather than a hard failure, because Set-OUStructure.ps1 may not have run yet.
            # -------------------------------------------------------------------------
            $ouExists = Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$targetOU)" -ErrorAction SilentlyContinue
            if (-not $ouExists) {
                $ouMessage = "Departmental OU '$targetOU' does not exist. Run Set-OUStructure.ps1 first, or correct the Department value."
                if ($WhatIfPreference) {
                    Write-Warning "Row $rowNumber : $ouMessage"
                }
                else {
                    throw $ouMessage
                }
            }

            # -------------------------------------------------------------------------
            # STEP 3 - Derive identity attributes.
            # -------------------------------------------------------------------------
            $sam         = Resolve-SamAccountName -FirstName $row.FirstName -LastName $row.LastName
            $displayName = "$($row.FirstName.Trim()) $($row.LastName.Trim())"
            $upn         = "$sam@$UpnSuffix"   # routable suffix -> clean hybrid sign-in name
            $groupName   = Get-DepartmentGroupName -Department $department

            $result.SamAccountName    = $sam
            $result.UserPrincipalName = $upn
            $result.TargetOU          = $targetOU
            $result.SecurityGroup     = $groupName

            # -------------------------------------------------------------------------
            # STEP 4 - Temporary password.
            # WHY per-user by default: if one handover email leaks, only one account is
            # exposed. Every account is force-reset at first logon regardless.
            # -------------------------------------------------------------------------
            if ($TemporaryPassword) {
                $securePassword = $TemporaryPassword
                $plainForReport = '<supplied by operator>'
            }
            else {
                $plainForReport = New-TemporaryPassword -Length 16
                $securePassword = ConvertTo-SecureString -String $plainForReport -AsPlainText -Force
            }
            $result.TemporaryPassword = $plainForReport

            # -------------------------------------------------------------------------
            # STEP 5 - Create the account.
            # NOTE: -Enabled is set here in the same call rather than as a later
            # Enable-ADAccount, because a password is supplied up front. Creating an
            # account enabled WITHOUT a password would violate the domain password policy.
            # -ChangePasswordAtLogon $true enforces the handover-then-rotate pattern.
            # -------------------------------------------------------------------------
            if ($PSCmdlet.ShouldProcess($upn, "Create AD user in $targetOU")) {

                $newUserParams = @{
                    Name                  = $displayName
                    GivenName             = $row.FirstName.Trim()
                    Surname               = $row.LastName.Trim()
                    DisplayName           = $displayName
                    SamAccountName        = $sam
                    UserPrincipalName     = $upn
                    Path                  = $targetOU
                    Title                 = $row.JobTitle.Trim()
                    Department            = $department
                    Company               = 'ADLab Industries'      # fictional
                    AccountPassword       = $securePassword
                    ChangePasswordAtLogon = $true
                    PasswordNeverExpires  = $false                  # never true for humans
                    CannotChangePassword  = $false
                    Enabled               = $true
                    Description           = "Onboarded $(Get-Date -Format 'yyyy-MM-dd') via New-EmployeeOnboarding.ps1"
                    ErrorAction           = 'Stop'
                }

                New-ADUser @newUserParams
                Write-Verbose "CREATED : $sam ($displayName) in $targetOU"

                # ---------------------------------------------------------------------
                # STEP 6 - Department security group (create on demand, then add member).
                # WHY create on demand HERE but not the OU: groups are cheap, flat and
                # easy to merge if duplicated; a stray OU changes GPO and delegation scope.
                # Global scope is correct for "all users in a department" in a single-domain
                # forest, and global groups sync cleanly to Entra ID.
                # ---------------------------------------------------------------------
                $group = Get-ADGroup -LDAPFilter "(sAMAccountName=$groupName)" -ErrorAction SilentlyContinue

                if (-not $group) {
                    Write-Verbose "CREATED : missing department group '$groupName'"
                    $group = New-ADGroup -Name $groupName `
                                         -SamAccountName $groupName `
                                         -GroupCategory Security `
                                         -GroupScope Global `
                                         -Path $groupsDN `
                                         -Description "All members of the $department department. Managed by onboarding automation." `
                                         -PassThru `
                                         -ErrorAction Stop
                }

                Add-ADGroupMember -Identity $group -Members $sam -ErrorAction Stop
                Write-Verbose "MEMBER  : $sam -> $groupName"

                # ---------------------------------------------------------------------
                # STEP 7 - Explicit enable check.
                # WHY belt-and-braces: some password-policy edge cases cause AD to create
                # the object disabled even when -Enabled $true was requested. Verify rather
                # than assume, because a disabled account is invisible to Entra Connect sync
                # troubleshooting until someone complains they cannot sign in.
                # ---------------------------------------------------------------------
                $created = Get-ADUser -Identity $sam -Properties Enabled -ErrorAction Stop
                if (-not $created.Enabled) {
                    Enable-ADAccount -Identity $sam -ErrorAction Stop
                    Write-Verbose "ENABLED : $sam (was created disabled)"
                }

                $result.Status  = 'Created'
                $result.Message = 'Account created, group assigned, enabled, password change forced.'
            }
            else {
                $result.Status  = 'WhatIf'
                $result.Message = "Would create $sam in $targetOU and add to $groupName."
            }
        }
        catch {
            # WHY continue instead of throw: one bad row in a 200-row new-hire batch should
            # not block the other 199. The failure is captured in the report for rework.
            $result.Status  = 'Failed'
            $result.Message = $_.Exception.Message
            Write-Warning "Row $rowNumber ($($row.FirstName) $($row.LastName)): $($_.Exception.Message)"
        }
        finally {
            $script:Results.Add([pscustomobject]$result)
        }
    }
}

end {
    # ---------------------------------------------------------------------------------
    # STEP 8 - Summary report.
    # WHY both console and CSV: the console table is for the operator running the batch;
    # the CSV is the artefact attached to the onboarding ticket and used for the password
    # handover. Passwords are written to disk deliberately and MUST be deleted after
    # handover - this is called out loudly below.
    # ---------------------------------------------------------------------------------
    $created = @($script:Results | Where-Object Status -eq 'Created')
    $failed  = @($script:Results | Where-Object Status -eq 'Failed')
    $whatIf  = @($script:Results | Where-Object Status -eq 'WhatIf')

    Write-Host ''
    Write-Host '=========================================================' -ForegroundColor Cyan
    Write-Host ' Employee Onboarding Summary'                              -ForegroundColor Cyan
    Write-Host '=========================================================' -ForegroundColor Cyan

    $script:Results |
        Format-Table -AutoSize -Property Row, SamAccountName, UserPrincipalName, Department, SecurityGroup, Status |
        Out-String |
        Write-Host

    Write-Host ("  Processed : {0}" -f $script:Results.Count)
    Write-Host ("  Created   : {0}" -f $created.Count) -ForegroundColor Green
    Write-Host ("  WhatIf    : {0}" -f $whatIf.Count)  -ForegroundColor Yellow
    Write-Host ("  Failed    : {0}" -f $failed.Count)  -ForegroundColor ($(if ($failed.Count) { 'Red' } else { 'Gray' }))

    if ($failed.Count) {
        Write-Host ''
        Write-Host '  Failed rows:' -ForegroundColor Red
        $failed | ForEach-Object { Write-Host ("    ! Row {0} {1} {2} -> {3}" -f $_.Row, $_.FirstName, $_.LastName, $_.Message) }
    }

    # Only write a report when something real happened; a -WhatIf run still writes one
    # because reviewing the planned usernames before a big batch is genuinely useful.
    if ($script:Results.Count) {
        try {
            if (-not (Test-Path -Path $ReportPath)) {
                New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
            }

            $stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
            $file   = Join-Path -Path $ReportPath -ChildPath "Onboarding-Report-$stamp.csv"

            $script:Results | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

            Write-Host ''
            Write-Host "  Report : $file" -ForegroundColor Cyan
            Write-Warning 'The report contains temporary passwords. Hand them over through an approved channel and DELETE the file afterwards. Never commit reports to source control.'
        }
        catch {
            Write-Warning "Could not write report to '$ReportPath': $($_.Exception.Message)"
        }
    }

    Write-Host ''
    Write-Host 'Hybrid note: new accounts appear in Microsoft Entra ID after the next Entra Connect delta sync (default 30 minutes).' -ForegroundColor Gray
    Write-Host 'Force a sync from the Entra Connect server with: Start-ADSyncSyncCycle -PolicyType Delta' -ForegroundColor Gray
    Write-Host ''

    # Emit objects to the pipeline so the script composes with other tooling.
    $script:Results
}
