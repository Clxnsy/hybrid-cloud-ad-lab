#Requires -Modules ActiveDirectory
#Requires -Version 5.1

<#
.SYNOPSIS
    Builds the departmental Organizational Unit (OU) hierarchy for the adlab.local domain.

.DESCRIPTION
    Creates a predictable, tiered OU structure that every other script in this repository
    depends on. The structure separates *people*, *groups*, and *decommissioned objects*
    so that Group Policy, delegated administration (RBAC) and Microsoft Entra Connect
    sync scoping can all target clean, stable containers.

    Layout produced (relative to the domain root):

        OU=ADLab
          |- OU=Departments
          |    |- OU=HR
          |    |- OU=IT
          |    |- OU=Sales
          |    |- OU=Finance
          |- OU=Security Groups
          |- OU=Disabled Users
          |- OU=Servers
          |- OU=Workstations

    Design reasoning (this repo doubles as study material):
      * A single top-level OU ("ADLab") keeps every managed object under one root, which
        means Entra Connect OU filtering is a single checkbox instead of a moving target.
      * Departments are separate OUs so GPOs and delegation can be scoped per business
        unit without security-group filtering gymnastics.
      * "Disabled Users" is deliberately OUTSIDE the Departments tree so that offboarded
        accounts immediately fall out of departmental GPO scope and (optionally) out of
        Entra Connect sync scope.
      * Security groups live in their own OU so a delegated helpdesk can be granted rights
        over user objects without inheriting rights over group objects.

    The script is idempotent: re-running it will not error or duplicate OUs. It also
    enables accidental-deletion protection on every OU it creates.

.PARAMETER DomainDN
    Distinguished name of the domain root, e.g. 'DC=adlab,DC=local'.
    Defaults to the DN of the current domain, so the script is portable between labs.

.PARAMETER RootOUName
    Name of the top-level container that holds the whole managed structure.
    Defaults to 'ADLab'.

.PARAMETER Departments
    Departmental OUs to create beneath OU=Departments. Defaults to HR, IT, Sales, Finance.

.PARAMETER ProtectFromDeletion
    When $true (default) each created OU gets accidental-deletion protection. Turning this
    off is only sensible in a throwaway lab you intend to tear down with a script.

.EXAMPLE
    PS> .\Set-OUStructure.ps1 -WhatIf

    Shows every OU that WOULD be created without touching Active Directory.
    Always run this first in a domain you did not build yourself.

.EXAMPLE
    PS> .\Set-OUStructure.ps1 -Verbose

    Creates the structure in the current domain and logs each decision (created vs. skipped).

.EXAMPLE
    PS> .\Set-OUStructure.ps1 -DomainDN 'DC=adlab,DC=local' -Departments 'HR','IT','Sales','Finance','Legal' -Verbose

    Creates the structure with an extra Legal department.

.NOTES
    Author : Hybrid Cloud AD Lab (personal portfolio project)
    Domain : adlab.local (fictional)
    Tested : Windows Server 2022, PowerShell 5.1, RSAT ActiveDirectory module
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DomainDN = (Get-ADDomain -ErrorAction Stop).DistinguishedName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RootOUName = 'ADLab',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$Departments = @('HR', 'IT', 'Sales', 'Finance'),

    [Parameter()]
    [bool]$ProtectFromDeletion = $true
)

begin {
    # Stop on unhandled errors so a partially-built OU tree never looks like a success.
    $ErrorActionPreference = 'Stop'

    Import-Module ActiveDirectory -ErrorAction Stop

    # Running tally so the operator gets a real summary instead of a wall of verbose text.
    $script:Created = [System.Collections.Generic.List[string]]::new()
    $script:Skipped = [System.Collections.Generic.List[string]]::new()
    $script:Failed  = [System.Collections.Generic.List[string]]::new()

    function New-LabOU {
        <#
        .SYNOPSIS
            Idempotently creates a single OU beneath a given parent path.
        .DESCRIPTION
            Wrapping New-ADOrganizationalUnit gives us three things the raw cmdlet does not:
              1. An existence check, so re-running the script is safe (idempotency).
              2. Consistent -WhatIf behaviour inherited from the parent script.
              3. Centralised error handling and result tallying.
        #>
        [CmdletBinding(SupportsShouldProcess = $true)]
        param(
            [Parameter(Mandatory)][string]$Name,
            [Parameter(Mandatory)][string]$Path,
            [Parameter()][string]$Description = '',
            [Parameter()][bool]$Protect = $true
        )

        $ouDN = "OU=$Name,$Path"

        try {
            # -------------------------------------------------------------------------
            # WHY: an LDAP filter search is cheaper and safer than Get-ADOrganizationalUnit
            # -Identity inside a try/catch, because a missing OU is a *normal* outcome here,
            # not an exception we want to swallow.
            # -------------------------------------------------------------------------
            $existing = Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$ouDN)" -ErrorAction SilentlyContinue

            if ($existing) {
                Write-Verbose "SKIP    : '$ouDN' already exists."
                $script:Skipped.Add($ouDN)
                return
            }

            # ShouldProcess is what wires -WhatIf / -Confirm through to the actual change.
            if ($PSCmdlet.ShouldProcess($ouDN, 'Create Organizational Unit')) {
                New-ADOrganizationalUnit -Name $Name `
                                         -Path $Path `
                                         -Description $Description `
                                         -ProtectedFromAccidentalDeletion $Protect `
                                         -ErrorAction Stop

                Write-Verbose "CREATED : '$ouDN' (protected=$Protect)"
                $script:Created.Add($ouDN)
            }
            else {
                # -WhatIf path: record it so the dry run still produces a useful summary.
                Write-Verbose "WHATIF  : would create '$ouDN'"
            }
        }
        catch {
            # WHY: we do not rethrow. One failed OU (e.g. a name collision with a container)
            # should not abandon the rest of the tree; we surface everything at the end.
            Write-Warning "FAILED  : '$ouDN' -> $($_.Exception.Message)"
            $script:Failed.Add("$ouDN :: $($_.Exception.Message)")
        }
    }
}

process {
    Write-Verbose "Target domain DN : $DomainDN"
    Write-Verbose "Root OU name     : $RootOUName"
    Write-Verbose "Departments      : $($Departments -join ', ')"

    try {
        # ---------------------------------------------------------------------------
        # STEP 1 - Top-level root OU.
        # WHY FIRST: every other container is a child of this one, so creation order
        # matters. AD will reject a child whose parent path does not exist yet.
        # ---------------------------------------------------------------------------
        New-LabOU -Name $RootOUName `
                  -Path $DomainDN `
                  -Description 'Root container for all lab-managed objects. Entra Connect sync scope is set here.' `
                  -Protect $ProtectFromDeletion

        $rootDN = "OU=$RootOUName,$DomainDN"

        # ---------------------------------------------------------------------------
        # STEP 2 - Second-level containers.
        # WHY: separating people / groups / retired objects / machines is what makes
        # least-privilege delegation possible later (see policies/rbac-role-definitions.md).
        # ---------------------------------------------------------------------------
        $secondLevel = [ordered]@{
            'Departments'     = 'Parent container for all departmental user OUs.'
            'Security Groups' = 'All role and department security groups. Delegated separately from user objects.'
            'Disabled Users'  = 'Offboarded accounts. Intentionally outside Departments so departmental GPOs no longer apply.'
            'Servers'         = 'Member servers. Receives the hardened server baseline GPO.'
            'Workstations'    = 'Domain-joined clients. Receives the workstation baseline + Entra hybrid join GPO.'
        }

        foreach ($ou in $secondLevel.Keys) {
            New-LabOU -Name $ou -Path $rootDN -Description $secondLevel[$ou] -Protect $ProtectFromDeletion
        }

        # ---------------------------------------------------------------------------
        # STEP 3 - Departmental OUs.
        # WHY: New-EmployeeOnboarding.ps1 resolves a user's target OU purely from the
        # Department column in the CSV, so these names are effectively an API contract.
        # ---------------------------------------------------------------------------
        $departmentsDN = "OU=Departments,$rootDN"

        # WHY test $WhatIfPreference directly instead of calling ShouldProcess again:
        # in a dry run the parent OU was never actually created, so attempting to create
        # children would throw a misleading "directory object not found". ShouldProcess is
        # reserved for describing real changes - using it as a "am I in -WhatIf?" test would
        # emit a phantom operation line and double-prompt under -Confirm.
        if (-not $WhatIfPreference) {
            foreach ($dept in $Departments) {
                New-LabOU -Name $dept `
                          -Path $departmentsDN `
                          -Description "User accounts for the $dept department." `
                          -Protect $ProtectFromDeletion
            }
        }
        else {
            foreach ($dept in $Departments) {
                Write-Host "What if: Performing the operation `"Create Organizational Unit`" on target `"OU=$dept,$departmentsDN`"."
            }
        }
    }
    catch {
        # A failure here (e.g. no rights to the domain root) is genuinely fatal.
        throw "Fatal error building OU structure: $($_.Exception.Message)"
    }
}

end {
    # -------------------------------------------------------------------------------
    # Operator summary. WHY: verbose output scrolls away; a short structured summary is
    # what you actually paste into a change ticket.
    # -------------------------------------------------------------------------------
    Write-Host ''
    Write-Host '=============================================' -ForegroundColor Cyan
    Write-Host ' OU Structure Deployment Summary'              -ForegroundColor Cyan
    Write-Host '=============================================' -ForegroundColor Cyan
    Write-Host ("  Created : {0}" -f $script:Created.Count) -ForegroundColor Green
    Write-Host ("  Skipped : {0} (already existed)" -f $script:Skipped.Count) -ForegroundColor Yellow
    Write-Host ("  Failed  : {0}" -f $script:Failed.Count) -ForegroundColor ($(if ($script:Failed.Count) { 'Red' } else { 'Gray' }))

    if ($script:Created.Count) {
        Write-Host ''
        Write-Host '  New OUs:' -ForegroundColor Green
        $script:Created | ForEach-Object { Write-Host "    + $_" }
    }

    if ($script:Failed.Count) {
        Write-Host ''
        Write-Host '  Failures:' -ForegroundColor Red
        $script:Failed | ForEach-Object { Write-Host "    ! $_" }
    }

    Write-Host ''
    Write-Host 'Next step: run New-EmployeeOnboarding.ps1 -CsvPath ..\sample-data\employees.csv -WhatIf' -ForegroundColor Gray
    Write-Host ''
}
