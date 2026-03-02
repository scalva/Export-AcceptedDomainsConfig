<# 
.SYNOPSIS
Accepted Domains Analyzer for Exchange Online (SPF/DKIM/DMARC via DomainHealthChecker).

.DESCRIPTION
Gets Exchange Online Accepted Domains and creates a CSV table with DNS/authentication analysis.
Designed for consulting/audit scenarios. PowerShell 7 compatible.

.ORIGINAL_AUTHOR
Ernesto Cobos Roqueñí

.ORIGINAL_SOURCE
https://github.com/ernestocrmsft/guacamole/tree/main/Scripts

.NOTES
Original concept adapted and extended for consulting and audit scenarios.

.CREDITS
- Uses DomainHealthChecker module (Invoke-SpfDkimDmarc) for SPF/DKIM/DMARC analysis (see README).
- Additional contributor(s): see README.

.PARAMETER OutputFolder
Base output folder. The script creates a timestamped subfolder per execution.

.PARAMETER InstallModules
If set, installs required modules (CurrentUser scope) when missing.

.PARAMETER NoConnect
If set, does not call Connect-ExchangeOnline (useful when already connected).

.PARAMETER SkipDhc
If set, skips DomainHealthChecker execution (NOT recommended; reduces usefulness).

.LICENSE
MIT
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder = (Join-Path -Path (Get-Location) -ChildPath "Output"),

    [Parameter()]
    [switch]$InstallModules,

    [Parameter()]
    [switch]$NoConnect,

    [Parameter()]
    [switch]$SkipDhc
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# DomainHealthChecker "OK" messages (PASS criteria)
$DHC_OK_SPF   = 'An SPF-record is configured and the policy is sufficiently strict.'
$DHC_OK_DKIM  = 'DKIM-record found.'
$DHC_OK_DMARC = 'Domain has a DMARC record and your DMARC policy will prevent abuse of your domain by phishers and spammers.'

function Write-Info {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host $Message -ForegroundColor Cyan
}

function Test-Command {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-PropValue {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$PropertyName
    )
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$PropertyName]
    if ($null -ne $p) { return $p.Value }
    return $null
}

function Get-PassFailFromOkText {
    param(
        [string]$Advisory,
        [string]$OkText
    )

    if ([string]::IsNullOrWhiteSpace($Advisory)) { return 'FAIL' }

    # Exact match first (trim)
    if ($Advisory.Trim() -eq $OkText) { return 'PASS' }

    # Fallback: contains (tolerates minor formatting changes)
    if ($Advisory -like "*$OkText*") { return 'PASS' }

    return 'FAIL'
}

function Assert-RequiredModule {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$RequiredVersion
    )

    $available = Get-Module -ListAvailable -Name $Name
    if ($available) { return }

    if (-not $InstallModules) {
        throw "Required module '$Name' is not installed. Install it manually or re-run with -InstallModules."
    }

    Write-Info "Installing module '$Name' (CurrentUser scope)..."
    if ($RequiredVersion) {
        Install-Module $Name -RequiredVersion $RequiredVersion -Force -Scope CurrentUser
    } else {
        Install-Module $Name -Force -Scope CurrentUser
    }
}

function New-ExecutionFolder {
    param([Parameter(Mandatory)][string]$BaseFolder)

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $execFolder = Join-Path -Path $BaseFolder -ChildPath "AcceptedDomains_$timestamp"

    if (-not (Test-Path $execFolder)) {
        New-Item -Path $execFolder -ItemType Directory -Force | Out-Null
    }
    return $execFolder
}

function Export-Results {
    param(
        [Parameter(Mandatory)]$Objects,
        [Parameter(Mandatory)][string]$Path
    )
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
    $Objects | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

function Add-ErrorLog {
    param(
        [Parameter(Mandatory)][string]$LogPath,
        [Parameter(Mandatory)][string]$Message
    )
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
}

try {
    # Execution folder + files
    $ExecutionFolder = New-ExecutionFolder -BaseFolder $OutputFolder
    $CsvOutput       = Join-Path $ExecutionFolder "AcceptedDomains_Analysis.csv"
    $SummaryCsv      = Join-Path $ExecutionFolder "AcceptedDomains_PassFail.csv"
    $ErrorLog        = Join-Path $ExecutionFolder "errors.log"
    $ExecutionInfo   = Join-Path $ExecutionFolder "ExecutionInfo.json"

    Write-Info "Execution folder:"
    Write-Info "  $ExecutionFolder"

    # Modules
    Assert-RequiredModule -Name 'ExchangeOnlineManagement' -RequiredVersion '3.1.0'
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    if (-not $SkipDhc) {
        Assert-RequiredModule -Name 'DomainHealthChecker'
        Import-Module DomainHealthChecker -ErrorAction Stop

        if (-not (Test-Command 'Invoke-SpfDkimDmarc')) {
            throw "DomainHealthChecker loaded but 'Invoke-SpfDkimDmarc' not found. Please verify module version."
        }
    }

    # Connect
    if (-not $NoConnect) {
        Write-Info "Connecting to Exchange Online..."
        Connect-ExchangeOnline -ShowBanner:$false | Out-Null
    }

    # Best-effort org/tenant info
    $orgConfig = $null
    try {
        if (Test-Command 'Get-OrganizationConfig') {
            $orgConfig = Get-OrganizationConfig
        }
    } catch {
        Add-ErrorLog -LogPath $ErrorLog -Message "Get-OrganizationConfig failed: $($_.Exception.Message)"
    }

    $connInfo = $null
    try {
        if (Test-Command 'Get-ConnectionInformation') {
            $connInfo = Get-ConnectionInformation | Select-Object -First 1
        }
    } catch {
        Add-ErrorLog -LogPath $ErrorLog -Message "Get-ConnectionInformation failed: $($_.Exception.Message)"
    }

    $tenantId =
        (Get-PropValue -Object $orgConfig -PropertyName 'ExternalDirectoryOrganizationId') ??
        (Get-PropValue -Object $connInfo -PropertyName 'TenantId') ??
        (Get-PropValue -Object $connInfo -PropertyName 'OrganizationId')

    $orgName =
        (Get-PropValue -Object $orgConfig -PropertyName 'Name') ??
        (Get-PropValue -Object $connInfo -PropertyName 'Organization')

    # Execution metadata
    $meta = [pscustomobject]@{
        RunTimestamp = (Get-Date).ToString("s")
        User         = $env:USERNAME
        ComputerName = $env:COMPUTERNAME
        PowerShell   = $PSVersionTable.PSVersion.ToString()
        OrgName      = $orgName
        TenantId     = $tenantId
        OutputFolder = $ExecutionFolder
        OutputCsv    = $CsvOutput
        SummaryCsv   = $SummaryCsv
        SkipDhc      = [bool]$SkipDhc
    }
    $meta | ConvertTo-Json -Depth 6 | Out-File -FilePath $ExecutionInfo -Encoding UTF8

    # Get accepted domains
    Write-Info "Retrieving Accepted Domains..."
    $acceptedDomains = @(Get-AcceptedDomain)

    if (-not $acceptedDomains -or $acceptedDomains.Count -eq 0) {
        Write-Warning "No accepted domains returned."
    }

    # Optional: EXO DKIM status map (best effort)
    $dkimMap = @{}
    if (Test-Command 'Get-DkimSigningConfig') {
        foreach ($ad in $acceptedDomains) {
            try {
                $d = $ad.DomainName
                $cfg = Get-DkimSigningConfig -Identity $d -ErrorAction Stop
                $dkimMap[$d] = $cfg
            } catch {
                # Not fatal
            }
        }
    }

    $results = foreach ($ad in $acceptedDomains) {
        $domain = $ad.DomainName

        # DomainHealthChecker analysis (core)
        $dhc = $null
        if (-not $SkipDhc) {
            try {
                $dhc = Invoke-SpfDkimDmarc -Name $domain
            } catch {
                Add-ErrorLog -LogPath $ErrorLog -Message "Invoke-SpfDkimDmarc failed for '$domain': $($_.Exception.Message)"
            }
        }

        # Safe reads from DHC
        $spfAdvisory   = Get-PropValue $dhc 'SpfAdvisory'
        $spfRecord     = Get-PropValue $dhc 'SpfRecord'
        $spfLen        = Get-PropValue $dhc 'SPFRecordLenght'   # module spelling

        $dmarcAdvisory = Get-PropValue $dhc 'DmarcAdvisory'
        $dmarcRecord   = Get-PropValue $dhc 'DmarcRecord'

        $dkimAdvisory  = Get-PropValue $dhc 'DkimAdvisory'
        $dkimSelector  = Get-PropValue $dhc 'DkimSelector'
        $dkimRecord    = Get-PropValue $dhc 'DkimRecord'

        $mtaAdvisory   = Get-PropValue $dhc 'MtaAdvisory'
        $mtaRecord     = Get-PropValue $dhc 'MtaRecord'

        # PASS/FAIL strictly based on module "OK" text
        $spfpass   = Get-PassFailFromOkText -Advisory $spfAdvisory   -OkText $DHC_OK_SPF
        $dkimpass  = Get-PassFailFromOkText -Advisory $dkimAdvisory  -OkText $DHC_OK_DKIM
        $dmarcpass = Get-PassFailFromOkText -Advisory $dmarcAdvisory -OkText $DHC_OK_DMARC

        # EXO DKIM status (best effort)
        $exoDkimEnabled   = $null
        $exoDkimDomain    = $null
        $exoDkimSelector1 = $null
        $exoDkimSelector2 = $null
        if ($dkimMap.ContainsKey($domain)) {
            $cfg = $dkimMap[$domain]
            $exoDkimEnabled   = Get-PropValue $cfg 'Enabled'
            $exoDkimDomain    = Get-PropValue $cfg 'Domain'
            $exoDkimSelector1 = Get-PropValue $cfg 'Selector1CNAME'
            $exoDkimSelector2 = Get-PropValue $cfg 'Selector2CNAME'
        }

        [pscustomobject]@{
            # EXO context
            DomainName    = $domain
            DomainType    = $ad.DomainType
            IsDefault     = $ad.Default

            # DHC analysis
            SPF_Advisory     = $spfAdvisory
            SPF_Record       = $spfRecord
            SPF_RecordLength = $spfLen

            DMARC_Advisory   = $dmarcAdvisory
            DMARC_Record     = $dmarcRecord

            DKIM_Advisory    = $dkimAdvisory
            DKIM_Selector    = $dkimSelector
            DKIM_Record      = $dkimRecord

            MTA_Advisory     = $mtaAdvisory
            MTA_Record       = $mtaRecord

            # EXO DKIM status (extra context)
            EXO_DKIM_Enabled   = $exoDkimEnabled
            EXO_DKIM_Domain    = $exoDkimDomain
            EXO_DKIM_Selector1 = $exoDkimSelector1
            EXO_DKIM_Selector2 = $exoDkimSelector2

            # PASS/FAIL summary (requested)
            spfpass   = $spfpass
            dkimpass  = $dkimpass
            dmarcpass = $dmarcpass
        }
    }

    Write-Info "Exporting analysis table CSV -> $CsvOutput"
    Export-Results -Objects $results -Path $CsvOutput

    # Summary CSV (your requested structure)
    $summary = $results | Select-Object `
        @{n='Domain_Name';e={$_.DomainName}}, `
        spfpass, dkimpass, dmarcpass

    Write-Info "Exporting summary CSV -> $SummaryCsv"
    Export-Results -Objects $summary -Path $SummaryCsv

    # Quick preview
    Write-Info "Preview (first 10 rows):"
    $summary | Select-Object -First 10 | Format-Table -AutoSize

    Write-Host "Done." -ForegroundColor Green
    Write-Host "Output folder: $ExecutionFolder" -ForegroundColor Green

} catch {
    try {
        if ($ErrorLog) {
            Add-ErrorLog -LogPath $ErrorLog -Message "FATAL: $($_.Exception.Message)"
        }
    } catch { }

    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    throw
} finally {
    if (Test-Command 'Disconnect-ExchangeOnline') {
        try { Disconnect-ExchangeOnline -Confirm:$false | Out-Null } catch { }
    }
}