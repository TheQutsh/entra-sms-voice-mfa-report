<#
.SYNOPSIS
    Lists Microsoft Entra ID users who have SMS or Voice Call registered as an
    authentication method, ahead of the Microsoft-provided SMS & Voice retirement
    on 1 February 2027.

.DESCRIPTION
    Produces an on-screen summary plus, depending on -OutputFormat:
      * a single CSV  - the working list for the remediation team
      * a single HTML - a self-contained report to send to stakeholders
                        (no dependencies, opens in any browser, sortable and filterable)

    HOW ENTRA STORES THIS
    Entra does not hold "SMS" and "Voice" as two separate registrations. It holds a
    phone number with a type, and the type decides what it can do:
        mobile           -> can receive SMS codes AND voice calls
        alternateMobile  -> voice calls only
        office           -> voice calls only

    Every user in the output is affected by the retirement. The report shows which of
    them can receive SMS, and what each one needs to do about it.

.PARAMETER TenantId
    Optional tenant ID or domain to connect to.

.PARAMETER OutputFolder
    Folder for the output files. Created if missing. Default: current directory.

.PARAMETER OutputFormat
    CSV, HTML, or Both. Default: Both.

.PARAMETER IncludePhoneNumbers
    Adds a masked phone number column. Requires UserAuthenticationMethod.Read.All and
    makes one extra Graph call per affected user, so it is slower on large tenants.

.PARAMETER ExcludeGuests
    Leaves guest (B2B) accounts out of the report.

.PARAMETER CustomerName
    Optional organisation name shown in the HTML report header.

.EXAMPLE
    .\Get-SmsVoiceMfaUsers.ps1

.EXAMPLE
    .\Get-SmsVoiceMfaUsers.ps1 -OutputFormat HTML -CustomerName "Contoso Ltd"

.EXAMPLE
    .\Get-SmsVoiceMfaUsers.ps1 -IncludePhoneNumbers -OutputFolder C:\Reports

.NOTES
    Graph permissions required:
        AuditLog.Read.All   + User.Read.All              (always)
        UserAuthenticationMethod.Read.All                (only with -IncludePhoneNumbers)
    Global Reader or Security Reader covers these.

    Only the Microsoft.Graph.Authentication module is needed:
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
#>

[CmdletBinding()]
param(
    [string] $TenantId,
    [string] $OutputFolder = '.',
    [ValidateSet('CSV', 'HTML', 'Both')]
    [string] $OutputFormat = 'Both',
    [switch] $IncludePhoneNumbers,
    [switch] $ExcludeGuests,
    [string] $CustomerName,
    [switch] $KeepSession,
    [switch] $NoFilePermissionHardening
)

$ErrorActionPreference = 'Stop'
$GraphBase = 'https://graph.microsoft.com/v1.0'
$MinimumGraphVersion = '2.0.0'

$PhoneMethods = @('mobilePhone', 'alternateMobilePhone', 'officePhone')

# Methods that remain valid MFA factors after the retirement.
# email / securityQuestion / temporaryAccessPass are excluded on purpose - they are
# password-reset and onboarding methods, not standing MFA factors.
$StrongMethods = @(
    'microsoftAuthenticatorPush', 'microsoftAuthenticatorPasswordless',
    'softwareOneTimePasscode', 'hardwareOneTimePasscode',
    'windowsHelloForBusiness', 'fido2SecurityKey', 'macOsSecureEnclaveKey'
)

$FriendlyMethodName = @{
    mobilePhone                        = 'Mobile phone (SMS + voice)'
    alternateMobilePhone               = 'Alternate mobile (voice)'
    officePhone                        = 'Office phone (voice)'
    microsoftAuthenticatorPush         = 'Authenticator app'
    microsoftAuthenticatorPasswordless = 'Authenticator passwordless'
    softwareOneTimePasscode            = 'Authenticator / software OTP'
    hardwareOneTimePasscode            = 'Hardware token'
    windowsHelloForBusiness            = 'Windows Hello for Business'
    fido2SecurityKey                   = 'FIDO2 security key'
    macOsSecureEnclaveKey              = 'macOS platform credential'
    email                              = 'Email (password reset only)'
    temporaryAccessPass                = 'Temporary Access Pass'
    passKeyDeviceBound                 = 'Passkey'
    passKeyDeviceBoundAuthenticator    = 'Passkey (Authenticator)'
    passKeyDeviceBoundWindowsHello     = 'Passkey (Windows Hello)'
    none                               = 'None'
}

$ActionText = @{
    1 = 'No other MFA method - user will be blocked at sign-in'
    2 = 'Change default method, then remove the phone number'
    3 = 'Alternative already in place - just remove the phone number'
}

function Get-FriendlyName {
    param([string] $Method)
    if (-not $Method) { return '' }
    if ($FriendlyMethodName.ContainsKey($Method)) { return $FriendlyMethodName[$Method] }
    if ($Method -like 'passKey*') { return 'Passkey' }
    return $Method
}

function Test-StrongMethod {
    param([string[]] $Methods)
    foreach ($m in $Methods) {
        if ($StrongMethods -contains $m -or $m -like 'passKey*') { return $true }
    }
    return $false
}

function Invoke-GraphGetWithRetry {
    param([Parameter(Mandatory)][string] $Uri, [int] $MaxAttempts = 5)
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try { return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject }
        catch {
            $status = $null
            try { $status = [int]$_.Exception.Response.StatusCode } catch { }
            if ($status -in 429,500,502,503,504 -and $attempt -lt $MaxAttempts) {
                $wait = [math]::Min([math]::Pow(2, $attempt), 30)
                try { if ($_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds) {
                          $wait = $_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds } } catch { }
                Start-Sleep -Seconds $wait
                continue
            }
            throw
        }
    }
}

function Invoke-GraphGetAll {
    param([Parameter(Mandatory)][string] $Uri, [string] $Label = 'Reading from Microsoft Graph')
    $out  = [System.Collections.Generic.List[object]]::new()
    $next = $Uri; $page = 0
    while ($next) {
        $page++
        Write-Progress -Activity $Label -Status "Page $page - $($out.Count) records"
        $r = Invoke-GraphGetWithRetry -Uri $next
        if ($r.value) { $out.AddRange(@($r.value)) }
        $next = $r.'@odata.nextLink'
    }
    Write-Progress -Activity $Label -Completed
    return $out
}

function Hide-PhoneNumber {
    param([string] $Number)
    if ([string]::IsNullOrWhiteSpace($Number)) { return '' }
    $d = $Number -replace '[^\d+]', ''
    if ($d.Length -le 7) { return ('*' * $d.Length) }
    return $d.Substring(0,4) + ('*' * ($d.Length - 7)) + $d.Substring($d.Length - 3)
}

function Protect-CsvValue {
    <#
        Neutralises CSV / DDE formula injection.

        Display names and UPNs are attacker-influenced: a guest or a self-service
        user can set a display name beginning with = + - @ or a control character.
        Excel and LibreOffice evaluate such cells as formulas on open, which can
        trigger DDE or hyperlink-based data exfiltration on the analyst workstation.
        Prefixing with an apostrophe forces the value to be treated as text.
    #>
    param([object] $Value)
    if ($null -eq $Value) { return $Value }
    if ($Value -isnot [string]) { return $Value }
    if ($Value -match '^[\s]*[=+\-@\t\r]') { return "'" + $Value }
    return $Value
}

function Protect-CsvObject {
    param([Parameter(ValueFromPipeline)] $InputObject)
    process {
        $safe = [ordered]@{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            $safe[$prop.Name] = Protect-CsvValue $prop.Value
        }
        [pscustomobject]$safe
    }
}

function Set-RestrictiveAcl {
    <#
        The output contains user principal names, admin status and optionally phone
        numbers. On Windows, remove inherited access and grant only the current user.
        Best effort - never fatal.
    #>
    param([string] $Path)
    if ($NoFilePermissionHardening) { return }
    if (-not $IsWindows -and $PSVersionTable.PSVersion.Major -ge 6) { return }
    try {
        $acl = Get-Acl -Path $Path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($r in @($acl.Access)) { $null = $acl.RemoveAccessRule($r) }
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $me, 'FullControl', 'Allow'))
        Set-Acl -Path $Path -AclObject $acl
    } catch {
        Write-Verbose "Could not harden permissions on $Path : $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------- connect

$mod = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
       Sort-Object Version -Descending | Select-Object -First 1
if (-not $mod) {
    throw "Microsoft.Graph.Authentication is not installed. Run: Install-Module Microsoft.Graph.Authentication -MinimumVersion $MinimumGraphVersion -Scope CurrentUser"
}
if ($mod.Version -lt [version]$MinimumGraphVersion) {
    throw "Microsoft.Graph.Authentication $($mod.Version) is installed; $MinimumGraphVersion or later is required. Run: Update-Module Microsoft.Graph.Authentication"
}
Import-Module Microsoft.Graph.Authentication -MinimumVersion $MinimumGraphVersion -ErrorAction Stop

# Least privilege: userRegistrationDetails requires only AuditLog.Read.All.
# UserAuthenticationMethod.Read.All is added ONLY when phone numbers are requested.
# This script performs GET requests exclusively - no write scope is ever requested.
$scopes = @('AuditLog.Read.All')
if ($IncludePhoneNumbers) { $scopes += 'UserAuthenticationMethod.Read.All' }

# Reuse an existing session only if it is BOTH sufficiently scoped AND in the
# expected tenant. Without the tenant check, a consultant moving between client
# tenants can silently produce a report from the previously connected tenant.
$ctx        = Get-MgContext
$reuse      = $false
$weConnected = $false

if ($ctx) {
    $scopeOk  = -not ($scopes | Where-Object { $_ -notin $ctx.Scopes })
    $tenantOk = $true
    if ($TenantId) {
        $tenantOk = ($ctx.TenantId -eq $TenantId)
        if (-not $tenantOk -and $TenantId -notmatch '^[0-9a-f-]{36}$') {
            # caller passed a domain rather than a GUID - verify against the tenant's domains
            try {
                $org = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
                       -Uri "https://graph.microsoft.com/v1.0/organization?`$select=id,displayName,verifiedDomains"
                $domains = @($org.value)[0].verifiedDomains.name
                $tenantOk = $domains -contains $TenantId
            } catch { $tenantOk = $false }
        }
    }
    $reuse = $scopeOk -and $tenantOk

    if ($ctx -and -not $reuse) {
        Write-Host "Existing Graph session ($($ctx.Account) / tenant $($ctx.TenantId)) does not match this request. Reconnecting." -ForegroundColor Yellow
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}

if (-not $reuse) {
    Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Yellow
    $p = @{ Scopes = $scopes; NoWelcome = $true }
    if ($TenantId) { $p['TenantId'] = $TenantId }
    Connect-MgGraph @p
    $ctx = Get-MgContext
    $weConnected = $true
}

if (-not $ctx) { throw 'Could not establish a Microsoft Graph session.' }

Write-Host "Connected to tenant $($ctx.TenantId) as $($ctx.Account)" -ForegroundColor Green

# Explicit confirmation for the operator and for anyone reviewing a transcript
Write-Host "Granted scopes: $($ctx.Scopes -join ', ')" -ForegroundColor DarkGray
if ($ctx.Scopes | Where-Object { $_ -match 'Write|ReadWrite' }) {
    Write-Warning 'This Graph session carries write scopes from an earlier connection. This script only reads, but consider reconnecting with read-only scopes.'
}

# resolve a display name for the tenant if the caller did not supply one
if (-not $CustomerName) {
    try {
        $org = Invoke-GraphGetWithRetry -Uri "$GraphBase/organization?`$select=displayName"
        if ($org.value) { $CustomerName = @($org.value)[0].displayName }
    } catch { }
}
if (-not $CustomerName) { $CustomerName = $ctx.TenantId }

# ---------------------------------------------------------------- collect

Write-Host 'Reading authentication method registrations...' -ForegroundColor Yellow
$all = Invoke-GraphGetAll -Uri "$GraphBase/reports/authenticationMethods/userRegistrationDetails?`$top=999" `
                          -Label 'Reading registrations'

if (-not $all -or $all.Count -eq 0) {
    throw @'
The registration report returned no records. This is an error condition, not a clean tenant.
Likely causes: AuditLog.Read.All not consented, the signed-in account lacks a supporting
directory role (Global Reader / Security Reader / Reports Reader), or the report has not yet
been generated for a newly created tenant. Resolve this before reporting "no affected users".
'@
}

if ($ExcludeGuests) { $all = $all | Where-Object { $_.userType -ne 'guest' } }

$report = [System.Collections.Generic.List[object]]::new()

foreach ($u in $all) {
    $methods = @($u.methodsRegistered)
    $phones  = @($methods | Where-Object { $PhoneMethods -contains $_ })
    if ($phones.Count -eq 0) { continue }

    $canSms     = $methods -contains 'mobilePhone'
    $hasOther   = Test-StrongMethod -Methods $methods
    $defaultTel = $PhoneMethods -contains $u.defaultMfaMethod

    $priority = if (-not $hasOther) { 1 } elseif ($defaultTel) { 2 } else { 3 }

    $row = [ordered]@{
        'Priority'                    = $priority
        'Action Required'             = $ActionText[$priority]
        'Display Name'                = $u.userDisplayName
        'User Principal Name'         = $u.userPrincipalName
        'Account Type'                = if ($u.userType -eq 'guest') { 'Guest' } else { 'Member' }
        'Privileged Account'          = if ($u.isAdmin) { 'Yes' } else { 'No' }
        'Can Receive SMS'             = if ($canSms) { 'Yes' } else { 'No' }
        'Can Receive Voice Call'      = 'Yes'
        'Phone Types Registered'      = (($phones | ForEach-Object { Get-FriendlyName $_ }) -join ', ')
        'Default MFA Method'          = Get-FriendlyName $u.defaultMfaMethod
        'Other MFA Method Registered' = if ($hasOther) { 'Yes' } else { 'No' }
        'All Registered Methods'      = (($methods | ForEach-Object { Get-FriendlyName $_ }) -join ', ')
        'User Object Id'              = $u.id
    }
    if ($IncludePhoneNumbers) { $row['Phone Numbers'] = '' }

    $report.Add([pscustomobject]$row)
}

$phoneReadFailures = 0

if ($IncludePhoneNumbers -and $report.Count -gt 0) {
    Write-Host "Reading phone numbers for $($report.Count) users..." -ForegroundColor Yellow
    $i = 0
    foreach ($row in $report) {
        $i++
        # Deliberately no UPN in the progress status - Start-Transcript would capture it
        Write-Progress -Activity 'Reading phone numbers' -Status "$i of $($report.Count)" `
                       -PercentComplete ([int](($i / $report.Count) * 100))
        try {
            $pm = Invoke-GraphGetWithRetry -Uri "$GraphBase/users/$($row.'User Object Id')/authentication/phoneMethods"
            $row.'Phone Numbers' = (@($pm.value) | ForEach-Object {
                "$($_.phoneType): $(Hide-PhoneNumber $_.phoneNumber)"
            }) -join ' | '
        } catch {
            $row.'Phone Numbers' = 'Unable to read'
            $phoneReadFailures++
            Write-Verbose "phoneMethods read failed for object $($row.'User Object Id'): $($_.Exception.Message)"
        }
    }
    Write-Progress -Activity 'Reading phone numbers' -Completed

    if ($phoneReadFailures -gt 0) {
        Write-Warning "$phoneReadFailures of $($report.Count) phone-number lookups failed (permissions or throttling). Those rows show 'Unable to read'. The affected-user counts are still complete."
    }
}

# ---------------------------------------------------------------- figures

$sorted   = $report | Sort-Object Priority, 'Display Name'
$smsCount = @($report | Where-Object { $_.'Can Receive SMS' -eq 'Yes' }).Count
$p1       = @($report | Where-Object { $_.Priority -eq 1 }).Count
$p2       = @($report | Where-Object { $_.Priority -eq 2 }).Count
$p3       = @($report | Where-Object { $_.Priority -eq 3 }).Count
$admins   = @($report | Where-Object { $_.'Privileged Account' -eq 'Yes' }).Count
$pct      = if ($all.Count) { [math]::Round(($report.Count / $all.Count) * 100, 1) } else { 0 }

if (-not (Test-Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }
$stamp = Get-Date -Format 'yyyy-MM-dd'
$written = @()

# ---------------------------------------------------------------- console

$line = '-' * 66
Write-Host ''
Write-Host $line -ForegroundColor DarkCyan
Write-Host '  SMS / VOICE MFA REGISTRATION - SUMMARY' -ForegroundColor Cyan
Write-Host "  $CustomerName   $(Get-Date -Format 'dd MMM yyyy HH:mm')" -ForegroundColor DarkGray
Write-Host $line -ForegroundColor DarkCyan
Write-Host ''
Write-Host ("  Users checked                        {0,7}" -f $all.Count)
Write-Host ''
Write-Host ("  USERS WITH SMS OR VOICE REGISTERED   {0,7}" -f $report.Count) -ForegroundColor Yellow
Write-Host ("     of which can receive SMS          {0,7}" -f $smsCount)
Write-Host ("     of which can receive voice calls  {0,7}" -f $report.Count)
Write-Host ("     privileged accounts               {0,7}" -f $admins) -ForegroundColor $(if ($admins) {'Red'} else {'Gray'})
Write-Host ''
Write-Host ("  NO OTHER MFA METHOD - act first      {0,7}" -f $p1) -ForegroundColor $(if ($p1) {'Red'} else {'Green'})
Write-Host ''
Write-Host $line -ForegroundColor DarkCyan

if ($report.Count -gt 0) {
    Write-Host ''
    Write-Host '  What needs to happen:' -ForegroundColor Cyan
    Write-Host ("     Priority 1  {0,6}   {1}" -f $p1, $ActionText[1]) -ForegroundColor Red
    Write-Host ("     Priority 2  {0,6}   {1}" -f $p2, $ActionText[2]) -ForegroundColor Yellow
    Write-Host ("     Priority 3  {0,6}   {1}" -f $p3, $ActionText[3]) -ForegroundColor Green
    Write-Host ''

    if ($p1 -gt 0) {
        Write-Host '  First 10 users with no other MFA method:' -ForegroundColor Red
        $report | Where-Object { $_.Priority -eq 1 } |
            Select-Object -First 10 'Display Name','User Principal Name','Phone Types Registered','Privileged Account' |
            Format-Table -AutoSize | Out-String | Write-Host
    }
} else {
    Write-Host '  No users have SMS or Voice registered. Nothing to remediate.' -ForegroundColor Green
}

# ---------------------------------------------------------------- CSV

if ($OutputFormat -in 'CSV', 'Both') {
    $csvPath = Join-Path $OutputFolder "SMS-Voice-MFA-Users-$stamp.csv"
    $sorted | Protect-CsvObject | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Set-RestrictiveAcl -Path $csvPath
    $written += $csvPath
}

# ---------------------------------------------------------------- HTML

if ($OutputFormat -in 'HTML', 'Both') {

    $rows = foreach ($r in $sorted) {
        $o = [ordered]@{
            p  = $r.Priority
            n  = $r.'Display Name'
            u  = $r.'User Principal Name'
            t  = $r.'Account Type'
            a  = $r.'Privileged Account'
            s  = $r.'Can Receive SMS'
            ph = $r.'Phone Types Registered'
            d  = $r.'Default MFA Method'
            o  = $r.'Other MFA Method Registered'
            m  = $r.'All Registered Methods'
        }
        if ($IncludePhoneNumbers) { $o.num = $r.'Phone Numbers' }
        [pscustomobject]$o
    }

    $json = if ($rows) { @($rows) | ConvertTo-Json -Depth 3 -Compress } else { '[]' }
    if ($json -notmatch '^\[') { $json = "[$json]" }
    # neutralise any sequence that could break out of the script block
    $json = $json.Replace('<', '\u003c').Replace('&', '\u0026')

    $milestones = @(
        @{ d = '2026-09-01'; t = 'Passkey prompts begin'; s = 'Users enabled for SMS or Voice are auto-enabled for passkeys and nudged at next MFA' }
        @{ d = '2026-09-18'; t = 'Telecom providers published'; s = 'Microsoft publishes the list of supported third-party telecom providers' }
        @{ d = '2026-10-30'; t = 'Provider deadline'; s = 'Organisations still needing SMS or Voice must have a supported provider configured' }
        @{ d = '2027-02-01'; t = 'Retirement'; s = 'Microsoft-provided SMS and voice stop working, including for SSPR' }
    )
    $today = Get-Date
    $tlHtml = ''
    foreach ($m in $milestones) {
        $md = [datetime]$m.d
        $days = ($md - $today).Days
        $cls = if ($days -lt 0) { 'past' } elseif ($days -le 45) { 'soon' } else { 'future' }
        $when = if ($days -lt 0) { 'passed' } else { "$days days" }
        $tlHtml += "<div class='ms $cls'><div class='ms-date'>$($md.ToString('dd MMM yyyy'))</div><div class='ms-title'>$($m.t)</div><div class='ms-sub'>$($m.s)</div><div class='ms-days'>$when</div></div>`n"
    }

    $daysLeft = ([datetime]'2027-02-01' - $today).Days
    $phoneCol = if ($IncludePhoneNumbers) { 'true' } else { 'false' }

    $template = @'
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SMS / Voice MFA Registration Report</title>
<style>
:root{
  --bg:#f3f4f7; --card:#fff; --ink:#1b1f27; --muted:#6b7280; --line:#e3e6ec;
  --blue:#0f4c8a; --accent:#0078d4;
  --red:#c0392b; --redbg:#fdecea; --amber:#b7791f; --amberbg:#fdf6e3;
  --green:#1e7d4f; --greenbg:#e9f6ef;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif;
  font-size:14px;line-height:1.5}
.wrap{max-width:1440px;margin:0 auto;padding:0 28px 56px}
header{background:linear-gradient(135deg,#0f4c8a 0%,#123a63 100%);color:#fff;padding:30px 0 34px;margin-bottom:-28px}
header .wrap{padding-bottom:0}
.eyebrow{font-size:11px;letter-spacing:.14em;text-transform:uppercase;opacity:.75;margin-bottom:6px}
h1{margin:0;font-size:25px;font-weight:600;letter-spacing:-.01em}
.sub{opacity:.8;margin-top:6px;font-size:13px}
.countdown{float:right;text-align:right;background:rgba(255,255,255,.1);
  border:1px solid rgba(255,255,255,.18);border-radius:8px;padding:12px 18px}
.countdown b{display:block;font-size:30px;font-weight:600;line-height:1}
.countdown span{font-size:11px;opacity:.8;letter-spacing:.05em;text-transform:uppercase}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px;margin:44px 0 26px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 20px;
  box-shadow:0 1px 3px rgba(16,24,40,.05)}
.card .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:8px}
.card .val{font-size:34px;font-weight:600;line-height:1;letter-spacing:-.02em}
.card .note{font-size:12px;color:var(--muted);margin-top:8px}
.card.alert{border-left:4px solid var(--red)} .card.alert .val{color:var(--red)}
.card.warn{border-left:4px solid var(--amber)} .card.warn .val{color:var(--amber)}
.card.ok{border-left:4px solid var(--green)}
h2{font-size:16px;font-weight:600;margin:34px 0 14px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:20px 22px;
  box-shadow:0 1px 3px rgba(16,24,40,.05)}
.act{display:flex;align-items:center;gap:16px;padding:13px 0;border-bottom:1px solid var(--line)}
.act:last-child{border-bottom:0}
.act .num{font-size:22px;font-weight:600;min-width:78px;text-align:right}
.act .bar{flex:1;height:8px;background:#eef0f4;border-radius:4px;overflow:hidden}
.act .bar i{display:block;height:100%;border-radius:4px}
.act .txt{flex:0 0 46%;font-size:13px}
.act .txt b{display:block;font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);margin-bottom:2px}
.p1 .num,.p1 .txt b{color:var(--red)}   .p1 .bar i{background:var(--red)}
.p2 .num,.p2 .txt b{color:var(--amber)} .p2 .bar i{background:var(--amber)}
.p3 .num,.p3 .txt b{color:var(--green)} .p3 .bar i{background:var(--green)}
.timeline{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px}
.ms{background:var(--card);border:1px solid var(--line);border-top:3px solid var(--line);
  border-radius:8px;padding:14px 16px}
.ms-date{font-size:12px;font-weight:600;color:var(--muted)}
.ms-title{font-weight:600;margin:4px 0 5px}
.ms-sub{font-size:12px;color:var(--muted);line-height:1.45}
.ms-days{font-size:11px;margin-top:9px;text-transform:uppercase;letter-spacing:.06em;font-weight:600}
.ms.past{opacity:.5;border-top-color:#9aa2ae} .ms.past .ms-days{color:var(--muted)}
.ms.soon{border-top-color:var(--red)} .ms.soon .ms-days{color:var(--red)}
.ms.future{border-top-color:var(--accent)} .ms.future .ms-days{color:var(--accent)}
.toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:14px}
input[type=search]{flex:1;min-width:230px;padding:9px 13px;border:1px solid var(--line);
  border-radius:7px;font-size:13px;font-family:inherit;background:#fff}
input[type=search]:focus{outline:2px solid var(--accent);outline-offset:-1px;border-color:transparent}
.chip{padding:7px 14px;border:1px solid var(--line);background:#fff;border-radius:20px;
  cursor:pointer;font-size:12.5px;font-family:inherit;color:var(--ink);transition:all .12s}
.chip:hover{border-color:var(--accent);color:var(--accent)}
.chip.on{background:var(--blue);border-color:var(--blue);color:#fff}
.btn{padding:8px 15px;border:1px solid var(--blue);background:#fff;color:var(--blue);
  border-radius:7px;cursor:pointer;font-size:12.5px;font-weight:600;font-family:inherit}
.btn:hover{background:var(--blue);color:#fff}
.tablewrap{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;
  box-shadow:0 1px 3px rgba(16,24,40,.05)}
table{width:100%;border-collapse:collapse}
th{background:#f7f8fa;text-align:left;padding:11px 14px;font-size:11px;text-transform:uppercase;
  letter-spacing:.07em;color:var(--muted);border-bottom:1px solid var(--line);cursor:pointer;
  white-space:nowrap;user-select:none;position:sticky;top:0;z-index:2}
th:hover{color:var(--accent)}
th .arw{opacity:.35;font-size:9px;margin-left:3px}
td{padding:11px 14px;border-bottom:1px solid #f0f2f5;vertical-align:top}
tbody tr:hover{background:#fafbfc}
tbody tr:last-child td{border-bottom:0}
.pill{display:inline-block;padding:2px 9px;border-radius:11px;font-size:11px;font-weight:600;white-space:nowrap}
.pill.r{background:var(--redbg);color:var(--red)}
.pill.a{background:var(--amberbg);color:var(--amber)}
.pill.g{background:var(--greenbg);color:var(--green)}
.pill.k{background:#eef1f5;color:#4b5563}
.nm{font-weight:600} .upn{color:var(--muted);font-size:12.5px}
.dim{color:var(--muted);font-size:12.5px}
.count{color:var(--muted);font-size:12.5px;padding:11px 2px}
.empty{padding:44px;text-align:center;color:var(--muted)}
.note{background:#eef4fb;border-left:3px solid var(--accent);border-radius:0 8px 8px 0;
  padding:14px 18px;font-size:13px;margin:22px 0}
.note b{display:block;margin-bottom:4px}
footer{margin-top:36px;padding-top:18px;border-top:1px solid var(--line);
  color:var(--muted);font-size:12px}
@media print{
  body{background:#fff} .toolbar{display:none} th{position:static}
  .card,.panel,.tablewrap,.ms{box-shadow:none;break-inside:avoid}
}
</style></head><body>

<header><div class="wrap">
  <div class="countdown"><b>__DAYSLEFT__</b><span>days to retirement</span></div>
  <div class="eyebrow">Microsoft Entra ID &middot; Authentication Method Assessment</div>
  <h1>SMS &amp; Voice MFA Registration Report</h1>
  <div class="sub">__CUSTOMER__ &nbsp;&middot;&nbsp; Generated __GENERATED__</div>
</div></header>

<div class="wrap">

  <div class="cards">
    <div class="card"><div class="lbl">Users evaluated</div><div class="val">__CHECKED__</div>
      <div class="note">All principals in the tenant registration report</div></div>
    <div class="card warn"><div class="lbl">SMS or Voice registered</div><div class="val">__AFFECTED__</div>
      <div class="note">__PCT__% of all users &middot; all are in scope</div></div>
    <div class="card"><div class="lbl">Can receive SMS</div><div class="val">__SMS__</div>
      <div class="note">Have a mobile number; the rest are voice-call only</div></div>
    <div class="card alert"><div class="lbl">No other MFA method</div><div class="val">__P1__</div>
      <div class="note">Blocked at sign-in after 1 Feb 2027 unless remediated</div></div>
    <div class="card alert"><div class="lbl">Privileged accounts</div><div class="val">__ADMINS__</div>
      <div class="note">Admin-role holders relying on telephony</div></div>
  </div>

  <h2>What needs to happen</h2>
  <div class="panel">
    <div class="act p1"><div class="num">__P1__</div>
      <div class="bar"><i style="width:__P1PCT__%"></i></div>
      <div class="txt"><b>Priority 1</b>__A1__</div></div>
    <div class="act p2"><div class="num">__P2__</div>
      <div class="bar"><i style="width:__P2PCT__%"></i></div>
      <div class="txt"><b>Priority 2</b>__A2__</div></div>
    <div class="act p3"><div class="num">__P3__</div>
      <div class="bar"><i style="width:__P3PCT__%"></i></div>
      <div class="txt"><b>Priority 3</b>__A3__</div></div>
  </div>

  <h2>Key dates</h2>
  <div class="timeline">__TIMELINE__</div>

  <div class="note"><b>How to read the SMS and Voice columns</b>
  Entra does not store SMS and Voice as two separate registrations. It stores a phone number
  with a type: a mobile number can receive both SMS codes and voice calls, while an office or
  alternate mobile number can only receive voice calls. Every user listed below is affected by
  the retirement.</div>

  <h2>Affected users</h2>
  <div class="toolbar">
    <input type="search" id="q" placeholder="Search name or user principal name...">
    <button class="chip on" data-f="all">All</button>
    <button class="chip" data-f="1">Priority 1</button>
    <button class="chip" data-f="2">Priority 2</button>
    <button class="chip" data-f="3">Priority 3</button>
    <button class="chip" data-f="admin">Admins</button>
    <button class="chip" data-f="sms">SMS capable</button>
    <button class="btn" id="dl">Export current view to CSV</button>
  </div>
  <div class="count" id="count"></div>
  <div class="tablewrap"><table>
    <thead><tr>
      <th data-k="p">Priority<span class="arw">&#9650;</span></th>
      <th data-k="n">User<span class="arw">&#9650;</span></th>
      <th data-k="s">SMS<span class="arw">&#9650;</span></th>
      <th data-k="ph">Phone types<span class="arw">&#9650;</span></th>
      <th data-k="d">Default method<span class="arw">&#9650;</span></th>
      <th data-k="o">Other MFA<span class="arw">&#9650;</span></th>
      <th data-k="a">Admin<span class="arw">&#9650;</span></th>
      <th data-k="m">All methods<span class="arw">&#9650;</span></th>
      __PHONEHEAD__
    </tr></thead>
    <tbody id="tb"></tbody>
  </table>
  <div class="empty" id="empty" style="display:none">No users match the current filter.</div>
  </div>

  <footer>
    Source: Microsoft Graph <code>/reports/authenticationMethods/userRegistrationDetails</code>.
    This report is generated data and may lag live directory state by a few hours.
    Priority 1 means the user has no MFA method other than a phone number.
  </footer>
</div>

<script>
var DATA = __DATA__;
var HASPHONE = __HASPHONE__;
var ACT = {1:"__A1__",2:"__A2__",3:"__A3__"};
var filter = "all", q = "", sortKey = "p", sortAsc = true;

function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,function(c){
  return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c];});}

function view(){
  return DATA.filter(function(r){
    if(filter==="1"&&r.p!==1)return false;
    if(filter==="2"&&r.p!==2)return false;
    if(filter==="3"&&r.p!==3)return false;
    if(filter==="admin"&&r.a!=="Yes")return false;
    if(filter==="sms"&&r.s!=="Yes")return false;
    if(q){var h=(r.n+" "+r.u).toLowerCase();if(h.indexOf(q)<0)return false;}
    return true;
  }).sort(function(x,y){
    var a=x[sortKey],b=y[sortKey];
    if(a===b)return String(x.n).localeCompare(String(y.n));
    var c=(typeof a==="number"&&typeof b==="number")?a-b:String(a).localeCompare(String(b));
    return sortAsc?c:-c;
  });
}

function render(){
  var rows=view(),tb=document.getElementById("tb"),h="";
  for(var i=0;i<rows.length;i++){
    var r=rows[i], cls=r.p===1?"r":(r.p===2?"a":"g");
    h+="<tr><td><span class='pill "+cls+"'>P"+r.p+"</span></td>"
      +"<td><div class='nm'>"+esc(r.n)+"</div><div class='upn'>"+esc(r.u)
      +(r.t==="Guest"?" <span class='pill k'>Guest</span>":"")+"</div></td>"
      +"<td>"+(r.s==="Yes"?"<span class='pill a'>Yes</span>":"<span class='pill k'>No</span>")+"</td>"
      +"<td class='dim'>"+esc(r.ph)+"</td>"
      +"<td class='dim'>"+esc(r.d)+"</td>"
      +"<td>"+(r.o==="Yes"?"<span class='pill g'>Yes</span>":"<span class='pill r'>None</span>")+"</td>"
      +"<td>"+(r.a==="Yes"?"<span class='pill r'>Admin</span>":"<span class='dim'>-</span>")+"</td>"
      +"<td class='dim'>"+esc(r.m)+"</td>"
      +(HASPHONE?"<td class='dim'>"+esc(r.num)+"</td>":"")
      +"</tr>";
  }
  tb.innerHTML=h;
  document.getElementById("empty").style.display=rows.length?"none":"block";
  document.getElementById("count").textContent="Showing "+rows.length+" of "+DATA.length+" affected users";
}

document.getElementById("q").addEventListener("input",function(e){
  q=e.target.value.toLowerCase().trim();render();});

var chips=document.querySelectorAll(".chip");
for(var c=0;c<chips.length;c++){
  chips[c].addEventListener("click",function(e){
    for(var k=0;k<chips.length;k++)chips[k].classList.remove("on");
    e.target.classList.add("on");filter=e.target.getAttribute("data-f");render();});
}

var ths=document.querySelectorAll("th[data-k]");
for(var t=0;t<ths.length;t++){
  ths[t].addEventListener("click",function(e){
    var k=e.currentTarget.getAttribute("data-k");
    if(k===sortKey){sortAsc=!sortAsc;}else{sortKey=k;sortAsc=true;}
    for(var j=0;j<ths.length;j++)ths[j].querySelector(".arw").innerHTML="&#9650;";
    e.currentTarget.querySelector(".arw").innerHTML=sortAsc?"&#9650;":"&#9660;";
    render();});
}

document.getElementById("dl").addEventListener("click",function(){
  var rows=view();
  var head=["Priority","Action Required","Display Name","User Principal Name","Account Type",
            "Privileged Account","Can Receive SMS","Phone Types Registered","Default MFA Method",
            "Other MFA Method Registered","All Registered Methods"];
  if(HASPHONE)head.push("Phone Numbers");
  // same DDE / formula-injection guard as the PowerShell export
  function q2(v){var s=String(v==null?"":v);
    if(/^\s*[=+\-@\t\r]/.test(s))s="'"+s;
    return '"'+s.replace(/"/g,'""')+'"';}
  var out=[head.map(q2).join(",")];
  for(var i=0;i<rows.length;i++){var r=rows[i];
    var line=[r.p,ACT[r.p],r.n,r.u,r.t,r.a,r.s,r.ph,r.d,r.o,r.m];
    if(HASPHONE)line.push(r.num);
    out.push(line.map(q2).join(","));}
  var blob=new Blob(["\uFEFF"+out.join("\r\n")],{type:"text/csv;charset=utf-8;"});
  var a=document.createElement("a");
  a.href=URL.createObjectURL(blob);
  a.download="SMS-Voice-MFA-filtered.csv";a.click();});

render();
</script></body></html>
'@

    $maxP = [math]::Max(1, ($p1, $p2, $p3 | Measure-Object -Maximum).Maximum)

    # Tenant display name is directory data and therefore untrusted input.
    # HTML-encode it, and strip any placeholder-shaped token so it cannot be
    # substituted into during templating.
    $safeCustomer = [System.Net.WebUtility]::HtmlEncode($CustomerName) -replace '__', '_'

    $tokens = @{
        DAYSLEFT  = "$daysLeft"
        CUSTOMER  = $safeCustomer
        GENERATED = (Get-Date -Format 'dd MMMM yyyy, HH:mm')
        CHECKED   = ('{0:N0}' -f $all.Count)
        AFFECTED  = ('{0:N0}' -f $report.Count)
        SMS       = ('{0:N0}' -f $smsCount)
        ADMINS    = ('{0:N0}' -f $admins)
        PCT       = "$pct"
        P1PCT     = [string][int](($p1 / $maxP) * 100)
        P2PCT     = [string][int](($p2 / $maxP) * 100)
        P3PCT     = [string][int](($p3 / $maxP) * 100)
        P1        = ('{0:N0}' -f $p1)
        P2        = ('{0:N0}' -f $p2)
        P3        = ('{0:N0}' -f $p3)
        A1        = $ActionText[1]
        A2        = $ActionText[2]
        A3        = $ActionText[3]
        TIMELINE  = $tlHtml
        PHONEHEAD = $(if ($IncludePhoneNumbers) { '<th data-k="num">Phone numbers<span class="arw">&#9650;</span></th>' } else { '' })
        HASPHONE  = $phoneCol
        DATA      = $json
    }

    # Single pass: a value substituted in can never itself be treated as a token.
    $html = [regex]::Replace($template, '__([A-Z0-9]+)__', {
        param($m)
        $k = $m.Groups[1].Value
        if ($tokens.ContainsKey($k)) { return $tokens[$k] }
        return $m.Value
    })

    $htmlPath = Join-Path $OutputFolder "SMS-Voice-MFA-Report-$stamp.html"
    # UTF8 without BOM where the platform supports it
    [System.IO.File]::WriteAllText(
        (Join-Path (Resolve-Path $OutputFolder) "SMS-Voice-MFA-Report-$stamp.html"),
        $html,
        (New-Object System.Text.UTF8Encoding($false)))
    Set-RestrictiveAcl -Path $htmlPath
    $written += $htmlPath
}

# ---------------------------------------------------------------- finish

Write-Host ''
foreach ($f in $written) {
    Write-Host "  Saved: $(Resolve-Path $f)" -ForegroundColor Green
}

if ($written.Count -gt 0) {
    Write-Host ''
    Write-Host '  These files contain personal data (names, UPNs, privileged-role status' -ForegroundColor DarkYellow
    Write-Host '  and, if requested, masked phone numbers). Handle and retain them under the' -ForegroundColor DarkYellow
    Write-Host '  data-protection terms agreed with the customer.' -ForegroundColor DarkYellow
}

# Do not leave a cached token for this tenant on the workstation
if (-not $KeepSession -and $weConnected) {
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Host ''
        Write-Host '  Graph session disconnected.' -ForegroundColor DarkGray
    } catch { }
}

Write-Host ''
Write-Host '  Key dates: 1 Sep 2026 passkey prompts begin | 1 Feb 2027 SMS & Voice stop working' -ForegroundColor DarkGray
Write-Host ''
