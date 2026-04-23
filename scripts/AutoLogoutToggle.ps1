<#
.SYNOPSIS
    AutoLogoutToggle.ps1 — Toggles the state (enabled/disabled) of specified
    Entra ID Conditional Access Policies via Microsoft Graph.

.DESCRIPTION
    Used by Azure Automation Runbooks to pulse a short Sign-in Frequency
    Conditional Access Policy On and Off on a daily schedule, forcing users
    to re-authenticate (and re-verify MFA) at 5 PM, 10 PM, and 2 AM local time
    across multiple regional offices.

    This is a sanitized reference copy. Replace placeholder Policy GUIDs,
    TenantId, and ClientId values with your organization's own before use.

.NOTES
    Auth mode         : Managed Identity (default) | App Secret (fallback)
    Graph endpoint    : PATCH /identity/conditionalAccess/policies/{id}
    Required scopes   : Policy.ReadWrite.ConditionalAccess (Policy.Read.All optional)
    Tested on         : PowerShell 7.2 (Azure Automation runtime)
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Enable','Disable')]
    [string]$Action,

    [string[]]$PolicyIds,

    [switch]$DryRun,

    [ValidateSet('ManagedIdentity','AppSecret')]
    [string]$Auth = 'ManagedIdentity',

    [string]$TenantId,
    [string]$ClientId,
    [securestring]$ClientSecret,

    [ValidateSet('v1.0','beta')]
    [string]$GraphApi = 'v1.0'
)

$ErrorActionPreference = 'Stop'

# -- Default target policies (REDACTED — replace with your own policy GUIDs) --
$DefaultPolicyIds = @('00000000-0000-0000-0000-000000000000')

# -- NeverDisable guard list — policy IDs listed here will be skipped on Disable
$NeverDisable = @()

# -- Input normalization --
if ($PolicyIds -is [string]) { $PolicyIds = $PolicyIds -split '\s*,\s*' }
$targetPolicyIds = if ($PolicyIds -and $PolicyIds.Count -gt 0) { $PolicyIds } else { $DefaultPolicyIds }
if (-not $targetPolicyIds -or $targetPolicyIds.Count -eq 0) {
    throw 'No PolicyIds. Set param -PolicyIds or $DefaultPolicyIds.'
}

$guidRegex = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
foreach ($id in $targetPolicyIds) {
    if ($id -notmatch $guidRegex) { throw "Invalid policy id format: $id" }
}

$state     = if ($Action -eq 'Enable') { 'enabled' } else { 'disabled' }
$graphBase = "https://graph.microsoft.com/$GraphApi"

Write-Output "> Action: $Action | DryRun: $($DryRun.IsPresent) | Policies: $($targetPolicyIds -join ', ')"
Write-Output "> Auth mode: $Auth | Graph API: $GraphApi"

# -----------------------------------------------------------------------------
# Token inspection helpers
# -----------------------------------------------------------------------------
function ConvertFrom-Base64Url([string]$b64url) {
    $pad = 4 - ($b64url.Length % 4)
    if ($pad -lt 4) { $b64url += ('=' * $pad) }
    $b64url = $b64url.Replace('-','+').Replace('_','/')
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64url))
}

function Show-TokenClaims($token) {
    try {
        $parts = $token.Split('.')
        if ($parts.Count -ge 2) {
            $payload = $parts[1] | ConvertFrom-Base64Url | ConvertFrom-Json
            $script:TokenRoles = @()
            if ($payload.roles) { $script:TokenRoles = @($payload.roles) }

            Write-Output "Token audience (aud) : $($payload.aud)"
            Write-Output "AppId(appid)         : $($payload.appid) | SP ObjectId(oid): $($payload.oid)"
            if ($script:TokenRoles.Count) {
                Write-Output ("roles in token       : " + ($script:TokenRoles -join ', '))
            } else {
                Write-Output "roles in token       : (none)"
            }
        }
    } catch {
        Write-Warning "Token decode failed: $($_.Exception.Message)"
    }
}

# -----------------------------------------------------------------------------
# Token acquisition
# -----------------------------------------------------------------------------
function Get-GraphTokenFromMI {
    $resource    = 'https://graph.microsoft.com'
    $idEndpoint  = $env:IDENTITY_ENDPOINT
    $idHeader    = $env:IDENTITY_HEADER

    if ([string]::IsNullOrWhiteSpace($idEndpoint) -or [string]::IsNullOrWhiteSpace($idHeader)) {
        $msiEndpoint = $env:MSI_ENDPOINT
        $msiSecret   = $env:MSI_SECRET
        if ($msiEndpoint -and $msiSecret) {
            $resp = Invoke-RestMethod -Method POST -Uri $msiEndpoint `
                        -Headers @{ Secret = $msiSecret } `
                        -Body    @{ resource = $resource } `
                        -ErrorAction Stop
            if (-not $resp.access_token) { throw 'MSI token response missing access_token.' }
            return $resp.access_token
        }
        throw "Managed Identity variables missing. Ensure System-assigned identity is ON."
    }

    $join = if ($idEndpoint -match '\?') { '&' } else { '?' }
    $uri  = "$idEndpoint${join}resource=$resource&api-version=2019-08-01"
    $resp = Invoke-RestMethod -Method GET -Uri $uri `
                -Headers @{ 'X-IDENTITY-HEADER' = $idHeader; 'Metadata' = 'true' } `
                -ErrorAction Stop
    if (-not $resp.access_token) { throw 'MI token response missing access_token.' }
    return $resp.access_token
}

function Get-GraphTokenFromAppSecret {
    param(
        [Parameter(Mandatory=$true)] [string]$TenantId,
        [Parameter(Mandatory=$true)] [string]$ClientId,
        [Parameter(Mandatory=$true)] [securestring]$ClientSecret
    )

    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                 [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret))
    $body = @{
        client_id     = $ClientId
        scope         = 'https://graph.microsoft.com/.default'
        client_secret = $plain
        grant_type    = 'client_credentials'
    }
    try {
        $resp = Invoke-RestMethod -Method POST -Uri $tokenEndpoint `
                    -Body $body -ContentType 'application/x-www-form-urlencoded' `
                    -ErrorAction Stop
        if (-not $resp.access_token) { throw 'Token response did not contain access_token.' }
        return $resp.access_token
    }
    finally {
        if ($plain) { [System.Array]::Clear([char[]]$plain, 0, $plain.Length) }
    }
}

# -----------------------------------------------------------------------------
# Graph call with retry / body logging
# -----------------------------------------------------------------------------
function Invoke-Graph {
    param(
        [Parameter(Mandatory=$true)] [ValidateSet('GET','PATCH')] [string]$Method,
        [Parameter(Mandatory=$true)] [string]$Url,
        [hashtable]$Body = $null,
        [int]$MaxRetry = 5
    )

    $delay = 2
    for ($i = 1; $i -le $MaxRetry; $i++) {
        try {
            if ($Body) {
                $json = $Body | ConvertTo-Json -Depth 5
                return Invoke-RestMethod -Method $Method -Uri $Url `
                            -Headers $script:Headers -Body $json `
                            -ContentType 'application/json' -ErrorAction Stop
            } else {
                return Invoke-RestMethod -Method $Method -Uri $Url `
                            -Headers $script:Headers -ErrorAction Stop
            }
        } catch {
            $resp   = $_.Exception.Response
            $status = $null
            if ($resp) { try { $status = [int]$resp.StatusCode } catch {} }

            $transient = ($status -eq 403 -or $status -eq 429 -or $status -ge 500)
            if ($i -lt $MaxRetry -and $transient) {
                Write-Warning "Retry $i/$MaxRetry after $delay s (HTTP $status)"
                Start-Sleep -Seconds $delay
                $delay = [Math]::Min($delay * 2, 30)
            } else {
                if ($resp) {
                    try {
                        $bodyText = $resp.Content.ReadAsStringAsync().Result
                        Write-Error "HTTP $status Body: $bodyText"
                    } catch {
                        Write-Warning "Failed to read error body: $($_.Exception.Message)"
                    }
                }
                throw
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Acquire token and verify permissions
# -----------------------------------------------------------------------------
switch ($Auth) {
    'ManagedIdentity' {
        $accessToken = Get-GraphTokenFromMI
    }
    'AppSecret' {
        if (-not $TenantId -or -not $ClientId -or -not $ClientSecret) {
            throw 'AppSecret auth requires -TenantId, -ClientId, -ClientSecret.'
        }
        $accessToken = Get-GraphTokenFromAppSecret -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    }
}

Show-TokenClaims $accessToken
$script:Headers = @{ Authorization = "Bearer $accessToken" }

# -----------------------------------------------------------------------------
# Main loop — toggle each target policy
# -----------------------------------------------------------------------------
$errors   = @()
$hasRead  = $script:TokenRoles -contains 'Policy.Read.All'
$hasWrite = $script:TokenRoles -contains 'Policy.ReadWrite.ConditionalAccess'
Write-Output "permissions: hasWrite=$hasWrite | hasRead=$hasRead"

foreach ($policyId in $targetPolicyIds) {

    if ($Action -eq 'Disable' -and ($policyId -in $NeverDisable)) {
        Write-Output "$policyId is in NeverDisable. Skipped."
        continue
    }

    $url = "$graphBase/identity/conditionalAccess/policies/$policyId"

    try {
        # Optimistic path: no read permission but have write — PATCH directly
        if (-not $hasRead -and $hasWrite) {
            if ($DryRun) {
                Write-Output "DryRun: would set $policyId -> $state (pre-GET skipped, no Policy.Read.All)"
                continue
            }
            Invoke-Graph -Method PATCH -Url $url -Body @{ state = $state } | Out-Null
            Write-Output "OK    $policyId -> $state (patched without pre-GET)"
            continue
        }

        # Normal path: GET, compare, PATCH only if needed
        $policy       = Invoke-Graph -Method GET -Url $url
        $currentState = $policy.state
        Write-Output "info  $policyId current state: $currentState"

        if ($currentState -eq $state) {
            Write-Output "OK    $policyId already $state — nothing to change."
            continue
        }
        if ($DryRun) {
            Write-Output "DryRun: would change $policyId from '$currentState' -> '$state'"
            continue
        }
        Invoke-Graph -Method PATCH -Url $url -Body @{ state = $state } | Out-Null
        Write-Output "OK    $policyId -> $state"

    } catch {
        $msg = "FAIL  $policyId : $($_.Exception.Message)"
        Write-Error $msg
        $errors += $msg
    }
}

if ($errors.Count -gt 0) {
    throw ("Some policies failed:" + [Environment]::NewLine + ($errors -join [Environment]::NewLine))
} else {
    Write-Output 'Done.'
}
