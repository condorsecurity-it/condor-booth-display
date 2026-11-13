<#
.SYNOPSIS
  One-time enrollment for Claude Code's certificate-gated SSH access -
  Windows 10/11 WORKSTATION variant (training stations, Matrix, boardroom PC).

.DESCRIPTION
  Same CA-trust model as the rest of the fleet, and the same core as
  setup-claude-access-windows.ps1 (standalone/member servers). Differences
  for client machines:

    - Alias is OPTIONAL: defaults to the lowercased computer name
      (CS-TS-01 -> cs-ts-01), so the exact same command runs on every box.
    - OpenSSH Server install falls back to the official Win32-OpenSSH MSI
      from GitHub when Add-WindowsCapability fails (WSUS-managed or
      Feature-on-Demand blocked boxes return 0x800f0954).
    - 'claude' is hidden from the Windows sign-in screen so staff never see
      a tile for it.
    - Firewall rule 'Claude-SSH-In' covers ALL profiles. Workstations often
      sit on a 'Public' network profile, and the stock OpenSSH rule may not
      apply there.
    - Group membership uses the well-known SID S-1-5-32-544, so it works on
      non-English Windows and avoids the Get-LocalGroupMember orphaned-SID
      bug on domain-joined machines.
    - Warns if a security-baseline GPO denies network logon to local admin
      accounts (S-1-5-113/114) - that silently breaks SSH for 'claude'.
    - Optional -KeepAwake disables sleep/hibernate on AC power so the box
      stays reachable.

  POSTURE: always-on, like the Linux fleet and winprobe. sshd stays
  Automatic/Running; access is time-boxed by the certificate.

.PARAMETER Alias
  Optional fleet alias (lowercase). Must match the principal grant-claude.sh
  signs (claude-<alias>). Defaults to the lowercased computer name.

.PARAMETER KeepAwake
  Disable sleep and hibernate while on AC power.

.EXAMPLE
  Elevated PowerShell:
    powershell -ExecutionPolicy Bypass -File .\setup-claude-access-workstation.ps1
    powershell -ExecutionPolicy Bypass -File .\setup-claude-access-workstation.ps1 -Alias matrix -KeepAwake
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[a-z0-9][a-z0-9-]*$')]
    [string]$Alias,
    [switch]$KeepAwake
)

$ErrorActionPreference = 'Stop'
if (-not $Alias) {
    $Alias = ($env:COMPUTERNAME.ToLowerInvariant() -replace '[^a-z0-9-]', '-').Trim('-')
}
$Alias = $Alias.ToLowerInvariant()

# --- CA PUBLIC key (contents of ~/.ssh/claude_ca.pub). Public half only. ---
$ClaudeCaPubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJf+AdZ1VT9phXrJBY0HjeuCo5INyR6BmAZglnGCSwPF claude-ssh-ca"

if ($ClaudeCaPubkey -notmatch '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-\S+) [A-Za-z0-9+/=]{40,}') {
    Write-Error "`$ClaudeCaPubkey does not look like an SSH public key. Paste the contents of ~/.ssh/claude_ca.pub."
    exit 1
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Must run this in an elevated (Run as administrator) PowerShell session."
    exit 1
}

if ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 2) {
    Write-Error "This is a domain controller. Use setup-claude-access-windows-dc.ps1 instead."
    exit 1
}

Write-Host "==> Enrolling $($env:COMPUTERNAME) as alias '$Alias' (principal claude-$Alias)"

# 1. OpenSSH Server: Windows capability first, GitHub MSI as fallback.
function Find-Sshd {
    $cmd = Get-Command sshd.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    @("$env:windir\System32\OpenSSH\sshd.exe",
      "$env:ProgramFiles\OpenSSH\sshd.exe",
      "$env:ProgramFiles\OpenSSH-Win64\sshd.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
}

if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
    $installed = $false
    try {
        $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' |
               Where-Object { $_.Name -like 'OpenSSH.Server*' } | Select-Object -First 1
        if ($cap) {
            Write-Host "Installing OpenSSH Server capability (can take a few minutes)..."
            Add-WindowsCapability -Online -Name $cap.Name | Out-Null
            $installed = [bool](Get-Service sshd -ErrorAction SilentlyContinue)
        }
    } catch {
        Write-Warning "Add-WindowsCapability failed: $($_.Exception.Message)"
    }

    if (-not $installed) {
        Write-Host "Falling back to the Win32-OpenSSH MSI from GitHub..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $rel = Invoke-RestMethod -UseBasicParsing `
            -Uri 'https://api.github.com/repos/PowerShell/Win32-OpenSSH/releases/latest' `
            -Headers @{ 'User-Agent' = 'claude-fleet-enroll' }
        $asset = $rel.assets | Where-Object { $_.name -match '^OpenSSH-Win64.*\.msi$' } | Select-Object -First 1
        if (-not $asset) { Write-Error "No Win64 MSI found in release $($rel.tag_name)."; exit 1 }
        $msi = Join-Path $env:TEMP $asset.name
        Write-Host "Downloading $($asset.name) ($($rel.tag_name))..."
        Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile $msi
        $sig = Get-AuthenticodeSignature $msi
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') {
            Write-Error "MSI signature check failed ($($sig.Status), $($sig.SignerCertificate.Subject))."
            exit 1
        }
        $p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" ADDLOCAL=Server /qn /norestart" -Wait -PassThru
        if ($p.ExitCode -notin 0, 3010) { Write-Error "MSI install failed, exit $($p.ExitCode)."; exit 1 }
        Remove-Item $msi -Force -ErrorAction SilentlyContinue
    }
}

if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
    Write-Error "sshd service still missing after install attempts."
    exit 1
}

# Start once so Windows generates host keys and the stock sshd_config.
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
Start-Sleep -Seconds 2

$sshdPath = Find-Sshd
if (-not $sshdPath) { Write-Error "sshd.exe not found after install."; exit 1 }

$sshDataDir     = "$env:ProgramData\ssh"
$sshdConfigPath = "$sshDataDir\sshd_config"
if (-not (Test-Path $sshdConfigPath)) {
    Write-Error "sshd_config not found at $sshdConfigPath - sshd never started cleanly."
    exit 1
}
Write-Host "Using sshd: $sshdPath"

# 2. Local 'claude' account. Random password, never used or recorded -
#    step 6 restricts this account to certificate auth only.
# New-LocalUser caps -Description at 48 chars.
$desc = "Claude cert SSH: claude-$Alias"
if ($desc.Length -gt 48) { $desc = $desc.Substring(0, 48) }
if (-not (Get-LocalUser -Name 'claude' -ErrorAction SilentlyContinue)) {
    $pw  = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
    $pw += (33, 35, 36, 37, 42 | Get-Random | ForEach-Object { [char]$_ })
    New-LocalUser -Name 'claude' `
        -Password (ConvertTo-SecureString $pw -AsPlainText -Force) `
        -FullName 'Claude Code fleet access' `
        -Description $desc `
        -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
    Remove-Variable pw
    Write-Host "Created local user 'claude'"
} else {
    Enable-LocalUser -Name 'claude'
    Write-Host "Local user 'claude' already exists (ensured enabled)"
}

# 3. Local Administrators (by SID, language-independent).
$adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
try {
    Add-LocalGroupMember -Group $adminGroup -Member 'claude'
    Write-Host "Added 'claude' to $($adminGroup.Name)"
} catch [Microsoft.PowerShell.Commands.MemberExistsException] {
    Write-Host "'claude' already in $($adminGroup.Name)"
}

# 4. Hide 'claude' from the sign-in screen.
$ul = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
New-Item -Path $ul -Force | Out-Null
New-ItemProperty -Path $ul -Name 'claude' -Value 0 -PropertyType DWord -Force | Out-Null
Write-Host "Hid 'claude' from the sign-in screen"

# 5. CA trust + principals file. sshd REFUSES files writable by non-admins.
function Set-SshFileAcl([string]$Path) {
    icacls $Path /inheritance:r /grant "*S-1-5-18:(F)" /grant "*S-1-5-32-544:(F)" | Out-Null
}

$caPath = "$sshDataDir\claude_user_ca.pub"
Set-Content -Path $caPath -Value $ClaudeCaPubkey -Encoding ascii
Set-SshFileAcl $caPath

$principalsDir = "$sshDataDir\auth_principals"
New-Item -ItemType Directory -Force -Path $principalsDir | Out-Null
$principalsFile = "$principalsDir\claude"
Set-Content -Path $principalsFile -Value "claude-$Alias" -Encoding ascii
Set-SshFileAcl $principalsDir
Set-SshFileAcl $principalsFile
Write-Host "Principal 'claude-$Alias' written to $principalsFile"

# 6. sshd_config block. Idempotent via markers. Opens with 'Match all' to
#    escape the stock 'Match Group administrators' block that has no reset.
$beginMark = '# BEGIN claude-ca'
$endMark   = '# END claude-ca'
$block = @"
$beginMark
# Managed by setup-claude-access-workstation.ps1 - do not hand-edit.
Match all
TrustedUserCAKeys __PROGRAMDATA__/ssh/claude_user_ca.pub
AuthorizedPrincipalsFile __PROGRAMDATA__/ssh/auth_principals/%u

Match User claude
    PubkeyAuthentication yes
    PasswordAuthentication no
    AuthenticationMethods publickey
$endMark
"@

$backup = "$sshdConfigPath.bak-$(Get-Date -f yyyyMMdd-HHmmss)"
Copy-Item $sshdConfigPath $backup -Force
$existing = Get-Content $sshdConfigPath -Raw
if ($existing -match [regex]::Escape($beginMark)) {
    $pattern  = "(?s)" + [regex]::Escape($beginMark) + ".*?" + [regex]::Escape($endMark)
    $existing = [regex]::Replace($existing, $pattern, [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $block })
    Set-Content -Path $sshdConfigPath -Value $existing -Encoding ascii
    Write-Host "Replaced existing claude-ca block"
} else {
    Add-Content -Path $sshdConfigPath -Value "`r`n$block`r`n" -Encoding ascii
    Write-Host "Appended claude-ca block"
}

# 7. PowerShell as the default SSH shell (stock default is cmd.exe).
New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
    -Value "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -PropertyType String -Force | Out-Null

# 8. Firewall: own rule, all profiles (workstations are often 'Public').
if (Get-NetFirewallRule -Name 'Claude-SSH-In' -ErrorAction SilentlyContinue) {
    Set-NetFirewallRule -Name 'Claude-SSH-In' -Enabled True -Profile Any
} else {
    New-NetFirewallRule -Name 'Claude-SSH-In' -DisplayName 'Claude SSH (sshd tcp/22)' `
        -Enabled True -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Profile Any | Out-Null
    Write-Host "Created firewall rule Claude-SSH-In (tcp/22, all profiles)"
}

# 9. Optional: stay reachable on AC power.
if ($KeepAwake) {
    powercfg /change standby-timeout-ac 0
    powercfg /change hibernate-timeout-ac 0
    Write-Host "Sleep/hibernate on AC disabled"
}

# 10. Validate BEFORE restarting - a bad config leaves sshd dead.
Write-Host "==> Validating sshd config..."
& $sshdPath -T -f $sshdConfigPath > $null
if ($LASTEXITCODE -ne 0) {
    Copy-Item $backup $sshdConfigPath -Force
    Write-Error "sshd config validation FAILED - restored $backup. Nothing restarted."
    exit 1
}
Restart-Service sshd
Start-Sleep -Seconds 1
Write-Host "==> sshd restarted. Config validated."

# 11. GPO check: security baselines often deny network logon to local admins,
#     which blocks SSH for a local account with no obvious error.
$inf = Join-Path $env:TEMP 'claude-secpol.inf'
secedit /export /areas USER_RIGHTS /cfg $inf | Out-Null
$deny = (Select-String -Path $inf -Pattern '^SeDenyNetworkLogonRight' -ErrorAction SilentlyContinue).Line
Remove-Item $inf -Force -ErrorAction SilentlyContinue
if ($deny -match 'S-1-5-113|S-1-5-114') {
    Write-Warning "A policy DENIES network logon to local (admin) accounts: $deny"
    Write-Warning "SSH as 'claude' will be refused until that GPO/local policy is relaxed for this host."
}

# 12. Summary for the fleet config.
$svc  = Get-Service sshd
$port = (Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1)
$nics = Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
        ForEach-Object {
            $a = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
            "{0,-16} {1,-18} {2}" -f $_.IPAddress, $a.MacAddress, $_.InterfaceAlias
        }

Write-Host ""
Write-Host "================ SUMMARY ================" -ForegroundColor Green
Write-Host "Computer : $($env:COMPUTERNAME)"
Write-Host "Alias    : $Alias   (principal claude-$Alias)"
Write-Host "OS       : $((Get-CimInstance Win32_OperatingSystem).Caption)"
Write-Host "Domain   : $((Get-CimInstance Win32_ComputerSystem).Domain)"
Write-Host "sshd     : $($svc.Status) / $($svc.StartType)   listening on 22: $([bool]$port)"
Write-Host "IPv4     :"
$nics | ForEach-Object { Write-Host "  $_" }
Write-Host "=========================================" -ForegroundColor Green
Write-Host "Send this summary back to Claude."
