@echo off
rem ============================================================================
rem  Condor booth PC: one-time enrollment for Claude's SSH access.
rem  Double-click it and click Yes on the admin prompt. Safe to run again.
rem    1. Turns on SSH, creates the hidden admin account "claude" (certificate-only login,
rem       no usable password), keeps the PC awake on AC power. Alias: cs-booth-01
rem    2. Limits SSH (port 22) to NetBird addresses only, so nobody on the venue Wi-Fi can reach it.
rem  Then install NetBird and sign in. Claude takes it from there.
rem ============================================================================
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
  exit /b
)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-claude-access-workstation.ps1" -Alias cs-booth-01 -KeepAwake
if errorlevel 1 (
  echo.
  echo ENROLLMENT FAILED - send Claude a photo or copy of the red text above.
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-NetFirewallRule -Name 'Claude-SSH-In' -RemoteAddress '100.64.0.0/10'; Write-Host ('SSH allowed only from: ' + ((Get-NetFirewallRule -Name 'Claude-SSH-In' | Get-NetFirewallAddressFilter).RemoteAddress -join ', ')) -ForegroundColor Green"
echo.
echo Done. Next: install NetBird and sign in, then tell Claude.
pause
