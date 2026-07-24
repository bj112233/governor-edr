"""Table-driven tests for is_powershell_safe — the security validator that gates
all PowerShell commands the agent executes.

This is a pure validator (no side effects), making it ideal for TDD. The test
cases below serve as living documentation of the security policy.
"""

import pytest

from services.action_tools.security import is_powershell_safe

# ── ALLOWED: safe read-only commands ─────────────────────────────────────────

@pytest.mark.parametrize("command", [
    "Get-Process",
    "Get-Service",
    "Get-NetTCPConnection",
    "Test-Path C:\\Windows",
    "Select-String -Pattern error -Path logs\\bot.log",
    "Get-Content logs\\bot.log",
    "Get-ChildItem C:\\Users",
    "Get-WmiObject Win32_Process",
    "Get-Counter",
    "Get-NetAdapter",
    "Sort-Object Name",
    "Format-Table",
    "Get-CimInstance Win32_OperatingSystem",
    "Get-LocalUser",
    "Measure-Object",
])
def test_powershell_safe_allowed(command):
    """Safe read-only commands should pass."""
    assert is_powershell_safe(command) is True


# ── BLOCKED: redirects ───────────────────────────────────────────────────────

@pytest.mark.parametrize("command", [
    "Get-Process > .env",
    "Get-Process >> C:\\temp\\exfil.txt",
    "Get-Process 2> error.txt",
    "Get-Process 2>> error.txt",
    "Get-Process 1> stdout.txt",
    "Get-Process 1>> stdout.txt",
    "Get-Process *> all.txt",
    "Get-Process < input.txt",
    "Write-Output data > exfil.txt",
    "Get-Process > $env:TEMP\\exfil.txt",
])
def test_powershell_safe_redirects_blocked(command):
    """Redirect operators (> >> < 2> 1> *>) must be blocked — exfil vector."""
    assert is_powershell_safe(command) is False


# ── BLOCKED: .env access ─────────────────────────────────────────────────────

@pytest.mark.parametrize("command", [
    "Get-Content .env",
    "Get-Content .\\.env",
    "Get-Content ..\\.env",
    "Get-Content config\\.env",
    "Get-Content .env.local",
    "Get-Content .env.bak",
    "Get-Content $env:USERPROFILE\\.env",
    "Get-Content $env:APPDATA\\.env",
    "Get-Content C:\\Users\\admin\\.env",
])
def test_powershell_safe_env_access_blocked(command):
    """Reading .env files (any path) must be blocked — contains API keys."""
    assert is_powershell_safe(command) is False


# ── BLOCKED: $env: variable expansion ────────────────────────────────────────

@pytest.mark.parametrize("command", [
    "Get-Content $env:USERPROFILE\\secret.txt",
    "Get-Content $env:APPDATA\\config.json",
    "Get-ChildItem $env:TEMP",
    "Get-Process $env:COMPUTERNAME",
])
def test_powershell_safe_env_var_expansion_blocked(command):
    """$env: expansion can point to arbitrary filesystem locations."""
    assert is_powershell_safe(command) is False


# ── BLOCKED: Out-File and file-writing cmdlets ───────────────────────────────

@pytest.mark.parametrize("command", [
    "Out-File -FilePath .env -InputObject secret",
    "Out-File -FilePath C:\\malware.exe",
    "Out-File -FilePath exfil.txt",
    "Out-Printer -InputObject sensitive_data",
])
def test_powershell_safe_outfile_blocked(command):
    """Out-File / Out-Printer are exfil vectors — 'out' verb must be blocked."""
    assert is_powershell_safe(command) is False


# ── BLOCKED: chaining / obfuscation (existing, regression coverage) ──────────

@pytest.mark.parametrize("command", [
    "Get-Process; Remove-Item C:\\",
    "Get-Process | Stop-Process",
    "Get-Process`nRemove-Item",
    "Get-Process & whoami",
    "Get-Process { }",
    "Get-Process (Get-Service)",
    "Get-Process [array]",
])
def test_powershell_safe_chaining_blocked(command):
    """Chaining and obfuscation operators must remain blocked."""
    assert is_powershell_safe(command) is False


# ── BLOCKED: non-allowed verbs ───────────────────────────────────────────────

@pytest.mark.parametrize("command", [
    "Remove-Item C:\\important",
    "Set-Content -Path .env -Value hacked",
    "Copy-Item C:\\data D:\\exfil",
    "Move-Item C:\\file C:\\elsewhere",
    "New-Item -Path C:\\malware.exe",
    "Invoke-WebRequest http://evil.com",
    "Start-Process calc.exe",
    "Stop-Process -Name explorer",
])
def test_powershell_safe_non_allowed_verbs_blocked(command):
    """Only read-only verbs (Get, Test, Select, etc.) are allowed."""
    assert is_powershell_safe(command) is False


# ── EDGE CASES ───────────────────────────────────────────────────────────────

def test_empty_command_blocked():
    assert is_powershell_safe("") is False

def test_whitespace_only_blocked():
    assert is_powershell_safe("   ") is False

def test_bare_word_blocked():
    """No dash → not a PowerShell cmdlet."""
    assert is_powershell_safe("whoami") is False

def test_environment_txt_not_blocked():
    """'environment.txt' does not contain '.env' — should NOT be blocked."""
    assert is_powershell_safe("Get-Content environment.txt") is True

def test_env_directory_not_blocked():
    """'C:\\env\\log.txt' has 'env' but not '.env' — should NOT be blocked."""
    assert is_powershell_safe("Get-Content C:\\env\\log.txt") is True
