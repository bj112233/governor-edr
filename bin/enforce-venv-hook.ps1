# PreToolUse hook (matcher: exec) — blocks Python invocations that bypass the project venv.
# Reads Claude-format hook JSON on stdin: { "tool_name": "exec", "tool_input": { "command": "..." } }
# Exit 2 = block (Devin/Claude hook convention). stdout JSON optional.
#
# Allowed:  .venv\Scripts\python.exe ...   |   .\.venv\Scripts\python.exe ...
# Blocked:  py -3 | py -3.14 | python | python.exe   (when NOT routed through .venv\Scripts\)
$ErrorActionPreference = 'Stop'
$raw = [Console]::In.ReadToEnd()
$cmd = ''
try {
    $data = $raw | ConvertFrom-Json
    $cmd = [string]$data.tool_input.command
} catch {
    # Malformed stdin — allow (don't break unrelated exec calls).
    exit 0
}
if (-not $cmd) { exit 0 }

# Normalize for matching.
$c = $cmd.Trim()

# Skip non-python commands entirely.
$isPython = ($c -match '(?i)(^|[\s&|;`(])py(\s|$|-3)' -or
             $c -match '(?i)(^|[\s&|;`(])python(\.exe)?(\s|$)')
if (-not $isPython) { exit 0 }

# Allow if the command explicitly uses the project venv interpreter.
if ($c -match '(?i)(\./|\.\\|/|\\)?\.venv\\Scripts\\python\.exe') { exit 0 }
# Allow venv activation scripts.
if ($c -match '(?i)(\./|\.\\)?\.venv\\Scripts\\(Activate|activate)') { exit 0 }
# Allow pip installs targeting the venv.
if ($c -match '(?i)\.venv\\Scripts\\(pip|python)\.exe') { exit 0 }

# Block everything else that looks like a bare/system python launch.
$reason = "BLOCKED by enforce-venv-hook: this project requires the venv interpreter. " +
          "Use: .\.venv\Scripts\python.exe -m pytest / .\.venv\Scripts\python.exe bin\lint-gate.py " +
          "or run .\.venv\Scripts\Activate.ps1 first. Never use bare 'python', 'python.exe', or 'py -3'."
$obj = [PSCustomObject]@{ decision = 'block'; reason = $reason }
$obj | ConvertTo-Json -Compress | Write-Output
exit 2
