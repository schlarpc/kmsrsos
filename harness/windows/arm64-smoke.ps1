# Start the shipped ARM64 binary on a real ARM64 Windows machine and watch it
# serve (`PKG-022`, #385).
#
# # Why this exists
#
# `PKG-020` (#379) added an `aarch64-pc-windows-msvc` build that was checked the
# way the x86_64 one is checked *at build time* — the PE machine type is read
# off the artifact and Control Flow Guard is asserted absent — and that had
# never been executed. `PKG-018` (#374) is the precedent for why that is not
# enough: Control Flow Guard produced an artifact whose `DllCharacteristics` bit
# was honestly set and which died at start-up with
# `FAST_FAIL_GUARD_ICALL_CHECK_FAILURE` before logging a line. Every check
# passed. Nothing caught it until somebody ran it.
#
# So this runs it, and the two things it is really asking are:
#
#   1. does the process start and serve an activation, and
#   2. which of the five `SetProcessMitigationPolicy` policies does *this*
#      kernel accept? `SEC-019` (#356) verified five on Windows 11 26200 on
#      x86_64 and nowhere else, and `ProcessSystemCallDisablePolicy` is the one
#      to watch: it removes the `win32k.sys` surface, and `win32k` on ARM64 is a
#      different build of a driver with its own history of what is filterable.
#
# # What it runs, and what it deliberately does not
#
# The **cross-compiled artifact**, not a build made here. That is the whole
# point of #385: the binary an operator downloads is the one that has to start,
# and a binary rebuilt natively on the test machine is a different binary. The
# `platforms` matrix in `test.yml` builds and tests natively on this same
# runner, which is a different question and is asked separately.
#
# Usage, from the repository root:
#
#     pwsh harness/windows/arm64-smoke.ps1 `
#         -Server out/kmsrs-server-windows-aarch64.exe `
#         -Client out/kmsrs-client-windows-aarch64.exe
[CmdletBinding()]
param(
    # The server under test.
    [Parameter(Mandatory = $true)][string] $Server,
    # The diagnostic client, from the same build, which is what turns "the
    # process is running" into "the process served an activation".
    [Parameter(Mandatory = $true)][string] $Client,
    # Where the captured start-up report is written.
    [string] $Report = 'arm64-smoke-report.txt',
    # What the process-mitigation line is expected to say. Asserted rather than
    # merely printed, so that the day this stops being true a job fails instead
    # of a log line changing where nobody is reading.
    [ValidateSet('applied', 'refused by the kernel', 'not available on this target')]
    [string] $ExpectMitigations = 'applied'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Fail([string] $message) {
    Write-Host "FAIL: $message" -ForegroundColor Red
    exit 1
}

# --- 1. This has to be a real ARM64 machine ------------------------------
#
# The first thing to establish, because everything below is worthless without
# it and would pass perfectly on an x86 runner emulating one. #385 rejected
# emulation for exactly this reason: a mitigation applied inside an emulator
# answers a question about the emulator.
$hostArch = $env:PROCESSOR_ARCHITECTURE
if ($hostArch -ne 'ARM64') {
    Fail "this must run on ARM64 Windows; PROCESSOR_ARCHITECTURE is '$hostArch'"
}
Write-Host "host: $hostArch, $((Get-CimInstance Win32_OperatingSystem).Caption) build $([System.Environment]::OSVersion.Version.Build)"

# --- 2. And the binary has to be the ARM64 one ---------------------------
#
# Read off the file rather than trusted from its name. The PE machine type
# lives two bytes after the `PE\0\0` signature, which is at the offset stored
# at 0x3C. 0xAA64 is `IMAGE_FILE_MACHINE_ARM64`.
function Get-PeMachine([string] $path) {
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $peOffset = [System.BitConverter]::ToInt32($bytes, 0x3C)
    return [System.BitConverter]::ToUInt16($bytes, $peOffset + 4)
}

foreach ($binary in @($Server, $Client)) {
    if (-not (Test-Path $binary)) { Fail "no such file: $binary" }
    $machine = Get-PeMachine (Resolve-Path $binary)
    if ($machine -ne 0xAA64) {
        Fail ("{0} is machine 0x{1:X4}, not 0xAA64 (ARM64)" -f $binary, $machine)
    }
}
Write-Host "both binaries are IMAGE_FILE_MACHINE_ARM64"

# --- 3. Start it, and capture everything it says -------------------------
#
# `log-level = "debug"` because the sandbox lines are debug ones: a mitigation
# that was applied is not news at `info`, and here it is the entire point.
# JSON because this script then reads them, and a format somebody parses should
# be one somebody wrote deliberately.
$log = Join-Path (Get-Location) 'arm64-smoke-server.log'
if (Test-Path $log) { Remove-Item $log }
$env:KMSRSOS_CONFIG = "log-level = `"debug`"`nlog-format = `"json`""

$process = Start-Process -FilePath (Resolve-Path $Server) -PassThru `
    -RedirectStandardError $log -RedirectStandardOutput 'arm64-smoke-stdout.log' `
    -WindowStyle Hidden

try {
    # Wait for the port rather than for a log line: what the next step needs is
    # a listener, and a host that logged `listening` and then failed to bind
    # would hang here rather than reporting a confusing client error.
    $deadline = (Get-Date).AddSeconds(30)
    $up = $false
    while ((Get-Date) -lt $deadline) {
        if ($process.HasExited) {
            Write-Host (Get-Content $log -Raw)
            Fail "the server exited at start-up with code $($process.ExitCode). That is the PKG-018 (#374) failure: every build-time check passed and the process did not run"
        }
        try {
            $probe = New-Object System.Net.Sockets.TcpClient
            $probe.Connect('127.0.0.1', 1688)
            $probe.Close()
            $up = $true
            break
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if (-not $up) { Fail 'the server never accepted a connection on 1688' }

    # --- 4. Serve an activation ------------------------------------------
    #
    # `--healthcheck` is one activation and an exit code, which is exactly the
    # question here. The detection-resistance suite is a different and much
    # longer run, and it is not what #385 asks for.
    & (Resolve-Path $Client) --healthcheck 127.0.0.1:1688
    if ($LASTEXITCODE -ne 0) {
        Write-Host (Get-Content $log -Raw)
        Fail "the client could not activate against it (exit $LASTEXITCODE)"
    }
    Write-Host 'served an activation'
} finally {
    if (-not $process.HasExited) {
        $process.Kill()
        $process.WaitForExit(10000) | Out-Null
    }
}

# --- 5. What the kernel accepted -----------------------------------------
$lines = Get-Content $log
$sandbox = $lines | Where-Object { $_ -match '"event":"sandbox"' }
if (-not $sandbox) {
    Write-Host (Get-Content $log -Raw)
    Fail 'the server logged no sandbox report at all'
}

$mitigations = $null
foreach ($line in $sandbox) {
    if ($line -match '"detail":"process-mitigations: ([^"]*)"') {
        $mitigations = $Matches[1]
    }
}
if ($null -eq $mitigations) { Fail 'the sandbox report has no process-mitigations line' }

$summary = @(
    "host                 : $hostArch, build $([System.Environment]::OSVersion.Version.Build)",
    "binary               : $Server",
    'started              : yes',
    'served an activation : yes'
) + ($sandbox | ForEach-Object {
    if ($_ -match '"detail":"([^"]*)"') { "sandbox              : $($Matches[1])" }
})
$summary | Tee-Object -FilePath $Report

# The assertion, last, so the report is captured either way. A refusal is not a
# crash — `apply()` reports `Failed` and the process goes on serving, which is
# the property that made shipping the untested binary defensible in the first
# place — but it is a different security posture on this architecture than on
# the other, and `docs/decisions.md` has to say so per architecture rather than
# once.
if ($mitigations -ne $ExpectMitigations) {
    Fail "process mitigations reported '$mitigations', expected '$ExpectMitigations'. If this ARM64 kernel genuinely refuses one of the five, record which in docs/decisions.md and change -ExpectMitigations; do not delete the assertion (PKG-022, #385)"
}
Write-Host "process mitigations: $mitigations" -ForegroundColor Green
