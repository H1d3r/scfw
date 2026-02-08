#
# fetch-winsdk.ps1 — Download Windows SDK + CRT headers/libs via xwin.
#
# Uses an isolated CARGO_HOME/RUSTUP_HOME so nothing is left behind
# except the output directory containing crt/ and sdk/.
#

param(
    [string] $Output = ".\winsdk",
    [switch] $Force,
    [switch] $Isolated,
    [switch] $Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------- help ----------

if ($Help) {
    Write-Host @"
Usage: fetch-winsdk.ps1 [OPTIONS]

Download Windows SDK and CRT headers/libs via xwin.

Options:
  -Output DIR   Output directory (default: .\winsdk)
  -Force        Re-download even if output directory already exists
  -Isolated     Always download fresh Rust, ignore system Rust
  -Help         Show this help
"@
    exit 0
}

# ---------- helpers ----------

$Script:IsWin = ((Test-Path variable:IsWindows) -and $IsWindows) -or ($env:OS -eq "Windows_NT")
$Script:PathSep = if ($Script:IsWin) { ";" } else { ":" }

function Invoke-NativeCommand {
    param([string] $Description)

    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed (exit code $LASTEXITCODE)"
    }
}

# ---------- skip if already downloaded ----------

if (-not $Force -and (Test-Path (Join-Path $Output "crt")) -and (Test-Path (Join-Path $Output "sdk"))) {
    Write-Host "Windows SDK already present in $Output (use -Force to re-download)"
    exit 0
}

# ---------- temp dir with cleanup ----------

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "fetch-winsdk.$([System.IO.Path]::GetRandomFileName())"
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null
Write-Host "Temp directory: $TmpDir"

try {
    # ---------- find or install xwin ----------

    $XwinPath = $null

    # 1) Check for existing xwin on PATH
    if (-not $Isolated) {
        $Found = Get-Command xwin -ErrorAction SilentlyContinue
        if ($Found) {
            $XwinPath = $Found.Source
            Write-Host "Using system xwin: $XwinPath"
        }
    }

    # 2) Fall back to cargo install
    if (-not $XwinPath) {
        $XwinRoot = Join-Path $TmpDir "xwin-install"
        New-Item -ItemType Directory -Path $XwinRoot -Force | Out-Null

        $HasCargo = $false
        if (-not $Isolated) {
            $Found = Get-Command cargo -ErrorAction SilentlyContinue
            if ($Found) {
                Write-Host "Using system cargo: $($Found.Source)"
                $HasCargo = $true
            }
        }

        if (-not $HasCargo) {
            Write-Host "Downloading Rust toolchain into temp directory..."
            $env:CARGO_HOME = Join-Path $TmpDir "cargo"
            $env:RUSTUP_HOME = Join-Path $TmpDir "rustup"
            New-Item -ItemType Directory -Path $env:CARGO_HOME -Force | Out-Null
            New-Item -ItemType Directory -Path $env:RUSTUP_HOME -Force | Out-Null

            if ($Script:IsWin) {
                $RustupInit = Join-Path $TmpDir "rustup-init.exe"
                Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $RustupInit
                & $RustupInit -y --no-modify-path --default-toolchain stable --profile minimal
                Invoke-NativeCommand "rustup-init"
            } else {
                $RustupScript = Join-Path $TmpDir "rustup.sh"
                Invoke-WebRequest -Uri "https://sh.rustup.rs" -OutFile $RustupScript
                & bash $RustupScript -y --no-modify-path --default-toolchain stable --profile minimal
                Invoke-NativeCommand "rustup install"
            }

            $env:PATH = "$(Join-Path $env:CARGO_HOME 'bin')$($Script:PathSep)$env:PATH"
        }

        Write-Host "Using cargo: $((Get-Command cargo).Source)"
        & cargo --version
        Invoke-NativeCommand "cargo"

        Write-Host "Installing xwin..."
        & cargo install xwin --root $XwinRoot
        Invoke-NativeCommand "cargo install xwin"

        $XwinBin = if ($Script:IsWin) { "xwin.exe" } else { "xwin" }
        $XwinPath = Join-Path (Join-Path $XwinRoot "bin") $XwinBin
    }

    # ---------- run xwin ----------

    if ($Force -and (Test-Path $Output)) {
        Write-Host "Removing existing $Output..."
        Remove-Item -Recurse -Force $Output
    }

    New-Item -ItemType Directory -Path $Output -Force | Out-Null
    $Output = (Resolve-Path $Output).Path

    Write-Host "Fetching Windows SDK + CRT into $Output..."
    $XwinCache = Join-Path $TmpDir "xwin-cache"
    & $XwinPath --accept-license --arch x86,x86_64 --cache-dir $XwinCache splat --copy --output $Output
    Invoke-NativeCommand "xwin splat"

    Write-Host "Done. Windows SDK available at $Output"

} finally {
    Write-Host "Cleaning up temp directory..."
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
}
