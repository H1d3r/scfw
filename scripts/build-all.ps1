$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$BinDir = Join-Path $ProjectDir "bin"

# Clean output directory
if (Test-Path $BinDir) { Remove-Item -Recurse -Force $BinDir }
New-Item -ItemType Directory -Path "$BinDir\x86" -Force | Out-Null
New-Item -ItemType Directory -Path "$BinDir\x64" -Force | Out-Null

foreach ($arch in "x86", "x64") {
    Write-Host "=== Building $arch ==="

    $BuildDir = Join-Path $ProjectDir "build-$arch"
    if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }

    cmake --preset $arch -S $ProjectDir
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    cmake --build $BuildDir
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    # Copy scrun
    Copy-Item "$BuildDir\tools\scrun.exe" "$BinDir\$arch\scrun.exe"
    Write-Host "  $arch/scrun.exe"

    # Copy all .bin files
    Get-ChildItem -Path "$BuildDir\examples\*\*.bin" | ForEach-Object {
        Copy-Item $_.FullName "$BinDir\$arch\$($_.Name)"
        $size = $_.Length
        Write-Host "  $arch/$($_.Name) ($size bytes)"
    }

    Write-Host ""
}

Write-Host "Done. Output in $BinDir\"
