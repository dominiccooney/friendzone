# Fetches the CI-built Linux guest binary into the broker's guest-bin/
# so a Windows host can bootstrap Linux VMs. Requires gh (authenticated)
# and a completed "guest-binary" workflow run on GitHub.
$ErrorActionPreference = "Stop"
$guestBin = Join-Path $env:LOCALAPPDATA "friendzone\guest-bin"
New-Item -ItemType Directory -Force -Path $guestBin | Out-Null
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "fz-guest-dl-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
    gh run download --repo dominiccooney/friendzone --name fz-linux-x86_64 --dir $tmp
    Move-Item -Force (Join-Path $tmp "fz-linux-x86_64") (Join-Path $guestBin "fz-linux-x86_64")
    Write-Host "Installed $guestBin\fz-linux-x86_64"
    Write-Host "Restart the broker; guests fetch it from /bootstrap/fz/fz-linux-x86_64"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
