# install_nmap_host.ps1
#
# Installs nmap on the Windows host so `uv run kryon engage` can perform
# port discovery when running natively (not via the Kryon Docker container).
#
# Background: Kryon's `engage` orchestrator calls nmap for Phase 1 service
# discovery. When the Kryon container runs inside Docker Desktop on Windows,
# it does not inherit the host's VPN routes (no mirror networking). The
# workaround is to run `uv run kryon engage` directly from the host, where
# the VPN to the client network is already active — but the host needs nmap.
#
# Requires admin. Run in elevated PowerShell:
#   pwsh -ExecutionPolicy Bypass -File scripts/install_nmap_host.ps1
#
# OR right-click PowerShell > Run as Administrator, then:
#   .\scripts\install_nmap_host.ps1

#Requires -RunAsAdministrator

Write-Host "==> Installing nmap via winget (Insecure.Nmap)..." -ForegroundColor Cyan

# Use --silent so the installer does not prompt during scripted runs.
$result = winget install --id Insecure.Nmap `
    --silent `
    --accept-source-agreements `
    --accept-package-agreements `
    --disable-interactivity 2>&1

Write-Host $result
Write-Host ""

# Refresh PATH for current session (winget updates Machine PATH but not the
# current process). The next shell will have it naturally.
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + `
            [System.Environment]::GetEnvironmentVariable("Path", "User")

Write-Host "==> Verifying installation..." -ForegroundColor Cyan
$nmapPath = Get-Command nmap -ErrorAction SilentlyContinue
if ($nmapPath) {
    Write-Host "  nmap found at: $($nmapPath.Source)" -ForegroundColor Green
    & nmap --version | Select-Object -First 2
    Write-Host ""
    Write-Host "==> Done. Open a new PowerShell/Bash session for the PATH to take effect," -ForegroundColor Green
    Write-Host "    then run:" -ForegroundColor Green
    Write-Host "       bash scripts/audit_britimp.sh" -ForegroundColor Yellow
} else {
    Write-Host "  ERROR: nmap not in PATH after install." -ForegroundColor Red
    Write-Host "  Try logging out and back in, then re-run nmap --version." -ForegroundColor Red
    exit 1
}
