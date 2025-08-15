<#
.SYNOPSIS
  Open or remove a Windows port-proxy to a WSL2 distro so services in WSL are reachable from Windows/LAN.

.DESCRIPTION
  - Listens on 0.0.0.0:<Port> (all IPv4 interfaces on Windows) and forwards to <WSL IPv4>:<Port>.
  - Optionally also listens on :::<Port> (IPv6) and forwards to the same WSL IPv4.
  - Adds an inbound Windows Firewall rule (Private,Domain) unless -NoFirewall is set.
  - Useful for exposing services like OpenWebUI at http://<Windows_LAN_IP>:<Port> to your LAN.

.PARAMETER Action
  add      -> create/update proxy & firewall rule
  refresh  -> same as add (forces a fresh WSL IP lookup; safe after 'wsl --shutdown')
  remove   -> delete proxy & firewall rule
  show     -> display current portproxy entries

.PARAMETER Port
  TCP port to expose (default 3000).

.PARAMETER Distro
  WSL distribution name (default 'Ubuntu'). Use 'wsl -l -v' to see names.

.PARAMETER IPv6
  Also create an IPv6 -> IPv4 proxy (listen on '::').

.PARAMETER Profiles
  Windows Firewall profiles to allow (default: Private,Domain).

.PARAMETER NoFirewall
  Skip firewall rule changes.

.EXAMPLE
  .\wsl-open-port.ps1 -Action add -Port 3000 -Distro "Ubuntu" -IPv6

.EXAMPLE
  .\wsl-open-port.ps1 -Action refresh -Port 3000 -Distro "Ubuntu"

.EXAMPLE
  .\wsl-open-port.ps1 -Action remove -Port 3000
#>

[CmdletBinding(SupportsShouldProcess)]
param(
  [ValidateSet('add','refresh','remove','show')]
  [string]$Action = 'add',

  [int]$Port = 3000,

  [string]$Distro = 'Ubuntu',

  [switch]$IPv6,

  [string[]]$Profiles = @('Private','Domain'),

  [switch]$NoFirewall
)

function Confirm-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must be run in an elevated PowerShell (Run as Administrator)."
  }
}

function Get-WSLIPv4([string]$DistroName) {
  # Try hostname -I first
  $raw = (wsl.exe -d $DistroName hostname -I) 2>$null
  $ip  = ($raw -split '\s+' | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1)
  if (-not $ip) {
    # Fallback: parse ip addr show eth0
    $raw2 = (wsl.exe -d $DistroName ip -4 addr show eth0) 2>$null
    $ip   = ($raw2 -split '\s+' | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$' } | ForEach-Object { $_ -replace '/\d{1,2}$','' } | Select-Object -First 1)
  }
  if (-not $ip) { throw "Unable to determine WSL IPv4 address for distro '$DistroName'." }
  return $ip.Trim()
}

function Remove-Proxy([int]$P, [switch]$DoIPv6) {
  & netsh interface portproxy delete v4tov4 listenport=$P listenaddress=127.0.0.1  | Out-Null
  & netsh interface portproxy delete v4tov4 listenport=$P listenaddress=0.0.0.0    | Out-Null
  if ($DoIPv6) {
    & netsh interface portproxy delete v6tov4 listenport=$P listenaddress=::       | Out-Null
  }
}

function Add-Proxy([int]$P, [string]$TargetIPv4, [switch]$DoIPv6) {
  & netsh interface portproxy add v4tov4 listenport=$P listenaddress=0.0.0.0 connectport=$P connectaddress=$TargetIPv4 | Out-Null
  if ($DoIPv6) {
    & netsh interface portproxy add v6tov4 listenport=$P listenaddress=:: connectport=$P connectaddress=$TargetIPv4    | Out-Null
  }
}

function Ensure-FirewallRule([int]$P, [string[]]$Profiles) {
  $name = "WSL PortProxy $P"
  # Remove existing rule(s) with the same name to keep idempotency
  & netsh advfirewall firewall delete rule name="$name" | Out-Null
  if (-not $NoFirewall) {
    $profilesCsv = ($Profiles -join ',').ToLower()
    & netsh advfirewall firewall add rule name="$name" dir=in action=allow protocol=TCP localport=$P profile=$profilesCsv | Out-Null
  }
}

function Show-Proxy([int]$P) {
  Write-Host "`n[v4tov4]"
  & netsh interface portproxy show v4tov4
  Write-Host "`n[v6tov4]"
  & netsh interface portproxy show v6tov4
  Write-Host ""
}

try {
  Confirm-Admin

  switch ($Action) {
    'show'    { Show-Proxy -P $Port; break }

    'remove'  {
      Remove-Proxy -P $Port -DoIPv6:$IPv6
      if (-not $NoFirewall) {
        & netsh advfirewall firewall delete rule name="WSL PortProxy $Port" | Out-Null
      }
      Write-Host "Removed portproxy and firewall rule for port $Port."
    }

    'add'     {
      $ip = Get-WSLIPv4 -DistroName $Distro
      Remove-Proxy -P $Port -DoIPv6:$IPv6
      Add-Proxy -P $Port -TargetIPv4 $ip -DoIPv6:$IPv6
      Ensure-FirewallRule -P $Port -Profiles $Profiles
      Write-Host "Listening on 0.0.0.0:$Port (and :::$Port if -IPv6), forwarding to $ip:$Port (WSL:$Distro)."
    }

    'refresh' {
      $ip = Get-WSLIPv4 -DistroName $Distro
      Remove-Proxy -P $Port -DoIPv6:$IPv6
      Add-Proxy -P $Port -TargetIPv4 $ip -DoIPv6:$IPv6
      Ensure-FirewallRule -P $Port -Profiles $Profiles
      Write-Host "Refreshed: 0.0.0.0:$Port -> $ip:$Port (WSL:$Distro)."
    }
  }

  Show-Proxy -P $Port
  Write-Host "Tip: access from LAN via http://$( (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp | Select -First 1).IPAddress ):$Port"
}
catch {
  Write-Error $_
  exit 1
}
