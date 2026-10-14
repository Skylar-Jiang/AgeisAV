param(
    [Parameter(Mandatory)] [string] $PublicKeyPath,
    [Parameter(Mandatory)] [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'
$publicKey = (Get-Content -LiteralPath $PublicKeyPath -Raw).Trim()
if ($publicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/=]+(?: .*)?$') {
    throw 'Expected an Ed25519 SSH public key.'
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$userData = Join-Path $OutputDirectory 'user-data'
$metaData = Join-Path $OutputDirectory 'meta-data'
$seedIso = Join-Path $OutputDirectory 'aegisav-seed.iso'
if (Test-Path -LiteralPath $seedIso) { throw "Seed ISO already exists: $seedIso" }

$cloudConfig = @'
#cloud-config
hostname: aegisav-static
manage_etc_hosts: true
ssh_pwauth: false
disable_root: true
ssh_authorized_keys:
  - __PUBLIC_KEY__
package_update: true
package_upgrade: true
packages:
  - openssh-server
  - open-vm-tools
  - clamav
  - clamav-daemon
  - clamav-freshclam
  - python3-venv
  - python3-pip
  - git
write_files:
  - path: /etc/apt/apt.conf.d/99aegisav-no-recommends
    permissions: '0644'
    content: |
      APT::Install-Recommends "false";
  - path: /etc/ssh/sshd_config.d/60-aegisav.conf
    permissions: '0644'
    content: |
      PasswordAuthentication no
      PermitRootLogin no
      AllowUsers ubuntu
runcmd:
  - [systemctl, enable, --now, ssh]
  - [systemctl, enable, --now, open-vm-tools]
  - [systemctl, enable, --now, clamav-freshclam]
'@.Replace('__PUBLIC_KEY__', $publicKey)
[IO.File]::WriteAllText($userData, $cloudConfig + "`n", [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($metaData, "instance-id: aegisav-static-20260928`nlocal-hostname: aegisav-static`n", [Text.UTF8Encoding]::new($false))

$linuxPaths = @($seedIso, $userData, $metaData) | ForEach-Object {
    $absolute = [IO.Path]::GetFullPath($_)
    if ($absolute -notmatch '^([A-Za-z]):\\(.*)$') { throw "Expected a local drive path: $_" }
    '/mnt/' + $Matches[1].ToLowerInvariant() + '/' + $Matches[2].Replace('\', '/')
}
& wsl.exe -d Ubuntu-22.04 -- cloud-localds $linuxPaths[0] $linuxPaths[1] $linuxPaths[2]
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $seedIso)) { throw 'cloud-localds failed' }
Get-FileHash -LiteralPath $seedIso -Algorithm SHA256 | Select-Object Path, Hash
