[CmdletBinding()]
param(
    [ValidateSet('offline', 'home', 'validation')][string]$Mode = 'offline',
    [string]$Runtime = '',
    [string]$Go = 'go'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $Runtime) {
    $Runtime = if ($env:NETLAUNCH_WINDOWS_RUNTIME) { $env:NETLAUNCH_WINDOWS_RUNTIME } else { Join-Path $repo '.local\windows-runtime' }
}
$runtimeRoot = (Resolve-Path -LiteralPath $Runtime).Path
if ($env:NETLAUNCH_GO -and -not $PSBoundParameters.ContainsKey('Go')) { $Go = $env:NETLAUNCH_GO }
$goCommand = (Get-Command $Go -ErrorAction Stop).Source
$expectedManifest = Join-Path $PSScriptRoot 'runtime-manifest.windows-amd64.json'
$actualManifest = Join-Path $runtimeRoot 'manifest.json'
# Git may check out CRLF on Windows; only normalize line endings, not JSON values.
$actualText = [IO.File]::ReadAllText($actualManifest).Replace("`r`n", "`n")
$expectedText = [IO.File]::ReadAllText($expectedManifest).Replace("`r`n", "`n")
if ($actualText -cne $expectedText) {
    throw 'Runtime manifest differs from the repository pin.'
}
$notices = @('Go-LICENSE', 'mihomo-LICENSE', 'yaml-LICENSE', 'windows-components.txt', 'openconnect/COPYING.LGPL')
foreach ($name in $notices) {
    if (-not (Test-Path -LiteralPath (Join-Path $runtimeRoot ('notices/' + $name)) -PathType Leaf)) {
        throw 'Runtime release notices are incomplete; use the full distribution runtime, not a frozen run directory.'
    }
}

Push-Location -LiteralPath $repo
$savedGOOS, $savedGOARCH = $env:GOOS, $env:GOARCH
try {
    # Run build helpers on this Windows host; only the application is cross-built.
    $env:GOOS, $env:GOARCH = '', ''
    $version = & $goCommand run ./cmd/netlaunch version
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '^\d+\.\d+\.\d+[-.a-zA-Z0-9]*$') { throw 'Could not determine the application version.' }
    $package = Join-Path $repo "dist\NetLaunch-Windows-amd64-$version-$Mode"
    if (Test-Path -LiteralPath $package) { throw 'Package directory already exists; choose a clean build workspace or move the previous package first.' }
    $null = New-Item -ItemType Directory -Path $package
    $tags = switch ($Mode) { 'home' { 'windows_home' } 'validation' { 'windows_validation' } default { '' } }
    $env:GOOS, $env:GOARCH = 'windows', 'amd64'
    $buildArgs = @('build', '-trimpath', '-o', (Join-Path $package 'netlaunch.exe'))
    if ($tags) { $buildArgs += @('-tags', $tags) }
    $buildArgs += './cmd/netlaunch'
    & $goCommand @buildArgs
    if ($LASTEXITCODE -ne 0) { throw 'Application build failed.' }
    $env:GOOS, $env:GOARCH = '', ''

    function Copy-PackageFile([string]$Source, [string]$Relative) {
        $destination = Join-Path $package $Relative
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force
        Copy-Item -LiteralPath $Source -Destination $destination
    }
    foreach ($name in @('README.md', 'THIRD_PARTY.md', 'licenses/golang-x-sys.txt', 'examples/policy.json', 'examples/bootstrap.json')) {
        Copy-PackageFile (Join-Path $repo $name) $name
    }
    foreach ($entry in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'entries-windows') -Filter '*.cmd' -File) {
        Copy-PackageFile $entry.FullName $entry.Name
    }
    Copy-PackageFile $actualManifest 'runtime/manifest.json'
    # Paths come from the repository manifest checked above (LF/CRLF normalized).
    $manifest = Get-Content -LiteralPath $expectedManifest -Raw | ConvertFrom-Json
    foreach ($file in $manifest.files) {
        Copy-PackageFile (Join-Path $runtimeRoot $file.path) ('runtime/' + $file.path)
    }
    foreach ($name in $notices) {
        Copy-PackageFile (Join-Path $runtimeRoot ('notices/' + $name)) ('runtime/notices/' + $name)
    }
    # The archive builder verifies runtime digests and uses an explicit allowlist.
    & $goCommand run ./cmd/packagezip $package "$package.zip" windows
    if ($LASTEXITCODE -ne 0) { throw 'Archive validation or creation failed.' }
    $digest = (Get-FileHash -LiteralPath "$package.zip" -Algorithm SHA256).Hash.ToLowerInvariant()
    $checksum = "$digest  $([IO.Path]::GetFileName($package)).zip`n"
    [IO.File]::WriteAllText("$package.zip.sha256", $checksum, [Text.UTF8Encoding]::new($false))
    Write-Output "$package.zip"
} finally {
    $env:GOOS, $env:GOARCH = $savedGOOS, $savedGOARCH
    Pop-Location
}
