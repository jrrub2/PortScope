param(
  [string]$NodePath,
  [string]$NodeLicensePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) { throw 'Build with 64-bit Windows PowerShell 5.1.' }
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $NodePath) { $NodePath = (Get-Command node.exe -ErrorAction Stop).Source }
$NodePath = (Resolve-Path -LiteralPath $NodePath).Path
$runtime = & $NodePath -p 'JSON.stringify({version:process.version,platform:process.platform,arch:process.arch})' | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $runtime.platform -ne 'win32' -or $runtime.arch -ne 'x64') { throw 'A Windows x64 Node runtime is required.' }
if ($runtime.version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') { throw 'The Node runtime version is invalid.' }
$package = Get-Content -LiteralPath (Join-Path $root 'package.json') -Raw | ConvertFrom-Json
if ($package.version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { throw 'Package version must be a stable semantic version.' }
$dist = Join-Path $root 'dist'
$name = 'PortScope-' + $package.version + '-windows-x64'
$output = Join-Path $dist $name
$archive = Join-Path $dist ($name + '.zip')
# Never overwrite/delete an existing release or an arbitrary computed directory.
if ((Test-Path -LiteralPath $output) -or (Test-Path -LiteralPath $archive)) { throw ('Release already exists: ' + $output + '. Move it aside before rebuilding.') }
if (-not (Test-Path -LiteralPath (Join-Path $root 'web/index.html') -PathType Leaf)) { throw 'Build the web dashboard before packaging.' }
foreach ($required in @('server.js', 'LICENSE', 'lib/icmp-worker.ps1', 'web/THIRD-PARTY-NOTICES.txt')) {
  if (-not (Test-Path -LiteralPath (Join-Path $root $required) -PathType Leaf)) { throw ('Missing required input: ' + $required) }
}
[void](New-Item -ItemType Directory -Path $output)
$runtimeDir = New-Item -ItemType Directory -Path (Join-Path $output 'runtime')
$app = New-Item -ItemType Directory -Path (Join-Path $output 'app')
Copy-Item -LiteralPath $NodePath -Destination (Join-Path $runtimeDir.FullName 'node.exe')
Copy-Item -LiteralPath (Join-Path $root 'LICENSE') -Destination (Join-Path $output 'LICENSE')
Copy-Item -LiteralPath (Join-Path $root 'server.js') -Destination (Join-Path $app.FullName 'server.js')
# Only runtime files, never node_modules, fixtures, profiles, screenshots or repository history.
foreach ($directory in @('lib', 'web')) {
  $source = Join-Path $root $directory
  $destination = Join-Path $app.FullName $directory
  [void](New-Item -ItemType Directory -Path $destination)
  $files = Get-ChildItem -LiteralPath $source -Recurse -Force
  if ($files | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) { throw ('Refusing linked input in ' + $directory) }
  foreach ($file in ($files | Where-Object { -not $_.PSIsContainer })) {
    $relative = $file.FullName.Substring($source.Length + 1)
    if ($directory -eq 'lib' -and $file.Extension -notin @('.js', '.ps1')) { throw ('Unexpected backend input: ' + $relative) }
    if ($directory -eq 'web' -and $file.Extension -notin @('.html', '.js', '.css', '.svg', '.png', '.jpg', '.jpeg', '.webp', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.json', '.txt')) { throw ('Unexpected web input: ' + $relative) }
    $target = Join-Path $destination $relative
    [void](New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force)
    Copy-Item -LiteralPath $file.FullName -Destination $target
  }
}
$runtimePackage = [ordered]@{ name = $package.name; version = $package.version; private = $true; type = 'commonjs'; license = $package.license }
[IO.File]::WriteAllText((Join-Path $app.FullName 'package.json'), ($runtimePackage | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
$nodeLicense = Join-Path $runtimeDir.FullName 'NODE-LICENSE.txt'
$licenseUrl = 'https://raw.githubusercontent.com/nodejs/node/' + $runtime.version + '/LICENSE'
if ($NodeLicensePath) {
  Copy-Item -LiteralPath (Resolve-Path -LiteralPath $NodeLicensePath).Path -Destination $nodeLicense
} else {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -UseBasicParsing -Uri $licenseUrl -OutFile $nodeLicense
}
$licenseText = Get-Content -LiteralPath $nodeLicense -Raw
if ($licenseText.Length -lt 30000 -or $licenseText -notmatch 'Copyright Node.js contributors' -or $licenseText -notmatch 'externally maintained libraries') {
  throw 'The full Node license and bundled dependency notices are required.'
}
$launcher = Join-Path $output 'PortScope.exe'
# Add-Type loads its output assembly, so compile in a short-lived process before ZIP reads the executable.
& (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'windows/compile.ps1') -OutputPath $launcher
if ($LASTEXITCODE -ne 0) { throw 'Native launcher compilation failed.' }
$nodeHash = (Get-FileHash -LiteralPath (Join-Path $runtimeDir.FullName 'node.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
$licenseHash = (Get-FileHash -LiteralPath $nodeLicense -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $runtimeDir.FullName 'runtime.json'), (@{
  nodeVersion = $runtime.version; platform = $runtime.platform; architecture = $runtime.arch;
  nodeSha256 = $nodeHash; licenseSource = $licenseUrl; licenseSha256 = $licenseHash
} | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
$instructions = @'
PortScope portable for Windows x64

Extract the COMPLETE ZIP, then double-click PortScope.exe. No Node installation or administrator access is required.
Keep the console open while monitoring. Ctrl+C stops the local server; closing the console also stops its workers.
The browser is opened to a numeric loopback address only. Browser launch failure prints the URL instead.

From PowerShell or Command Prompt:
  .\PortScope.exe --help
  .\PortScope.exe --version
  .\PortScope.exe --port 4599 --open

The executable is unsigned; this is a portable folder, not an installer. Do not run from inside the ZIP preview.
Requires supported Windows x64 with .NET Framework 4.8 and Windows PowerShell 5.1 for native ICMP diagnostics.
The local server never requests administrator access. Explicit diagnostic targets may contact the network.
Runtime JavaScript and built web assets are in app/, not embedded in PortScope.exe. No source archive is included.
Licenses: LICENSE, app/web/THIRD-PARTY-NOTICES.txt, runtime/NODE-LICENSE.txt.
'@
[IO.File]::WriteAllText((Join-Path $output 'START-HERE.txt'), $instructions, (New-Object Text.UTF8Encoding($false)))
Compress-Archive -LiteralPath $output -DestinationPath $archive -CompressionLevel Optimal
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(($archive + '.sha256'), ($hash + '  ' + [IO.Path]::GetFileName($archive) + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
Write-Output ('Portable directory: ' + $output)
Write-Output ('ZIP: ' + $archive)
Write-Output ('SHA256: ' + $hash)
