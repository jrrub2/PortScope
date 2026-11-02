param([Parameter(Mandatory = $true)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
$compiler = New-Object CodeDom.Compiler.CompilerParameters
$compiler.CompilerOptions = '/platform:x64 /optimize+'
foreach ($assembly in @('System.dll', 'System.Core.dll', 'System.IO.Compression.dll', 'System.Web.Extensions.dll')) { [void]$compiler.ReferencedAssemblies.Add($assembly) }
$compiler.GenerateExecutable = $true
$compiler.OutputAssembly = [IO.Path]::GetFullPath($OutputPath)
Add-Type -Path (Join-Path $PSScriptRoot 'PortScope.cs') -CompilerParameters $compiler
