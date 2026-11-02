param([Parameter(Mandatory = $true)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
$compiler = New-Object CodeDom.Compiler.CompilerParameters
$compiler.CompilerOptions = '/platform:x64 /optimize+'
[void]$compiler.ReferencedAssemblies.Add('System.dll')
$compiler.GenerateExecutable = $true
$compiler.OutputAssembly = [IO.Path]::GetFullPath($OutputPath)
Add-Type -Path (Join-Path $PSScriptRoot 'PortScope.cs') -CompilerParameters $compiler
