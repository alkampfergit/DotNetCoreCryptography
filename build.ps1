Install-package BuildUtils -Confirm:$false -Scope CurrentUser -Force
Import-Module BuildUtils

$runningDirectory = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

$version = Invoke-Gitversion
$assemblyVer = $version.assemblyVersion 
$assemblyFileVersion = $version.assemblyFileVersion
$nugetPackageVersion = $version.nugetVersion
$assemblyInformationalVersion = $version.assemblyInformationalVersion

Write-host "assemblyInformationalVersion   = $assemblyInformationalVersion"
Write-host "assemblyVer                    = $assemblyVer"
Write-host "assemblyFileVersion            = $assemblyFileVersion"
Write-host "nugetPackageVersion            = $nugetPackageVersion"

# Now restore packages and build everything.
dotnet restore "$runningDirectory/src/DotNetCoreCryptography.sln"
dotnet test "$runningDirectory/src/DotNetCoreCryptography.Tests/DotNetCoreCryptography.Tests.csproj" --collect "Code Coverage" -p:ParallelizeTestCollections=false
dotnet build "$runningDirectory/src/DotNetCoreCryptography.sln" --configuration release
dotnet pack "$runningDirectory/src/DotNetCoreCryptographyCore/DotNetCoreCryptographyCore.csproj" --configuration release -o "$runningDirectory/artifacts/NuGet" /p:PackageVersion=$nugetPackageVersion /p:AssemblyVersion=$assemblyVer /p:FileVersion=$assemblyFileVer /p:InformationalVersion=$assemblyInformationalVersion