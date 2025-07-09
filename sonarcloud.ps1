param(
    [string] $sonarSecret
)


# Removed BuildUtils dependency - using direct GitVersion call instead
# Install-package BuildUtils -Confirm:$false -Scope CurrentUser -Force
# Import-Module BuildUtils

$runningDirectory = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

$testOutputDir = "$runningDirectory/TestResults"

if (Test-Path $testOutputDir) 
{
    Write-host "Cleaning temporary Test Output path $testOutputDir"
    Remove-Item $testOutputDir -Recurse -Force
}

# Call GitVersion directly instead of using BuildUtils Invoke-Gitversion
# This fixes the .NET Core 3.1 compatibility issue
$gitVersionOutput = dotnet tool run dotnet-gitversion /nofetch /nonormalize /output json
$version = $gitVersionOutput | ConvertFrom-Json
$assemblyVer = $version.AssemblySemVer 

$branch = git branch --show-current
Write-Host "branch is $branch"

dotnet tool restore
dotnet tool run dotnet-sonarscanner begin /k:"alkampfergit_DotNetCoreCryptography" /v:"$assemblyVer" /o:"alkampfergit-github" /d:sonar.login="$sonarSecret" /d:sonar.host.url="https://sonarcloud.io" /d:sonar.cs.vstest.reportsPaths=TestResults/*.trx /d:sonar.cs.opencover.reportsPaths=TestResults/*/coverage.opencover.xml /d:sonar.coverage.exclusions="**Test*.cs" /d:sonar.branch.name="$branch"

dotnet restore src
dotnet build src --configuration release
dotnet test "./src/DotNetCoreCryptography.Tests/DotNetCoreCryptography.Tests.csproj" --collect:"XPlat Code Coverage" --results-directory TestResults/ --logger "trx;LogFileName=unittests.trx" --no-build --no-restore --configuration release -- DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Format=opencover
         

dotnet tool run dotnet-sonarscanner end /d:sonar.login="$sonarSecret"