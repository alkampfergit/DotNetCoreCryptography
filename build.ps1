param(
    [string] $nugetApiKey,
    [bool]   $nugetPublish = $false,
    # Stage switches. Defaults keep the full local flow (test + pack) intact, while
    # CI can split them: the cross-platform test jobs run with -runPack $false and the
    # single Windows publish job runs with -runTests $false so tests are not re-run.
    [bool]   $runTests = $true,
    [bool]   $runPack = $true
)

# Helper function to check last execution result
function Assert-LastExecution {
    param(
        [string]$message,
        [bool]$haltExecution = $false
    )
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error $message
        if ($haltExecution) {
            exit $LASTEXITCODE
        }
    }
}

# Removed BuildUtils dependency - using direct GitVersion call instead
# Install-package BuildUtils -Confirm:$false -Scope CurrentUser -Force
# Import-Module BuildUtils

$runningDirectory = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

$nugetTempDir = "$runningDirectory/artifacts/NuGet"

if (Test-Path $nugetTempDir) 
{
    Write-host "Cleaning temporary nuget path $nugetTempDir"
    Remove-Item $nugetTempDir -Recurse -Force
}

# GitVersion is only needed to stamp the NuGet package, so it runs in the pack stage.
if ($true -eq $runPack)
{
    # Call GitVersion directly instead of using BuildUtils Invoke-Gitversion
    # This fixes the .NET Core 3.1 compatibility issue
    try {
        $gitVersionOutput = dotnet tool run dotnet-gitversion /nofetch /output json 2>&1
        if ($LASTEXITCODE -eq 0) {
            $version = $gitVersionOutput | ConvertFrom-Json
            $assemblyVer = $version.AssemblySemVer
            $assemblyFileVersion = $version.AssemblySemFileVer
            $nugetPackageVersion = $version.FullSemVer
            $assemblyInformationalVersion = $version.InformationalVersion
            Write-Host "GitVersion executed successfully"
        } else {
            Write-Warning "GitVersion failed with exit code $LASTEXITCODE. Output: $gitVersionOutput"
            Write-Warning "Using fallback version values"
            $assemblyVer = "0.7.0.0"
            $assemblyFileVersion = "0.7.0.0"
            $nugetPackageVersion = "0.7.0-dev"
            $assemblyInformationalVersion = "0.7.0-dev"
        }
    } catch {
        Write-Warning "GitVersion execution failed: $($_.Exception.Message)"
        Write-Warning "Using fallback version values"
        $assemblyVer = "0.7.0.0"
        $assemblyFileVersion = "0.7.0.0"
        $nugetPackageVersion = "0.7.0-dev"
        $assemblyInformationalVersion = "0.7.0-dev"
    }

    Write-host "assemblyInformationalVersion   = $assemblyInformationalVersion"
    Write-host "assemblyVer                    = $assemblyVer"
    Write-host "assemblyFileVersion            = $assemblyFileVersion"
    Write-host "nugetPackageVersion            = $nugetPackageVersion"
}

# Restore is required by every stage (test and pack alike).
Write-Host "\n\n*******************RESTORING PACKAGES*******************"
dotnet restore "$runningDirectory/src/DotNetCoreCryptography.sln"
Assert-LastExecution -message "Error in restoring packages." -haltExecution $true

if ($true -eq $runTests)
{
    Write-Host "\n\n*******************TESTING SOLUTION*******************"
    # --logger trx emits a machine-readable result file that CI turns into a job
    # summary; the results dir is fixed so the workflow knows where to find it.
    dotnet test "$runningDirectory/src/DotNetCoreCryptography.Tests/DotNetCoreCryptography.Tests.csproj" /p:CollectCoverage=true /p:CoverletOutput=TestResults/ /p:CoverletOutputFormat=lcov --logger "trx;LogFileName=test-results.trx" --results-directory "$runningDirectory/src/DotNetCoreCryptography.Tests/TestResults"
    Assert-LastExecution -message "Error in test running." -haltExecution $true
}

if ($true -eq $runPack)
{
    Write-Host "\n\n*******************BUILDING SOLUTION*******************"
    dotnet build "$runningDirectory/src/DotNetCoreCryptography.sln" --configuration release
    Assert-LastExecution -message "Error in building in release configuration" -haltExecution $true

    Write-Host "\n\n*******************PUBLISHING SOLUTION*******************"
    dotnet pack "$runningDirectory/src/DotNetCoreCryptographyCore/DotNetCoreCryptographyCore.csproj" --configuration release -o "$runningDirectory/artifacts/NuGet" /p:PackageVersion=$nugetPackageVersion /p:AssemblyVersion=$assemblyVer /p:FileVersion=$assemblyFileVersion /p:InformationalVersion=$assemblyInformationalVersion /p:CI=true
    Assert-LastExecution -message "Error in creating nuget packages.." -haltExecution $true

    if ($true -eq $nugetPublish)
    {
        Write-Host "\n\n*******************PUBLISHING NUGET PACKAGE*******************"
        dotnet nuget push .\artifacts\NuGet\** --source https://api.nuget.org/v3/index.json --api-key $nugetApiKey --skip-duplicate
        Assert-LastExecution -message "Error pushing nuget packages to nuget.org." -haltExecution $true
    }
}