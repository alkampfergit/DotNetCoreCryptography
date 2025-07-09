param(
    [string] $sonarSecret
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

$testOutputDir = "$runningDirectory/TestResults"

if (Test-Path $testOutputDir) 
{
    Write-host "Cleaning temporary Test Output path $testOutputDir"
    Remove-Item $testOutputDir -Recurse -Force
}

# Call GitVersion directly instead of using BuildUtils Invoke-Gitversion
# This fixes the .NET Core 3.1 compatibility issue
try {
    $gitVersionOutput = dotnet tool run dotnet-gitversion /nofetch /nonormalize /output json 2>&1
    if ($LASTEXITCODE -eq 0) {
        $version = $gitVersionOutput | ConvertFrom-Json
        $assemblyVer = $version.AssemblySemVer 
        Write-Host "GitVersion executed successfully, version: $assemblyVer"
    } else {
        Write-Warning "GitVersion failed with exit code $LASTEXITCODE. Output: $gitVersionOutput"
        Write-Warning "Using fallback version values"
        $assemblyVer = "0.7.0.0"
    }
} catch {
    Write-Warning "GitVersion execution failed: $($_.Exception.Message)"
    Write-Warning "Using fallback version values"
    $assemblyVer = "0.7.0.0"
}

# Try to get branch from GitHub Actions environment variables first
$branch = $env:GITHUB_HEAD_REF  # For pull requests
if (-not $branch) {
    $branch = $env:GITHUB_REF_NAME  # For pushes (GitHub Actions v2+)
}
if (-not $branch -and $env:GITHUB_REF) {
    # Extract branch name from refs/heads/branch-name format
    $branch = $env:GITHUB_REF -replace '^refs/heads/', ''
}
# Fall back to git command for local development
if (-not $branch) {
    $branch = git branch --show-current
}
# Final fallback to prevent empty branch name
if (-not $branch) {
    $branch = "develop"
    Write-Warning "Unable to detect branch name, using fallback: $branch"
}
Write-Host "branch is $branch"

Write-Host "Restoring dotnet tools..."
dotnet tool restore
Assert-LastExecution -message "Error restoring dotnet tools." -haltExecution $true

Write-Host "Starting SonarCloud analysis..."
dotnet tool run dotnet-sonarscanner begin /k:"alkampfergit_DotNetCoreCryptography" /v:"$assemblyVer" /o:"alkampfergit-github" /d:sonar.login="$sonarSecret" /d:sonar.host.url="https://sonarcloud.io" /d:sonar.cs.vstest.reportsPaths=TestResults/*.trx /d:sonar.cs.opencover.reportsPaths=TestResults/*/coverage.opencover.xml /d:sonar.coverage.exclusions="**Test*.cs" /d:sonar.branch.name="$branch"
Assert-LastExecution -message "Error starting SonarCloud analysis. Please check your SONAR_TOKEN and network connectivity." -haltExecution $true

Write-Host "Restoring packages..."
dotnet restore src
Assert-LastExecution -message "Error restoring packages." -haltExecution $true

Write-Host "Building solution..."
dotnet build src --configuration release
Assert-LastExecution -message "Error building solution." -haltExecution $true

Write-Host "Running tests with coverage..."
dotnet test "./src/DotNetCoreCryptography.Tests/DotNetCoreCryptography.Tests.csproj" --collect:"XPlat Code Coverage" --results-directory TestResults/ --logger "trx;LogFileName=unittests.trx" --no-build --no-restore --configuration release -- DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Format=opencover
Assert-LastExecution -message "Error running tests." -haltExecution $true

Write-Host "Completing SonarCloud analysis..."
dotnet tool run dotnet-sonarscanner end /d:sonar.login="$sonarSecret"
Assert-LastExecution -message "Error completing SonarCloud analysis." -haltExecution $true

Write-Host "SonarCloud analysis completed successfully."