<#
.SYNOPSIS
    Run SonarQube scanner and check results for the BtWiFi project.
.DESCRIPTION
    This script runs tests with coverage, sends results to the local
    SonarQube server at 192.168.50.94:9000, and checks the quality gate.
    Requires: sonar-scanner on PATH, SONAR_BTWIFI env var set.
#>
param(
    [switch]$SkipTests,
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
$sonarUrl = "http://192.168.50.94:9000"
$projectKey = "btwifi"

# Validate token
if (-not $env:SONAR_BTWIFI) {
    Write-Error "SONAR_BTWIFI environment variable is not set. Set it to your SonarQube token."
    exit 1
}

if ($CheckOnly) {
    Write-Host "`n=== Checking SonarQube Quality Gate ===" -ForegroundColor Cyan
    $status = Invoke-RestMethod -Uri "$sonarUrl/api/qualitygates/project_status?projectKey=$projectKey" `
        -Headers @{ Authorization = "Bearer $env:SONAR_BTWIFI" }
    Write-Host "Quality Gate: $($status.projectStatus.status)"

    Write-Host "`n=== Open Issues ===" -ForegroundColor Cyan
    $issues = Invoke-RestMethod -Uri "$sonarUrl/api/issues/search?projectKeys=$projectKey&resolved=false&ps=100&p=1" `
        -Headers @{ Authorization = "Bearer $env:SONAR_BTWIFI" }
    Write-Host "Total open issues: $($issues.total)"
    foreach ($issue in $issues.issues) {
        Write-Host "  [$($issue.severity)] $($issue.message) -- $($issue.component):$($issue.line)"
    }

    Write-Host "`n=== Security Hotspots ===" -ForegroundColor Cyan
    $hotspots = Invoke-RestMethod -Uri "$sonarUrl/api/hotspots/search?projectKey=$projectKey&ps=100" `
        -Headers @{ Authorization = "Bearer $env:SONAR_BTWIFI" }
    Write-Host "Total hotspots: $($hotspots.paging.total)"
    foreach ($hs in $hotspots.hotspots) {
        Write-Host "  [$($hs.vulnerabilityProbability)] $($hs.message) -- $($hs.component):$($hs.line)"
    }
    exit 0
}

# Step 1: Run tests with coverage (unless skipped)
if (-not $SkipTests) {
    Write-Host "`n=== Running tests with coverage ===" -ForegroundColor Cyan
    python -m pytest tests/ --cov=src --cov-report=xml:coverage.xml --timeout=30 -q
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Tests failed. Fix them before running SonarQube scan."
        exit 1
    }
}

# Step 2: Run SonarQube scanner
Write-Host "`n=== Running SonarQube Scanner ===" -ForegroundColor Cyan
sonar-scanner "-Dsonar.token=$env:SONAR_BTWIFI"
if ($LASTEXITCODE -ne 0) {
    Write-Error "SonarQube scanner failed."
    exit 1
}

# Step 3: Wait for analysis to complete
Write-Host "`n=== Waiting for SonarQube analysis ===" -ForegroundColor Cyan
Start-Sleep -Seconds 10

# Step 4: Check quality gate
Write-Host "`n=== Checking Quality Gate ===" -ForegroundColor Cyan
$status = Invoke-RestMethod -Uri "$sonarUrl/api/qualitygates/project_status?projectKey=$projectKey" `
    -Headers @{ Authorization = "Bearer $env:SONAR_BTWIFI" }
$gate = $status.projectStatus.status
Write-Host "Quality Gate: $gate"

if ($gate -ne "OK") {
    Write-Warning "Quality gate did NOT pass: $gate"
    foreach ($cond in $status.projectStatus.conditions) {
        if ($cond.status -ne "OK") {
            Write-Host "  FAILED: $($cond.metricKey) = $($cond.actualValue) (threshold: $($cond.errorThreshold))"
        }
    }
}

# Step 5: Show open issues
Write-Host "`n=== Open Issues ===" -ForegroundColor Cyan
$issues = Invoke-RestMethod -Uri "$sonarUrl/api/issues/search?projectKeys=$projectKey&resolved=false&ps=100&p=1&facets=rules" `
    -Headers @{ Authorization = "Bearer $env:SONAR_BTWIFI" }
Write-Host "Total open issues: $($issues.total)"
foreach ($issue in $issues.issues) {
    Write-Host "  [$($issue.severity)] $($issue.message) -- $($issue.component):$($issue.line)"
}

Write-Host "`nDone." -ForegroundColor Green
