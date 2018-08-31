Param(
    [string]$buildNumber = "0",
    [string]$preRelease = $null,
    [string]$branchName = "master",
    [string]$gitCommitHash = "1234567890123456789012345678901234567890"
)

$exists = Test-Path nuget.exe

if ($exists -eq $false) {
    $source = "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe"
    Invoke-WebRequest $source -OutFile nuget.exe
}

.\nuget.exe update -self

gci .\source -Recurse "packages.config" |% {
	"Restoring " + $_.FullName
	.\nuget.exe install $_.FullName -o .\source\packages
    
    if ($LastExitCode -ne 0) {
        exit $LastExitCode
    }
}

$msbuild = .\source\packages\vswhere.2.5.2\tools\vswhere.exe -version "[15.0,16.0)" -requires Microsoft.Component.MSBuild -property installationPath
if ($msbuild) {
    $msbuild = join-path $msbuild 'MSBuild\15.0\Bin\MSBuild.exe'
}
else {
    $msbuild = "msbuild"
}

Import-Module .\source\packages\psake.4.7.1\tools\psake\psake.psm1

#if(Test-Path Env:\APPVEYOR_BUILD_NUMBER){
#	$buildNumber = [int]$Env:APPVEYOR_BUILD_NUMBER
#	$task = "appVeyor"
    
#    Write-Host "Using APPVEYOR_BUILD_NUMBER"
#}

"Build number $buildNumber"

Invoke-Psake .\default-domain.ps1 $task -properties @{ buildNumber=$buildNumber; preRelease=$preRelease; msbuild=$msbuild; branchName=$branchName; gitCommitHash=$gitCommitHash }

Remove-Module psake