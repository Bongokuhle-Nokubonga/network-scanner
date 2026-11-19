# Compile and test the network scanner on Windows.
# Usage:  .\build.ps1                      -> compile + run tests
#         .\build.ps1 scan <target> [opts] -> compile + scan (authorised networks only)
$ErrorActionPreference = "Stop"
if (Test-Path out) { Remove-Item -Recurse -Force out }
$sources = Get-ChildItem -Recurse src -Filter *.java | ForEach-Object { $_.FullName }
javac --release 17 -Xlint:all -d out $sources
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($args.Count -gt 0 -and $args[0] -eq "scan") {
    $rest = @($args | Select-Object -Skip 1)
    java -cp out netscan.NetScanApp @rest
} else {
    java -cp out netscan.NetScanTest
}
exit $LASTEXITCODE
