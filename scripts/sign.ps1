param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath
)

# sign.ps1 - code signing helper (requires installed cert + signtool)

$SignTool = "C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
$TimestampUrl = "http://timestamp.digicert.com"
$CertStore = "My"
$CertSubject = "YOUR COMPANY NAME"

if (!(Test-Path $SignTool)) {
    Write-Error "signtool not found at $SignTool"
    exit 1
}

& $SignTool sign /fd SHA256 /a /sm /s $CertStore /n $CertSubject /tr $TimestampUrl /td SHA256 $BinaryPath
if ($LASTEXITCODE -ne 0) {
    Write-Error "Sign failed."
    exit 1
}

Write-Host "Signed $BinaryPath"
