#Variables
$AuditVerification = "C:\Security\Scripts\AutomatedAuditing\Config\AuditVerification.txt"
$Verification = "C:\Security\Scripts\Configuration\Verification.txt"
$Template = "C:\Security\Scripts\ExcelTemplates\AuditTemplate.xlsx"
$PCisConfigured = Test-Path -Path $Verification
$ScriptisConfigured = Test-Path -Path $AuditVerification
$ARworkbook = "C:\Security\Results\AutomatedAuditing\AuditResults.xlsx"
$WorkbookExists = Test-Path -Path $ARworkbook
$timestamp = Get-Date -Format "MM/dd/yyyy HH:mm"

try {
  if ($PCisConfigured -eq $true) {write-host "Configuration has already occured." -ForegroundColor Green} else {
  write-host "Performing configuration now." -ForegroundColor Yellow
  write-host "Creating folders and files..."
  New-Item -Path "C:\Security\Scripts\" -ItemType "Directory"
  New-Item -Path "C:\Security\Scripts\ExcelTemplates" -ItemType "Directory"
  New-Item -Path "C:\Security\Scripts\Configuration" -ItemType "Directory"
  New-Item -Path "C:\Security\Scripts\Logs" -ItemType "Directory"
  New-Item -Path "C:\Security\Scripts\Logs\GeneralErrors.txt"
  New-Item -Path "C:\Security\Results" -ItemType "Directory"
  New-Item -Path $Verification
}
} Catch {
  Write-OutPut "Error setting up PCconfiguration on $timestamp" | Out-File -FilePath C:\Security\Scripts\Logs\GeneralErrors.txt -Append
}
try {
    if ($ScriptisConfigured -eq $true) {write-host "Configuration has already occured." -ForegroundColor Green} else {
    New-Item -Path "C:\Security\Results\AutomatedAuditing" -ItemType "Directory"
    New-Item -Path "C:\Security\Results\AutomatedAuditing\Logs" -ItemType "Directory"
    New-Item -Path "C:\Security\Results\AutomatedAuditing\Logs\Errorlog.txt"
    Move-Item -Path C:\AutomatedAuditing -Destination C:\Security\Scripts
    Move-Item -Path C:\Security\Scripts\AutomatedAuditing\AuditTemplate.xlsx -Destination C:\Security\Scripts\ExcelTemplates\AuditTemplate.xlsx
    Move-Item -Path C:\SetupScript.PS1 -Destination C:\Security\Scripts\AutomatedAuditing\AuditScript\Setup\SetupScript.PS1
    New-Item -Path $PJVerification
  }
  } Catch {
    Write-OutPut "Error setting up Script Configuration on $timestamp" | Out-File -FilePath C:\Security\Scripts\Logs\GeneralErrors.txt -Append
  }
  try {
    if ($WorkbookExists -eq $true) {write-host "Workbook already exists." -ForegroundColor Green} else {
    Copy-Item -Path "$Template" -Destination "$ARworkbook"
  }
  } Catch {
    Write-OutPut "Error setting up Workbook on $timestamp" | Out-File -FilePath C:\Security\Scripts\Logs\GeneralErrors.txt -Append
  }