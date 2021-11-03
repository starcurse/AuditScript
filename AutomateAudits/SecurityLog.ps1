$EventIDs = 4625,4656,4660,4723,4724,4725,4776,4777,4608,4616,4658,4663,4698,4700,4703,4704,4705,4717,4722,4739,4740,4767,4911,4913,5142,5143,5144,6416,6420,6422
$EventCheese = 4624,4688,4826,1101,4616,4777
$AllIDs = @{
    LogName = 'Security'
    ID = $EventCheese
}
$ComputerName = $env:ComputerName
$AuditCSV = "C:\Security\Scripts\AutomatedAuditing\Temp\AuditResults.CSV"
Get-WinEvent -ComputerName $ComputerName -FilterHashtable $AllIDs | Select-Object -Property Keywords,ID,TimeCreated | Export-Csv -Path $AuditCSV -NoTypeInformation
