$Template = "C:\Security\Scripts\ExcelTemplates\AuditTemplate.xlsx"
$ARworkbook = "C:\Security\Results\AutomatedAuditing\AuditResults.xlsx"
$ARCSV = "C:\Security\Scripts\AutomatedAuditing\Temp\AuditResults.CSV"
$SecurityData = Import-Csv -Path $ARCSV
$WorkbookExists = Test-Path -Path "$ARworkbook"
#Testing for existence of the excel workbook, if it doesn't exist then a new workbook is created
if ($WorkbookExists -eq $false) {
    Copy-Item -Path "$Template" -Destination "$ARworkbook"
}
$Excel = New-Object -ComObject excel.application
$Excel.ScreenUpdating = $false
$Excel.EnableEvents = $false
$Excel.DisplayStatusbar = $false
$Excel.Visible = $false
$Excel.DisplayAlerts = $false
#Assigning variables to important parts of the workbook
$Workbook = $Excel.Workbooks.Open($ARworkbook)
$AuditResults = $Workbook.worksheets.item("Audit Results")
$i = 2
foreach($process in $SecurityData) {
    $AuditResults.cells.item($i,2) = $process.ID
    $AuditResults.cells.item($i,3) = $process.TimeCreated
    $AuditResults.cells.item($i,4) = $process.Keywords
    $i++
}
$AuditResults.Cells.Item(2,1).Formula = "=IF(D2=-9214364837600034816,`"Audit Success`",`"Audit Failure`")"
$rows = $AuditResults.range("B1").currentregion.rows.count
$AuditResults.range("A2:A$rows").formula = $AuditResults.range("A2").formula 
# Enabling visual clutter for users when they use excel again
$Excel.ScreenUpdating = $true
$Excel.EnableEvents = $true
$Excel.DisplayStatusbar = $true
$Excel.Visible = $true
$Excel.Quit()