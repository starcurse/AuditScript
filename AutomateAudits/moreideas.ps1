Get-EventLog -LogName Security | Select-Object -Property EntryType,EventID,Message,TimeGenerated,Source,Category | Export-CSV -Path C:\Security\Audits\2021\Resultspls.csv -NoClobber

#open file
$FilePath = 'C:\Security\Audits\2021\Resultspls.csv' #<------- Change this!!!
$workbook = $excel.Workbooks.Open($FilePath)

#make it visible (just to check what is happening)
$excel.Visible = $false

#access the Application object and run a macro
$app = $excel.Application
$excel.Run('Plswork')
$excel.Quit()
