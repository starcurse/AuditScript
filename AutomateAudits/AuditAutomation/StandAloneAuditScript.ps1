#region GlobalVariables
# -------------------------------------------------------
##### SET GLOBAL VARIABLES #####
$runScriptInteractively = $checkProcessIsElevated = $true
$script:auditBasePath = "C:\Security\Audits"
$script:auditOutput= "$script:auditBasePath\Automated_Audit_Output"
# -------------------------------------------------------
#endregion GlobalVariables

Add-Type -TypeDefinition @"
        public enum UserType
        {
            Local,
            Domain
        }
"@

Function GetUniqueFileName {
    Param (
        [Parameter(Mandatory=$true)]
           [string]$Name,
        [Parameter(Mandatory=$true)]
           [string]$Path
    )
    $i = 1
    $Path = $($Path.TrimEnd('\',1))
    $fileName,$extension = $Name.Split('.')
    $FullPath = "$Path$Name"
    $newFileName = ""
    while (Test-Path -Path "$FullPath") {
        $newFileName = "${Name}-$i"
        %FullPath = "$Path$Name$extension"
        $i++
    }
    return $FullPath
}

Function Get-UserList {
    Param (
        [Parameter(Mandatory=$false)]
           [UserType]$UserType=[UserType]::Local
    )
    
    Function FilterNames {
        Param (
          [Parameter(Mandatory=$true)]
               $Users
        )
        $UserNames = New-Object System.Collections.ArrayList
        if (Confirm-NotNull $users){
            foreach ($user in $users){
                if (!(($user -contains 'mailbox') -or ((($user.ToCharArray() | ?{$_ -match  '[0-9]'}).Count -gt 4) -and ($user.ToCharArray() | ?{$_ -match  '[a-zA-Z]'}).Count -lt 5)) -or (($user.ToCharArray() | ?{$_ -match  '-'}).Count -lt 5)){
                    [void]$UserNames.add($user) 
                }
            }
        }
        return $UserNames
    }
    
    try {
        if ($UserType -eq [UserType]::Domain){
            if ($(Get-Command -Name "Get-ADUser" 2> $null)) {
                $users = Get-ADUser -filter {ObjectClass -eq "user"} | Where-Object {$_.Name.Length -lt 25 -and $_.GivenName -ne ""} | select -ExpandProperty SamAccountName
                return FilterNames -Users $users
            } else {
                $users = (cmd /c net user $User /domain '2>&1') | Out-String
                if ($users.indexOf('not be found') -ne -1) {
                    return $false
                } else {
                    $userArray = ([regex]::replace(([regex]::match($users,'^(?>.*[-]{3,})(.*)(?=The command completed successfully.)')).Groups[0].Value,"\s+",",")).split(","); 
                    return FilterNames -Users $userArray
                }
            }
        } elseif ($UserType -eq [UserType]::Local){
            if ($(Get-Command -Name "Get-LocalUser" 2> $null)) { 
                $users = (Get-LocalUser | Select-Object -ExpandProperty Name)
                return $users
            } else {
                $users = (cmd /c net user $User '2>&1') | Out-String
                if ($users.indexOf('not be found') -ne -1) {
                    return $False
                } else {
                    $userArray = ([regex]::replace(([regex]::match($users,'^(?>.*[-]{3,})(.*)(?=The command completed successfully.)')).Groups[0].Value,"\s+",",")).split(","); 
                    return $userArray
                }
            }
        }
    } catch {
        return $False
    }    
}


Function GetPropertyIfExists {
    Param (
        [Parameter(Mandatory=$true)]
        $Value,
        [Parameter(Mandatory=$true)]
        $PropertyName
    )
    write-output "$($Value.Keys | Select-Object *)"
    if ($Value.Keys -contains $PropertyName) {
        return $Value.$PropertyName
    }
    return $null
}
Function TranslateFailureReason {
    Param (
        [Parameter(Mandatory=$true)]
        $Value
    )
    $failureReason = ""
    switch ($Value) {
        (($_ -eq "%%2305") -or ($_ -eq "The specified user account has expired.")) {$failureReason = "The specified user account has expired."}
        (($_ -eq "%%2309") -or ($_ -eq "The specified account's password has expired.")) {$failureReason = "The specified account's password has expired."}
        (($_ -eq "%%2310") -or ($_ -eq "Account currently disabled.")) {$failureReason = "Account currently disabled."}
        (($_ -eq "%%2311") -or ($_ -eq "Account logon time restriction violation. ")) {$failureReason = "Account logon time restriction violation. "}
        (($_ -eq "%%2312") -or ($_ -eq "User not allowed to logon at this computer.")) {$failureReason = "User not allowed to logon at this computer."}
        (($_ -eq "%%2313") -or ($_ -eq "Unknown user name or bad password.")) {$failureReason = "Unknown user name or bad password."}

    }
    return $failureReason
}

Function TranslateSubStatusCode {
    Param (
        [Parameter(Mandatory=$true)]
        $Value
    )
    if ($null -ne $Value) {
        if ($Value.toUpper() -match '^0X.*') {

            $dictionary = @{
                "0XC000005E"="There are currently no logon servers available to service the logon request";
                "0XC0000064"="User name does not exist";
                "0xC000006A"="User name is correct but the password is wrong";
                "0XC000006D"="This is either due to a bad username or authentication information";
                "0XC000006E"="Unknown user name or bad password.";
                "0XC000006F"="User tried to logon outside his day of week or time of day restrictions";
                "0XC0000070"="Workstation restriction or Authentication Policy Silo violation (look for event ID 4820 on domain controller)";
                "0XC0000071"="Expired password";
                "0XC0000072"="Account is currently disabled";
                "0XC00000DC"="Indicates the SAM Server was in the wrong state to perform the desired operation";
                "0XC0000133"="Clocks between DC and other computer too far out of sync";
                "0XC000015B"="The user has not been granted the requested logon type (aka logon right) at this machine";
                "0XC000018C"="The logon request failed because the trust relationship between the primary domain and the trusted domain failed";
                "0XC0000192"="An attempt was made to logon but the netlogon service was not started";
                "0XC0000193"="Account expiration";
                "0XC0000224"="User is required to change password at next logon";
                "0XC0000225"="Evidently a bug in Windows and not a risk";
                "0XC0000234"="User is currently locked out";
                "0XC0000413"="Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine"
            }
            return $dictionary[$Value]
        } else {
            #Use existing value when Value is already a non hex string
            return $Value
        }
    } else {
        return ""
    }
}
	
Function TranslateAccessReason {
    Param (
        [Parameter(Mandatory=$true)]
        $Value
    )
    if ($null -ne $Value) {
        if ($Value -match '^%%.*') {
            $dictionary = @{
                "%%4416"="ReadData (or ListDirectory)";
                "%%4417"="WriteData (or AddFile)";
                "%%4418"="AppendData (or AddSubdirectory or CreatePipeInstance)";
                "%%4419"="ReadEA";
                "%%4420"="WriteEA";
                "%%4421"="Execute/Traverse";
                "%%4422"="DeleteChild";
                "%%4423"="ReadAttributes";
                "%%4424"="WriteAttributes";
                "%%1537"="DELETE";
                "%%1538"="READ_CONTROL";
                "%%1539"="WRITE_DAC";
                "%%1540"="WRITE_OWNER";
                "%%1541"="SYNCHRONIZE";
                "%%1542"="ACCESS_SYS_SEC";
                "%%4432"="Query Key Value";
                "%%4433"="Set Key Value";
                "%%4434"="Create Sub Key";
                "%%4435"="Enumerate sub-keys";
                "%%4436"="Notify about changes to keys";
                "%%4437"="Create Link"
            }
            return $dictionary[$Value]
        } else {
            #Use existing value when git add
        }
    } else {
        return ""
    }
}

Function TranslateImpersonationLevel {
  Param (
    [Parameter(Mandagigtory=$true)]
    $Value
  )
  $impersonationLevel = ""
  switch ($Value) {
      (($_ -eq "%%1832") -or ($_ -eq "Identification")) {$impersonationLevel = "Identification"}
      (($_ -eq "%%1833") -or ($_ -eq "Impersonation")) {$impersonationLevel = "Impersonation"}
      (($_ -eq "%%1840") -or ($_ -eq "Delegation")) {$impersonationLevel = "Delegation"}
      (($_ -eq "%%1841") -or ($_ -eq "Denied by Process Trust Label ACE")) {$impersonationLevel = "Denied by Process Trust Label ACE"}
      (($_ -eq "%%1842") -or ($_ -eq "Yes")) {$impersonationLevel = "Yes"}
      (($_ -eq "%%1843") -or ($_ -eq "No")) {$impersonationLevel = "No"}
      (($_ -eq "%%1844") -or ($_ -eq "System")) {$impersonationLevel = "System"}
      (($_ -eq "%%1845") -or ($_ -eq "Not Available")) {$impersonationLevel = "Not Available"}
      (($_ -eq "%%1846") -or ($_ -eq "Default")) {$impersonationLevel = "Default"}
      (($_ -eq "%%1847sdfgsdfgsdfg") -or ($_ -eq "DisallowMmConfig")) {$impersonationLevel = "DisallowMmConfig"}
      (($_ -eq "%%1848") -or ($_ -eq "Off")) {$impersonationLevel = "Off"}
      (($_ -eq "%%1849") -or ($_ -eq "Auto")) {$impersonationLevel = "Auto"}
   }
   return $impersonationLevel
}


<#####
Path to folder containing folders for each computer's event logs
e.g.
2021\
      20210326.evtx
      Other Audits\
         20210326_Sys.evtx
         20210326_App.evtx
      Machine2\ ...
#>
#Ensure variables are initialized as blank
$lastLoginAttemptTime = $repeatedFailures = $lastUser = $repeatedFailures = $lockouts = $escalations = $failedLogons = ""
$lastUserCount=1
$script:lastRecord = ""
$script:repeatTracker = ""
$script:repeatCount = $null
#Produces "YYYY, e.g. 2021
$script:auditFolderName = "{0}" -f [DateTime]::Today.Year
$script:auditFilesPath = "{0}\{1}" -f $script:auditBasePath,$script:auditFolderName

$script:repeatObj = @{}
$script:users = Get-UserList
#Adjust  how far back in the logs to perform analysis. Default is 15 days back. Value must be a a negative number, E.g. -15
$script:StartDate = (Get-Date).Adddays(-15)
$script:Today = (Get-Date)
$script:today_name = (Get-Date -Format "yyyy-MM-dd")
$script:reportingPath = "{0}\{1}" -f $script:auditOutput,$script:today_name

#Check that log directory exists, if not create and exit
if (!(Test-Path $script:auditFilesPath)) {
    [void] $(New-Item -Path $script:auditFilesPath -ItemType Directory)
    Write-Output "`nCreated new Log directory as it did not exist.`nNow exiting as no log files were available for audit."
    Read-Host -Prompt "Press any key to exit..."
    exit
}

if (!(Test-Path $script:auditOutput)) {    
    New-Item -Path "$script:auditOutput" -ItemType Directory 
}
if (!(Test-Path "$script:reportingPath")) {
    New-Item -Path "$script:reportingPath" -ItemType Directory
}

Write-Output "*** Processing logs from $script:auditBasePath ***"
foreach ($log in $(Get-ChildItem -Filter "*.evtx" -Path "$script:auditFilesPath")) {
write-output "@@@ $($log.FullName) @@@@"
    try {
        $usr = ""
        $evt = ""
        $loginEvt = ""
        
        
        $evt = Get-WinEvent -FilterHashtable  @{`
            Path="$($log.FullName)"
            Id=4625
            Keywords="4503599627370496"
            StartTime=$script:startDate
            EndTime=$script:Today} -EA Stop

        foreach ($loginObj in $(Get-WinEvent -FilterHashtable  @{`
            Path="$($log.FullName)"
            Id=@(4634,4800,4624,-4673,-4674)
            Keywords="9007199254740992"
            StartTime=$script:startDate
            EndTime=$script:Today} -EA Stop
)) {
              
            $userMatch = [regex]::Match($loginObj.Message,'.*Account Name:\s+(?<accountName>\S+)',[System.Text.RegularExpressions.RegexOptions]::Multiline)
            $userMatch2 = [regex]::Match($loginObj.Message,'(?<=.*New Logon:.*)Account Name:\s+(?<accountName>\S+)',[System.Text.RegularExpressions.RegexOptions]::SingleLine)
            
            if ($userMatch.Groups.Count -gt 1){
                $loginUsr = $userMatch.Groups["accountName"].Value
            }
            if ($userMatch2.Groups.Count -gt 1){
                $loginUsr2 = $userMatch2.Groups["accountName"].Value
            }
            
            $impMatch = [regex]::Match($loginObj.Message,'.*Impersonation Level:\s+(?<impersonation>\S+)',[System.Text.RegularExpressions.RegexOptions]::Multiline)
            if ($impMatch.Groups.Count -gt 1){
                $impersonationLevel = $impMatch.Groups["impersonation"].Value
            } else {
                $impersonationLevel = $null
            }
            
            #Eventually change
            if (($script:users -contains $loginUsr) -or ($script:users -contains $loginUsr2)){
            #    write-output "$("{0} {1} {2} {3} {4}" -f $loginObj.Id,$loginObj.TaskDisplayName,$loginUsr,$loginUsr2,$impersonationLevel)"
            }
        }
         
        #recNum helps us keep track of how close to the end of the records we are
        $recNum = 0
        foreach ($obj in $evt) {
            $recNum++
            $escalation = $lockout = ""

            $time = $obj.TimeCreated
            $usr = if ($obj.Properties.Count -gt 4) { $obj.Properties[5].Value.TrimEnd(" ",1)} else {""}
            
            if ($obj.Message -match ".*consent\.exe.*") {
                $escalation = "{0}[{1}]`tEscalation attempt made using credential: {2}`r`n" -f $escalation, $time, $usr
            }
            if ($obj.TaskDisplayName -eq "Account Lockout") {
                $callerProcessMatch = [regex]::match($obj.Message,"Caller Process Name:.(?<procname>\S+\.exe)",[System.Text.RegularExpressions.RegexOptions]::Multiline)
                if ($callerProcessMatch.Groups.count -gt 1){
                    $callerProcess = $callerProcessMatch.Groups["procname"].Value
                } else {
                    $callerProcess = ""
                }
                if ($callerProcess -match ".*consent.exe") {
                    $lockoutAnalysis = "(Escalation attempted)"
                } else {
                    $lockoutAnalysis = ""
                }

                $lockoutMsg = "[{0}]`tUser: {1} locked Out by process: {2} {3}" -f $time, $usr, $callerProcess, $lockoutAnalysis
                $lockouts = "{0}{1}`r`n" -f $lockouts,$lockoutMsg
                write-output "$lockoutMsg"
            }
        
            if ($lastUser -eq $usr){
                if ($lastUser -eq $usr) {
                    $lastUserCount++
                }
            }
            if ((($lastUser -ne $usr) -and ($lastUserCount -ge 2) -and ($lastUser -ne "")) -or ($recNum -eq $evt.Count)){
                #if recNum is the same as the total number of events, ignore the other conditions
                $tempRec = "[{0}]`t{1} failed logon count`t{2}" -f $time,$lastUser,$lastUserCount
                $repeatedFailures = "$repeatedFailures`r`n$tempRec"
                $lastUserCount=1
            }

            $record = "[{0}] {1} failed to log in" -f $time,$usr
            $lastUser = $usr
            Write-Output "$record"
            if (($usr.Length -gt 0) -and ($script:users -contains $usr)) {
                $failedLogons = "{0}{1}`r`n" -f $failedLogons,$record
            }
        }
    } Catch [System.Exception]{}
    

}

while (Test-Path -Path "$OTLocalPath\$todayFolder") {
    $todayFolder = "$today $i"
    $i++
}

"$repeatedFailures" | Out-File -FilePath "$auditOutput\$today_name\Repeated-Logon-Attempts.txt" 
"$escalations" | out-file -FilePath $("{0}\Escalation-Attempts.txt" -f $script:reportingPath) 
"$lockouts" | out-file -FilePath $("{0}\Lockouts.txt" -f $script:reportingPath)
"$failedLogons" | Out-File -FilePath "$auditOutput\$today_name\Failed-Logon-Attempts.txt"
Write-Output "*** Results written to ${script:reportingPath}  ***"
