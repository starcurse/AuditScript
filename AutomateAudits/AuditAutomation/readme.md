# Audit Automation #

## The purpose of this automation is to provide a 1-click audit that will do the following ##
 * Open a PowerShell script and run as admin.
 * Save the Application, Security, and System logs to C:\Security\Automation using *standardized* filenames
 * Create custom queries that are executed by PowerShell and output a file for a human to review
    * Output any of the standard error codes
    * Output other relevant information with those codes, i.e. username and time for failed login
    * Eventually do other, more complex calculations such as flag out of normal hours login/logout
    * Flag rapid or multiple login attempts, past what would be allowed before lockout
    * Other logic as needed

<<<<<<< HEAD
In all of this remember to:
=======
### In all of this remember to ###
>>>>>>> e159cc7 (fix readme.md formatting)
 * Consult the ISSOs and get their feedback, so they will *trust* the script.
 * Test on COMET before implementing in the secure room


### To run the script ###
 * Navigate to the folder where the StandAloneAuditScript.ps1 file resides.
 * Open PowerShell as an admin (File..Open Windows PowerShell..Open Windows PowerShell as Administrator)  At some future point an .exe may be provided.

          Powershell -ExecutionPolicy Bypass -File .\StandAloneAuditScript.ps1
 
 * The script looks for and writes to the following folders:
    * Audits are read from **C:\Security\Audits\YYYY**\YYYYMMDD_Sys.evtx (or other .evtx files)
    * Note that the base path **C:\Security\Audits** is a configurable parameter at the top of the script
    * Results are written to the base path above + **\Automated_Audit_Output\YYYY-MM-DD**\file.txt, configurable at the top of the script