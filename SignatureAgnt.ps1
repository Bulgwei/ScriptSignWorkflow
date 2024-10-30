#
# ==============================================================================================
# THIS SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
# FITNESS FOR A PARTICULAR PURPOSE.
#
# This sample is not supported under any Microsoft standard support program or service. 
# The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
# implied warranties including, without limitation, any implied warranties of merchantability
# or of fitness for a particular purpose. The entire risk arising out of the use or performance
# of the sample and documentation remains with you. In no event shall Microsoft, its authors,
# or anyone else involved in the creation, production, or delivery of the script be liable for 
# any damages whatsoever (including, without limitation, damages for loss of business profits, 
# business interruption, loss of business information, or other pecuniary loss) arising out of 
# the use of or inability to use the sample or documentation, even if Microsoft has been advised 
# of the possibility of such damages.
# ==============================================================================================
#
# version 1.1
# dev'd by andreas.luy@microsoft.com
# 28.10.2ß24
#

<#
    .SYNOPSIS
    Submit incoming requests to CA and add additional SANs to that appropriate pending request. 
    All necessary parameters are taken from the config.xml file

    .PARAMETER Help
    display help.

   .Notes
    AUTHOR: Andreas Luy, MSFT; andreas.luy@microsoft.com
    last change 26.07.2021

#>

Param (
    [Parameter(Mandatory=$false)]
    [Switch]$Help
)

If ($Help) {
    Get-Help $MyInvocation.MyCommand.Definition -Detailed
    exit
}


$ScriptDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

#debug only
#$ScriptDir = "C:\LabFiles\Automation"
. ($ScriptDir+"\lib.helper.ps1")

$RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\SignatureAgent"
$BaseDir = (Get-ItemProperty -Path $RegistryRoot -Name "WorkingDirectory").WorkingDirectory

#region verify if eventlog should be used
$UseEventlog = Use-Eventlog
#endregion

#region verify if mail information should be used
$UseMail = Use-Mail
#endregion

#region verify if automatic approval is configured
$AutoApproval = Check-AutoApprove
#endregion

#region control file location file
$CntlFile = $ScriptDir+"\SignCntl.csv"
#endregion

if(!(Test-Path $BaseDir)) {
    $EvtMsg = "Configuration Error!`n`r`n`rWorking directory is not accessible:`n`r"+$BaseDir+".`n`rVerify that the directory exists and the SignatureAgent account has appropriate access permissions."
    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1001 -EntryType Error -Message $EvtMsg
    if ($Global:UseAdminEmail){
        $Subject = "Working directory is not accessible"
        Shoot-AdminMail $Subject $EvtMsg
    }
    break
}
if(!(Test-Path $BaseDir\inbox)) {
    $EvtMsg = "Configuration Error!`n`r`n`rInbox folder is not accessible:`n`r"+$BaseDir+"\Inbox.`n`rVerify that the folder exists and the SignatureAgent account has appropriate access permissions."
    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1002 -EntryType Error -Message $EvtMsg
    if ($Global:UseAdminEmail){
        $Subject = "Inbox folder is not accessible"
        Shoot-AdminMail $Subject $EvtMsg
    }
    break
}
if(!(Test-Path $BaseDir\outbox)) {
    $EvtMsg = "Configuration Error!`n`r`n`rOutbox folder is not accessible:`n`r"+$BaseDir+"\Outbox.`n`rVerify that the folder exists and the SignatureAgent account has appropriate access permissions."
    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1003 -EntryType Error -Message $EvtMsg
    if ($Global:UseAdminEmail){
        $Subject = "Outbox folder is not accessible"
        Shoot-AdminMail $Subject $EvtMsg
    }
    break
}
if(!(Test-Path $BaseDir\approved)) {
    $EvtMsg = "Configuration Error!`n`r`n`rArchive folder is not accessible:`n`r"+$BaseDir+"\Archive.`n`rVerify that the folder exists and the SignatureAgent account has appropriate access permissions."
    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1004 -EntryType Error -Message $EvtMsg
    if ($Global:UseAdminEmail){
        $Subject = "Archive folder is not accessible"
        Shoot-AdminMail $Subject $EvtMsg
    }
    break
}
if(!(Test-Path $BaseDir\archive)) {
    $EvtMsg = "Configuration Error!`n`r`n`rArchive folder is not accessible:`n`r"+$BaseDir+"\Archive.`n`rVerify that the folder exists and the SignatureAgent account has appropriate access permissions."
    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1004 -EntryType Error -Message $EvtMsg
    if ($Global:UseAdminEmail){
        $Subject = "Archive folder is not accessible"
        Shoot-AdminMail $Subject $EvtMsg
    }
    break
}
if(!(Test-Path $BaseDir\rejected)) {
    $EvtMsg = "Configuration Error!`n`r`n`rRejected folder is not accessible:`n`r"+$BaseDir+"\rejected.`n`rVerify that the folder exists and the SignatureAgent account has appropriate access permissions."
    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1005 -EntryType Error -Message $EvtMsg
    if ($Global:UseAdminEmail){
        $Subject = "Rejected folder is not accessible"
        Shoot-AdminMail $Subject $EvtMsg
    }
    break
}
if(!(Test-Path $BaseDir\failed)) {
    $EvtMsg = "Configuration Error!`n`r`n`rArchive folder is not accessible:`n`r"+$BaseDir+"\Archive.`n`rVerify that the folder exists and the SignatureAgent account has appropriate access permissions."
    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1004 -EntryType Error -Message $EvtMsg
    if ($Global:UseAdminEmail){
        $Subject = "Archive folder is not accessible"
        Shoot-AdminMail $Subject $EvtMsg
    }
    break
}


$InboxFiles = (dir ($BaseDir+"\inbox\*.ps*"))
$ApprovedFiles = (dir ($BaseDir+"\approved\*.ps*"))
$CodeSignCert = dir Cert:\LocalMachine\My -CodeSigningCert | where {$_.Thumbprint -eq $((Get-ItemProperty -Path $RegistryRoot -Name "CodeSignCertThumbprint").CodeSignCertThumbprint)}
#define empty array which will be filled with request objects
$ReqList = @()
[int]$CurrentRequestNo = 1    

#region verify if control file file already exist and read/import if so
if (Test-Path $CntlFile) {
    Compare-FileHash ((Get-FileHash -Path $CntlFile -Algorithm SHA256).hash)
    $ReqList = @(import-csv $CntlFile)
    if ( $ReqList.Length -gt 0 ) {
        [int]$CurrentRequestNo = [int](($ReqList |Select-Object -Last 1).RequestNo) + 1
    }
} else {
    If (Test-RegistryValue $RegistryRoot\ControlFile "CntlFileHash") {
        # no file but existing hash --> ControlFile was deleted
        $EvtMsg = "Control file has been deleted!`n`rVerify audit logs to detect who deleted this file!"
        Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1110 -EntryType Warning -Message $EvtMsg
        if ($Global:UseAdminEmail){
            $Subject = "Audit Error - ControlFile"
            Shoot-AdminMail $Subject $EvtMsg
        }
    }        
}
#endregion


#region if manual approval, process approved files first
if ( !$AutoApproval -and ($ApprovedFiles.length -gt 0) ) {
    foreach ( $ReqFile in $ApprovedFiles ) {
        $FoundObj = @()
        $SignObj = "" | select RequestNo,ReqFileName,SubmitDate,SignDate,SHA256FileHash,AutoApprove,Status

        $SignObj.SignDate = Get-Date
        $SignObj.SHA256FileHash = (Get-FileHash -Path $ReqFile.fullname -Algorithm SHA256).Hash
        $SignObj.Status = Sign-Code -SignFile $ReqFile -CertThumb $CodeSignCert

        # do we already have records with this hash?
        # if so, we take the last one when we find multiple
        [array]$FoundObj = ($ReqList | Where-Object {($_.SHA256FileHash -eq $SignObj.SHA256FileHash) -and ($_.Status -eq "PendingApproval")}) | Select-Object -Last 1
        if ( !$FoundObj ) {
            # new object - no previous record found
            $SignObj.RequestNo = $CurrentRequestNo++
            $SignObj.ReqFileName = $ReqFile.Name
            $SignObj.SubmitDate = $SignObj.SignDate
            $SignObj.AutoApprove = $AutoApproval
            $ReqList += $SignObj
        } else {
            # looking for the index of the original list
            $ArrPosition = Find-ArrayIndex -Array $ReqList -Value $FoundObj
            # updateing original record
            $ReqList[$ArrPosition].Status = $SignObj.Status
            $ReqList[$ArrPosition].SignDate = $SignObj.SignDate
        }

    }
}
#endregion


#region checking for known pending approval scripts
if (!$AutoApproval) {
    $PendList = $ReqList | Where-Object {$_.status -eq "PendingApproval"}
    foreach ( $entry in $PendList ) {
        $FoundObj = @()
        if( Test-Path ("$($BaseDir)\rejected\$($entry.ReqFileName)") ) {
            $Status = "Rejected"
        } elseif ( Test-Path ("$($BaseDir)\inbox\$($entry.ReqFileName)") ) {
            $Status = "PendingApproval"
<#        } elseif ( Test-Path ("$($BaseDir)\archive\$(($entry.ReqFileName -replace ".{4}$"))-org*") ) {
            $Status = "Unknown"
            $foundFiles = dir ("$($BaseDir)\archive\$(($entry.ReqFileName -replace ".{4}$"))-org*")
            foreach ( $file in $foundFiles ) {
                if ( ((Get-FileHash -Path $File.fullname -Algorithm SHA256).Hash) -eq $entry.SHA256FileHash) {
                    $Status = "Signed"
                }
            }
#>
        } else {
            $Status = "Unknown"
        }
        # do we need to update the records?
        # only required if rejected or unknown as "Signed" has been processed previously
        if ( (($Status -eq "Unknown") -or ($Status -eq "Rejected")) ) {
            # we need to update the original record
            # finding the original record
            # if we find multiple, we take the last one
            $FoundObj = ($ReqList | Where-Object {($_.SHA256FileHash -eq $entry.SHA256FileHash) -and ($_.Status -eq "PendingApproval")}) | Select-Object -Last 1
            # looking for the index of the original list
            $ArrPosition = Find-ArrayIndex -Array $ReqList -Value $FoundObj
            # update record
            $ReqList[$ArrPosition].Status = $Status
        }
    }
}
#endregion

#region submit single requests from inbox ...
foreach ( $ReqFile in $inboxfiles ) {
    $FoundObj = @()
    $SignResult = ""
    $SignObj = "" | select RequestNo,ReqFileName,SubmitDate,SignDate,SHA256FileHash,AutoApprove,Status

    $SignObj.ReqFileName = $ReqFile.Name
    $SignObj.SHA256FileHash = (Get-FileHash -Path $ReqFile.fullname -Algorithm SHA256).Hash
    $SignObj.SubmitDate = Get-Date
    $SignObj.AutoApprove = $AutoApproval
    if ( $AutoApproval ) {
        $SignObj.RequestNo = $CurrentRequestNo++
        $SignObj.Status = Sign-Code -SignFile $ReqFile -CertThumb $CodeSignCert
        $SignObj.SignDate = $SignObj.SubmitDate
        $ReqList += $SignObj
    } else {
        # do we already have records with this hash in pending state?
        # if so, we take the last one when we find multiple
        [array]$FoundObj = ($ReqList | Where-Object {($_.SHA256FileHash -eq $SignObj.SHA256FileHash) -and ($_.Status -eq "PendingApproval")}) | Select-Object -Last 1
        if ( !$FoundObj ) {
            # new object - no previous record found
            $SignObj.RequestNo = $CurrentRequestNo++
            $SignObj.Status = "PendingApproval"
            if ($Global:UseAdminEmail){
                $Subject = "Script is waiting for approval to be signed..."
                $EvtMsg = "Please manually verify and approve the following Script`r`n"+$ReqFile.fullname
                Shoot-AdminMail $Subject $EvtMsg
            }
            $EvtMsg = $SubmitEventMsg -replace "!REQName!",$ReqFile.fullname
            Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID $Global:SubmitEventID -EntryType Information -Message $EvtMsg
            
            $ReqList += $SignObj
        } else {
            # do nothing and wait for approval
        }
    }


}
#endregion

$ReqList | export-csv $CntlFile -NoTypeInformation -Force
Update-FileHash ((Get-FileHash -Path $CntlFile -Algorithm SHA256).hash)
