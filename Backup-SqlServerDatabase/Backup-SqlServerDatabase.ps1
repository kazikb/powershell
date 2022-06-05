#Requires -Version 5.1
#Requires -Modules dbatools

<#
.SYNOPSIS

    A simple script to facilitate the backup of databases on the Express edition of the MSSQL Server.
    On full versions you should use builtin maintenance plans.
    The script is provided "as is" without any warranties and should not be used in production.
    In the case of a backup system, you should regularly test it and verify whether you can restore the backed up data.

.DESCRIPTION

    In order to backup databases located on an instance of MSSQL Express that does not have MSSQL Agent, the following script
    can imitate such functionality by calling it from the task scheduler. It uses a great PowerShell module "dbatools" to interact with the database engine.
    In order to establish a connection to the instance, integrated Windows login is used, so the account on which the task will be carried out
    must have permission to backup the listed databases ("db_backupoperator" and "public" User Mapping on a database) and "public" role to the instance itself.

    Sending e-mail notifications is carried out using the obsolete cmdlet "Send-MailMessage" and is intended to use the internal relay smtp server.

    Rotation of backup files should be thought out to allow data to be restored, especially in the case of differential backup,
    remember about the need to have the last full backup more info:
    https://docs.microsoft.com/en-us/sql/relational-databases/backup-restore/back-up-and-restore-of-sql-server-databases?view=sql-server-ver15

.PARAMETER SqlInstance

    The SQL Server instance hosting the databases to be backed up.

.PARAMETER Database

    The database(s) to backup.

.PARAMETER Type

    The type of SQL Server backup to perform. Accepted values are "Full" and "Differential".

.PARAMETER Path

    Path in which to place the backup files.

.PARAMETER NumberOfBackupsToKeep

    The number of backups to be kept. The oldest backup file of a given type exceeding this number will be deleted.

.PARAMETER SendMailNotification

    Enable email notifications. Requires additional parameters:
    -MailFrom
    -MailTo
    -MailSubject
    -SmtpServer
    -SmtpPort

.PARAMETER MailFrom

    Sender address.

.PARAMETER MailTo

    Recipient list.

.PARAMETER MailSubject

    Mail subject.

.PARAMETER SmtpServer

    SMTP server address.

.PARAMETER SmtpPort

    SMTP server port.

.EXAMPLE

    PS C:\> .\Backup-SqlServerDatabase.ps1 -SqlInstance 'WINSRV\SQLEXPRESS' -Database 'DemoDB','TestDB' -Path 'C:\BackupDB\' -NumberOfBackupsToKeep 10

    Full backup of DemoDB and TestDB databases to C:\BackupDB\. Backup files outside the latest 10 will be automatically deleted.

.EXAMPLE

    PS C:\> .\Backup-SqlServerDatabase.ps1 -SqlInstance 'WINSRV\SQLEXPRESS' -Database 'DemoDB','TestDB' -Path 'C:\BackupDB\' -NumberOfBackupsToKeep 10 -SendMailNotification -MailFrom 'winsrvdb@example.lan' -MailTo 'dbbackup@example.lan' -SmtpServer 'smtp.example.lan'

    Full backup of DemoDB and TestDB databases to C:\BackupDB\. Backup files outside the latest 10 will be automatically deleted.

.NOTES

    Kazimierz Biskup

.LINK

    https://github.com/kazikb/powershell
    https://dbatools.io/
    https://docs.microsoft.com/en-us/sql/relational-databases/backup-restore/back-up-and-restore-of-sql-server-databases?view=sql-server-ver15
    https://docs.microsoft.com/en-us/troubleshoot/sql/admin/schedule-automate-backup-database

#>
Param(
    [Parameter(Mandatory = $true)]
    [String]$SqlInstance,

    [Parameter(Mandatory = $true)]
    [String[]]$Database,

    [ValidateSet('Full', 'Differential')]
    [String]$Type = 'Full',

    [Parameter(Mandatory = $true)]
    [ValidateScript({
            if (Test-Path $_ -IsValid) {
                $true
            }
            else {
                Throw "Invalid path"
            }
        })]
    [String]$Path,

    [Int]$NumberOfBackupsToKeep,

    [Switch]$SendMailNotification,

    [String]$MailFrom,

    [String[]]$MailTo,

    [String]$MailSubject = "Backup-SqlServerDatabase.ps1 summary from $env:COMPUTERNAME",

    [String]$SmtpServer,

    [Int]$SmtpPort = 25
)

#region Notifications
$EmailMessageArray = [System.Collections.Generic.List[PSObject]]::New()

if ($SendMailNotification) {

    if ((-not $MailFrom) -or (-not $MailTo) -or (-not $MailSubject) -or (-not $SmtpServer) -or (-not $SmtpPort)) {

        Write-Error "Email notifications require the following parameters -MailFrom -MailTo -MailSubject -SmtpServer -SmtpPort"
        exit 1

    }
}
function Send-EmailAlert {
    Param (
        $IntEmailMessageArray
    )

    if (-not $SendMailNotification) { return }

    $IntBody = "<h1>Summary of MSSQL Server database backup from $env:COMPUTERNAME</h1>"

    foreach ($IntEmailMessag in $IntEmailMessageArray) {

        $IntBody += "<h3>$($IntEmailMessag.Section)</h3>"
        $IntBody += "<p>$($IntEmailMessag.LastError)</p>"

    }

    $CommandParam = @{
        From       = $MailFrom
        to         = $MailTo
        Subject    = $MailSubject
        Body       = $IntBody
        SmtpServer = $SmtpServer
        port       = $SmtpPort
        BodyAsHtml = $true
    }
    Send-MailMessage @CommandParam
    return
}
#endregion Notifications

# Test connection
try {
    Test-DbaConnection -SqlInstance $SqlInstance -EnableException -ErrorVariable LastError | Out-Null
}
catch {

    $Message = [PSCustomObject]@{
        Section   = "Connection to $SqlInstance failed"
        LastError = "$($LastError[0])`n$($LastError[-1])"
    }
    $EmailMessageArray.add($Message)

    Write-Error -Message $Message.Section
    Write-Error -Message $Message.LastError
    Send-EmailAlert -IntEmailMessageArray $EmailMessageArray
    exit 1

}

if (-not(Test-Path $Path)) { New-Item $Path -ItemType Directory }

# Backup database
foreach ($Db in $Database) {

    $BackupName = "$Type`_$DB"
    $FilePath = Join-Path -Path $Path -ChildPath "$BackupName`_$(Get-Date -UFormat "%Y%m%d%H%M").bak"

    try {

        $CommandParam = @{
            SqlInstance      = $SqlInstance
            Database         = $Db
            FilePath         = $FilePath
            Type             = $Type
            EnableException  = $true
            IgnoreFileChecks = $true
            ErrorVariable    = 'LastError'
        }
        Backup-DbaDatabase @CommandParam

        $Message = [PSCustomObject]@{
            Section   = "Backup database $Db successful"
            LastError = ''
        }
        $EmailMessageArray.add($Message)

    }
    catch {

        $Message = [PSCustomObject]@{
            Section   = "Backup database $Db failed"
            LastError = "$($LastError[0])`n$($LastError[-1])"
        }
        $EmailMessageArray.add($Message)

        Write-Error -Message $Message.Section
        Write-Error -Message $Message.LastError
        continue
    }

    # Remove old backup
    if ($NumberOfBackupsToKeep) {

        $DbBackupList = Get-ChildItem $Path | Where-Object { $_.Name -like "$BackupName*" }

        if ($DbBackupList.Count -gt $NumberOfBackupsToKeep) {

            $DbBackupList | Sort-Object LastWriteTime -Descending | Select-Object -Skip $NumberOfBackupsToKeep | Remove-Item -Force
        }

    }

}

Send-EmailAlert -IntEmailMessageArray $EmailMessageArray
