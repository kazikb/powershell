<#
.SYNOPSIS

    Get-ServerInfo.ps1 allows you to collect information about remote computers using PowerShell Remoting.

.DESCRIPTION

    List of information collected by the script:
    - HostName
    - BIOS Version
    - Serial Number
    - OS
    - OS Version
    - Uptime Days
    - Uptime Weeks
    - Number of updates waitingo for install
    - Last update install date
    - Selected software version (if present) (Win32_Product is used to gather information)
    - Microsoft Defender basic information
    - CPU Name
    - Number of CPU
    - Total number of cores
    - Total number of logical processors
    - Total RAM in GB
    - Disk information where DriveType is "fixed" (free/total space)
    - Application log entry count from last 24h
    - System log entry count from last 24h

    The list of computers and software for which the version information is to be collected can be read from txt files.
    The script output can be automatically saved to a csv or json file.

.PARAMETER ComputerName

    List of computers from which information will be collected.

.PARAMETER InputFileComputerName

    A file containing a list of computers from which information will be collected (one value per line).

.PARAMETER ExcludeComputerName

    Parameter used with -InputFileComputerName to exclude individual computers without modifying the list contained in the specified file.

.PARAMETER SoftwareName

    List of software for which we want to determine the installed version (using information from Win32_Product class).
    The parameter supports wildcards, e.g.: "*SQL Server * Database Engine Services*".

.PARAMETER InputFileSoftwareName

    A file containing a list of software for which we want to check the installed version (one value per line).

.PARAMETER OutputFilePath

    The output file with the collected information. Default csv if -OutputFileFormat is omit.

.PARAMETER OutputFileFormat

    Type of ouput data json or csv.

.PARAMETER Credential

    Alternative credential to use with Invoke-Command.

.PARAMETER InvokeCommandThrottleLimit

    Invoke-Command ThrottleLimit.

.PARAMETER DebugMode

    Debug mode - commands on remote computers are executed in a loop one by one.

.EXAMPLE

    PS C:\> .\Get-ServerInfo.ps1 -ComputerName SERVER01,SERVER02 -SoftwareName "*Java*","*SQL Server * Database Engine Services*"

    Retrieve information about SERVER01 and SERVER02.
    In addition, information will be collected about the installed version of Java and MS SQL Server if such software is located on remote servers.

.EXAMPLE

    PS C:\> .\Get-ServerInfo.ps1 -InputFileComputerName .\hosts.txt -InputFileSoftwareName .\soft.txt -OutputFilePath .\ServerInfoOut.csv

    Collect information about remote computers, the list of which is located in the hosts.txt file.
    The list of software for which we want to determine what version is installed can be found in the soft.txt file.
    The output will be placed in the ServerInfoOut.csv file.

.EXAMPLE

    PS C:\> .\Get-ServerInfo.ps1 -ComputerName SERVER01,SERVER02 -Credential (Get-Credential)

    Retrieve information about SERVER01 and SERVER02 using alternate credentials

.NOTES

    Kazimierz Biskup

.LINK

    https://github.com/kazikb/powershell

#>
Param(
    [Parameter(Mandatory = $true,
        ParameterSetName = 'ComputerName')]
    [String[]]$ComputerName,

    [Parameter(Mandatory = $true,
        ParameterSetName = 'InputFileComputerName')]
    [ValidateScript({
            if (Test-Path $_ ) {
                $true
            }
            else {
                Throw "Invalid file"
            }
        })]
    [String]$InputFileComputerName,

    [Parameter(ParameterSetName = 'InputFileComputerName')]
    [String[]]$ExcludeComputerName,

    [String[]]$SoftwareName,

    [ValidateScript({
            if (Test-Path $_ ) {
                $true
            }
            else {
                Throw "Invalid file"
            }
        })]
    [String]$InputFileSoftwareName,

    [ValidateScript({
            if (Test-Path $_ -IsValid) {
                $true
            }
            else {
                Throw "Invalid path"
            }
        })]
    [String]$OutputFilePath,

    [ValidateSet("csv", "json")]
    [String]$OutputFileFormat = 'csv',

    [System.Management.Automation.PSCredential]$Credential,

    [Int]$InvokeCommandThrottleLimit = 32,

    [Switch]$DebugMode
)

#region Remote script
$RemoteServerInfoScript = {

    # Collecting basic system info
    $Win32ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $OSversion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Name ProductName).ProductName
    $Win32BIOS = Get-CimInstance Win32_BIOS

    # Collecting network interface info (excluding loopback i APIPA)
    $NetworkInterfaceOutput = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { ($_.IPAddress -notlike "127.*") -and ($_.IPAddress -notlike "169.254.*") } |
    Select-Object InterfaceAlias, IPAddress, PrefixLength

    $Win32Product = Get-CimInstance -ClassName Win32_Product
    $SoftwareInfoOutput = @()

    # Collecting software info
    foreach ($item in $Using:SoftwareName) {

        $SoftwareInfoOutput += $Win32Product | Where-Object { $_.name -like $item } | Select-Object Name, Version -Unique

    }

    # Checking how many Windows updates are waiting to install
    $objSession = New-Object -com "Microsoft.Update.Session"
    $objSearcher = $objSession.CreateUpdateSearcher()
    $results = $objSearcher.search("IsInstalled=0 and IsHidden=0")

    # Checking Windows Updates last install date
    $lastpatch = Get-CimInstance -ClassName Win32_Quickfixengineering |
    Select-Object @{Name = "InstalledOn"; Expression = { $_.InstalledOn -as [datetime] } } |
    Sort-Object -Property Installedon | select-object -property installedon -last 1

    $installedOnDate = Get-Date $lastpatch.InstalledOn -format dd-MM-yyyy

    # System uptime
    $Win32OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $UptimeDays = ((Get-Date) - $Win32OperatingSystem.LastBootUpTime).Days
    $UptimeWeeks = [Int](((Get-Date) - $Win32OperatingSystem.LastBootUpTime).Days / 7)

    # Collecting CPU info
    $Win32Processor = Get-CimInstance -ClassName Win32_Processor

    if ($Win32Processor.Count) {
        $CPUNumber = $Win32Processor.Count
        $CPUNumberOfCores = $Win32Processor.Count * $Win32Processor[0].NumberOfCores
        $CPUNumberOfLogicalProcessors = $Win32Processor.Count * $Win32Processor[0].NumberOfLogicalProcessors
    }
    else {
        $CPUNumber = 1
        $CPUNumberOfCores = $Win32Processor[0].NumberOfCores
        $CPUNumberOfLogicalProcessors = $Win32Processor[0].NumberOfLogicalProcessors
    }

    # Collecting volume info
    $VolumeInfo = Get-Volume
    $VolumeInfoOutput = @()

    foreach ($Volume in $VolumeInfo) {

        if (($Volume.DriveLetter) -and ($Volume.DriveType -eq 'Fixed')) {

            $VolumeInfoOutput += [PSCustomObject]@{
                DriveLetter   = $Volume.DriveLetter
                SizeRemaining = [Math]::Round($Volume.SizeRemaining / 1GB, 2)
                Size          = [Math]::Round($Volume.Size / 1GB, 2)
            }

        }
    }

    # Collecting info about Microsoft Defender (if Windows Server 2016 or newer)
    $OSBuildInfo = [System.Version]::Parse($Win32OperatingSystem.Version)

    if ($OSBuildInfo.Build -ge 14393) {

        $MSDefenderInfoOutput = Get-MpComputerStatus |
        Select-Object AMEngineVersion, AMProductVersion, AMRunningMode, AMServiceEnabled, AMServiceVersion, AntispywareEnabled,
        AntispywareSignatureLastUpdated, AntispywareSignatureVersion, AntivirusEnabled, AntivirusSignatureLastUpdated,
        AntivirusSignatureVersion, NISEnabled, NISSignatureLastUpdated, NISSignatureVersion

    }

    # Collecting information about number of events by type from last 24h
    # Application log
    $ApplicationLogEntry = Get-EventLog -LogName Application -After (Get-Date).AddDays(-1)
    $ApplicationLogEntryOutput = New-Object -TypeName PSCustomObject
    $EntryTypeList = $ApplicationLogEntry | Select-Object EntryType -Unique
    foreach ($item in $EntryTypeList.EntryType) {
        Add-Member -InputObject $ApplicationLogEntryOutput -MemberType NoteProperty -Name $item -Value 0
    }
    $ApplicationLogEntry | ForEach-Object { $ApplicationLogEntryOutput.($_.EntryType)++ }

    # System log
    $SystemLogEntry = Get-EventLog -LogName System -After (Get-Date).AddDays(-1)
    $SystemLogEntryOutput = New-Object -TypeName PSCustomObject
    $EntryTypeList = $SystemLogEntry | Select-Object EntryType -Unique
    foreach ($item in $EntryTypeList.EntryType) {
        Add-Member -InputObject $SystemLogEntryOutput -MemberType NoteProperty -Name $item -Value 0
    }
    $SystemLogEntry | ForEach-Object { $SystemLogEntryOutput.($_.EntryType)++ }

    [PSCustomObject]@{
        Name                                 = $Win32ComputerSystem.Name
        Model                                = $Win32ComputerSystem.Model
        SMBIOSBIOSVersion                    = $Win32BIOS.SMBIOSBIOSVersion
        SerialNumber                         = $Win32BIOS.SerialNumber
        OS                                   = $OSversion
        OS_Version                           = $Win32OperatingSystem.Version
        Uptime_Days                          = $UptimeDays
        Uptime_Weeks                         = $UptimeWeeks
        Updates                              = $results.updates.count
        Updates_Install_Date                 = $installedOnDate
        Network_Interface_Info               = $NetworkInterfaceOutput
        Software_Info                        = $SoftwareInfoOutput
        Microsoft_Defender_Info              = $MSDefenderInfoOutput
        CPU_Name                             = $Win32Processor[0].Name
        CPU_Number                           = $CPUNumber
        CPU_Number_Of_Cores                  = $CPUNumberOfCores
        CPU_Number_Of_Logical_Processors     = $CPUNumberOfLogicalProcessors
        Total_RAM_GB                         = [Math]::Round($Win32ComputerSystem.TotalPhysicalMemory / 1GB)
        Disk_Info_GB                         = $VolumeInfoOutput
        Application_Log_Entry_Count_Last_24h = $ApplicationLogEntryOutput
        System_Log_Entry_Count_Last_24h      = $SystemLogEntryOutput
    }

}
#endregion Remote script

#region Input validation
$OldErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Stop'

if ($PSCmdlet.ParameterSetName -eq 'InputFileComputerName') {

    $ComputerName = Get-Content -Path $InputFileComputerName -ErrorAction Stop | Where-Object { $_ -notin $ExcludeComputerName }

}

if ($OutputFilePath) {

    $OutputFolderPath = Split-Path $OutputFilePath -Parent
    if (-not (Test-Path $OutputFolderPath)) { New-Item -Path $OutputFolderPath -ItemType Directory -ErrorAction Stop }

}

if ($InputFileSoftwareName -and $SoftwareName) {

    Write-Error "Specify only one parameter -InputFileSoftwareName or -SoftwareName"
    exit 1

}
elseif ($InputFileSoftwareName) {

    $SoftwareName = Get-Content -Path $InputFileSoftwareName -ErrorAction Stop

}
$ErrorActionPreference = $OldErrorActionPreference
#endregion Input validation

Write-Verbose "[$(Get-Date -UFormat "%d.%m.%Y %H:%M:%S")] Server list [$($ComputerName.Length)]"
foreach ($cn in $ComputerName) {
    Write-Verbose $cn
}
Write-Verbose "[$(Get-Date -UFormat "%d.%m.%Y %H:%M:%S")] Start gathering data"

# In Debug mode, Invoke-Command runs on each host individually
if ($DebugMode) {

    $Result = @()
    foreach ($cn in $ComputerName) {

        Write-Output "[$(Get-Date -UFormat "%d.%m.%Y %H:%M:%S")][Debug] SERWER: $cn"
        $CommandParam = @{
            ComputerName = $cn
            ScriptBlock  = $RemoteServerInfoScript
        }
        if ($Credential) { $CommandParam.Add('Credential', $Credential) }

        $Result += Invoke-Command @CommandParam

    }

}
else {

    $CommandParam = @{
        ComputerName  = $ComputerName
        ScriptBlock   = $RemoteServerInfoScript
        ThrottleLimit = $InvokeCommandThrottleLimit
    }
    if ($Credential) { $CommandParam.Add('Credential', $Credential) }

    $Result = Invoke-Command @CommandParam

}

#region Output
Write-Verbose "[$(Get-Date -UFormat "%d.%m.%Y %H:%M:%S")] Generating output"

if ($OutputFilePath) {

    switch ($OutputFileFormat) {
        'csv' {

            # Exporting to csv requires rewriting the returned object so that you can specify the order of columns
            # and consolidate fields such as Network_Interface/Software_Info/Disk_Info_GB which contain lists of objects into one string
            $CsvOutput = [System.Collections.Generic.List[PSObject]]::New()
            $ObjectNotePropertyName = ($Result | Get-Member | Where-Object { ($_.MemberType -eq 'NoteProperty') -and
                ($_.Name -ne 'PSShowComputerName') -and ($_.Name -ne 'RunspaceId') -and ($_.Name -ne 'PSComputerName') }).Name

            foreach ($OutputInfo in $Result) {

                $CsvObject = [PSCustomObject]@{
                    Name                                 = ''
                    Model                                = ''
                    SMBIOSBIOSVersion                    = ''
                    SerialNumber                         = ''
                    OS                                   = ''
                    OS_Version                           = ''
                    Uptime_Days                          = ''
                    Uptime_Weeks                         = ''
                    Updates                              = ''
                    Updates_Install_Date                 = ''
                    Network_Interface_Info               = ''
                    Software_Info                        = ''
                    Microsoft_Defender_Info              = ''
                    CPU_Name                             = ''
                    CPU_Number                           = ''
                    CPU_Number_Of_Cores                  = ''
                    CPU_Number_Of_Logical_Processors     = ''
                    Total_RAM_GB                         = ''
                    Disk_Info_GB                         = ''
                    Application_Log_Entry_Count_Last_24h = ''
                    System_Log_Entry_Count_Last_24h      = ''
                }

                foreach ($ObjectNoteProperty in $ObjectNotePropertyName) {

                    $j = 1
                    $ObjectNotePropertyValue = ''

                    if (($ObjectNoteProperty -eq 'Network_Interface_Info') -or
                        ($ObjectNoteProperty -eq 'Software_Info') -or
                        ($ObjectNoteProperty -eq 'Disk_Info_GB')) {

                        foreach ($item in $OutputInfo.$ObjectNoteProperty) {
                            $ObjectNotePropertyValue += "[$j] $item `n"
                            $j++
                        }

                    }
                    else {
                        $ObjectNotePropertyValue = $OutputInfo.$ObjectNoteProperty
                    }

                    $CsvObject.$ObjectNoteProperty = $ObjectNotePropertyValue

                }
                $CsvOutput.add($CsvObject)

            }

            $CsvOutput | Export-Csv -Path $OutputFilePath -NoTypeInformation -Encoding UTF8 -Force

        }
        'json' {
            $Result | ConvertTo-Json | Out-File -FilePath $OutputFilePath -Encoding utf8 -Force
        }
        Default {}

    }

} else {
    Write-Output $Result
}
Write-Verbose "[$(Get-Date -UFormat "%d.%m.%Y %H:%M:%S")] Done"
#endregion Output
