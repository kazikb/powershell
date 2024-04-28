#Requires -RunAsAdministrator

<#
.SYNOPSIS

    Setup-WindowsLabHost.ps1 initial setup of a new Windows Server host in my lab.

.DESCRIPTION

    Primary purpose of this script is to install additional software on a fresh installed os.
    In the future, when the winget tool comes to the Windows server edition,
    I will replace the current direct download of installers with it

    List of software to install:
    - Npcap https://npcap.com/
    - Nmap https://nmap.org/
    - Wireshark https://www.wireshark.org/
    - Notepad++ https://notepad-plus-plus.org/
    - Git https://git-scm.com/
    - Mozilla Firefox https://www.mozilla.org/
    - WinDbg https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
    - HxD https://mh-nexus.de/en/hxd/
    - SysinternalsSuite https://learn.microsoft.com/en-us/sysinternals/

    KVM tools:
    - WinFSP https://winfsp.dev/
    - Virtio-Win-Guest-Tools https://github.com/virtio-win/virtio-win-guest-tools-installer

    VirtualBox tools:
    - Guest Additions https://www.virtualbox.org/

    Optionally, you can remove all inbound firewall rules except DHCP client in.

.PARAMETER Platform

    What virtualization platform used indicates additional tools to install (supported software KVM and VirtualBox).

.PARAMETER ClearInboundFwRules

    Clear all inbound firewall rules except "Core Networking - Dynamic Host Configuration Protocol (DHCP-In)".

.EXAMPLE

    PS C:\> Invoke-WebRequest -Uri https://raw.githubusercontent.com/kazikb/powershell/main/VirtualLab/Setup-WindowsLabHost.ps1 -OutFile "$env:USERPROFILE\Desktop\Setup-WindowsLabHost.ps1"
    PS C:\> .\Setup-WindowsLabHost.ps1

    Install all the software without virtualization platform tools (used on Hyper-V guest).

.EXAMPLE

    PS C:\> Invoke-WebRequest -Uri https://raw.githubusercontent.com/kazikb/powershell/main/VirtualLab/Setup-WindowsLabHost.ps1 -OutFile "$env:USERPROFILE\Desktop\Setup-WindowsLabHost.ps1"
    PS C:\> .\Setup-WindowsLabHost.ps1 -Platform Kvm -ClearInboundFwRules

    Install all the software and KVM platform guest tools. All inbound firewall rules will be removed except DHCP client in.

.EXAMPLE

    PS C:\> Invoke-WebRequest -Uri https://raw.githubusercontent.com/kazikb/powershell/main/VirtualLab/Setup-WindowsLabHost.ps1 -OutFile "$env:USERPROFILE\Desktop\Setup-WindowsLabHost.ps1"
    PS C:\> .\Setup-WindowsLabHost.ps1 -Platform VirtualBox

    Install all the software and VirtualBox platform guest tools.

.NOTES

    Kazimierz Biskup

.LINK

    https://github.com/kazikb/powershell

#>
param(
    [ValidateSet("Kvm","VirtualBox")]
    [string]$Platform,

    [Switch]$ClearInboundFwRules,

	[Switch]$SilentInstall
)

$SetupLocation = "C:\Inst"
if (-not (Test-Path $SetupLocation)) { New-Item $SetupLocation -ItemType Directory }

$SoftwareToInstall = [System.Collections.Generic.List[PSObject]]::New()

function Write-ConsoleMessage($Url, $Installer, $Message){
    $timestamp = Get-Date -uFormat "%d.%m.%Y %H:%M:%S"

    if ($Message -and -not $Url -and -not $Installer) {
        Write-Output "[!][$timestamp] $Message"
    } elseif ($Url -and $Installer) {
        Write-Output "[-][$timestamp] Download: $Url To: $Installer"
    } elseif ($Installer -and -not $Url) {
        Write-Output "[+][$timestamp] Install: $Installer"
    }
}

if ($Platform -eq 'Kvm') {
    Write-ConsoleMessage -Message "Virtualization Platform KVM"

    #region WinFSP
    $Resp = Invoke-RestMethod -Uri "https://api.github.com/repos/winfsp/winfsp/releases/latest"

    foreach ($item in $Resp.assets) {
        if ($item.browser_download_url -like "*.msi") {

            $InstallerPath = "$SetupLocation\$($item.browser_download_url.Split("/")[-1])"

            $SoftwareToInstall.Add([PSCustomObject]@{
                Name           = "WinFSP"
                DownloadLink   = $item.browser_download_url
                InstallerPath  = $InstallerPath
                ArgumentList   = @("/i",$InstallerPath,"/passive","/norestart")
                Msiexec        = $true
            })

            break
        }
    }
    #endregion WinFSP

    #region Virtio-Win-Guest-Tools
    Write-ConsoleMessage -Message "Setup Virtio-Win-Guest-Tools"

    # Redirect to actual stable version
    $Resp = Invoke-WebRequest -Method Head -Uri "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio" -UseBasicParsing
    if ($Resp.BaseResponse.ResponseUri.AbsoluteUri) {
        $FileName = "virtio-win-guest-tools.exe"
        $InstallerPath = "$SetupLocation\$FileName"
        $DownloadLink = $Resp.BaseResponse.ResponseUri.AbsoluteUri + $FileName

        Write-ConsoleMessage -Url $DownloadLink -Installer $InstallerPath
        Invoke-WebRequest -Uri $DownloadLink -OutFile $InstallerPath -UseBasicParsing

        if (Test-Path $InstallerPath) {
            Write-ConsoleMessage -Installer $InstallerPath
            Start-Process -FilePath $InstallerPath -ArgumentList "/install","/passive","/norestart" -Wait

            Write-ConsoleMessage -Message "Configure service VirtioFsSvc"
            sc.exe config VirtioFsSvc start=delayed-auto
            Start-Service VirtioFsSvc
        } else {
            Write-Error "Missing installer file: $InstallerPath"
        }
    }
    #endregion Virtio-Win-Guest-Tools

} elseif ($Platform -eq "VirtualBox") {

    Write-ConsoleMessage -Message "Virtualization Platform VirtualBox"
    Write-ConsoleMessage -Message "Setup VirtualBox Guest Additions"

    $CDRomDrive = (Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 5 }).DeviceID
    $InstallerPath = "$CDRomDrive\VBoxWindowsAdditions.exe"

    if (Test-path $InstallerPath) {

        Write-ConsoleMessage -Installer $InstallerPath
        Start-Process -FilePath "$CDRomDrive\cert\VBoxCertUtil.exe" -ArgumentList "add-trusted-publisher vbox*.cer","--root vbox*.cer" -Wait
        Start-Process -FilePath $InstallerPath -ArgumentList "/S" -Wait

    } else {
        Write-Error "Missing installer file: $InstallerPath"
    }
}

#region Nmap & Npcap
if (-not($SilentInstall)) {
	$Resp = Invoke-WebRequest "https://nmap.org/download.html" -UseBasicParsing
	$FileName = [regex]::Match($Resp.RawContent,"npcap-\d+\.\d+.exe").value
	$SoftwareToInstall.Add([PSCustomObject]@{
		Name           = "Npcap"
		DownloadLink   = "https://npcap.com/dist/$FileName"
		InstallerPath  = "$SetupLocation\$FileName"
		ArgumentList   = @()
		Msiexec        = $false
	})
}

$Resp = Invoke-WebRequest "https://nmap.org/download.html" -UseBasicParsing
$FileName = [regex]::Match($Resp.RawContent,"nmap-\d+\.\d+-setup.exe").value
$SoftwareToInstall.Add([PSCustomObject]@{
    Name           = "Nmap"
    DownloadLink   = "https://nmap.org/dist/$FileName"
    InstallerPath  = "$SetupLocation\$FileName"
    ArgumentList   = @("/S")
    Msiexec        = $false
})
#endregion Nmap & Npcap

#region Wireshark
$Resp = Invoke-WebRequest "https://www.wireshark.org/" -UseBasicParsing
$WiresharkReleaseVersion = [regex]::Match($Resp.RawContent, "Stable Release: \d+\.\d+\.\d+").value.split(" ")[-1]

$FileName = "Wireshark-$WiresharkReleaseVersion-x64.exe"
$SoftwareToInstall.Add([PSCustomObject]@{
    Name           = "Wireshark"
    DownloadLink   = [regex]::Match($Resp.RawContent, "https:\/\/.+\/win64/$FileName").value
    InstallerPath  = "$SetupLocation\$FileName"
    ArgumentList   = @("/S","/desktopicon=yes","/quicklaunchicon=yes")
    Msiexec        = $false
})
#endregion Wireshark

#region Notepad++
$Resp = Invoke-RestMethod -Uri "https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest"
foreach ($item in $Resp.assets) {
    if ($item.browser_download_url -like "*Installer.x64.exe") {
        $InstallerPath = "$SetupLocation\$($item.browser_download_url.Split("/")[-1])"

        $SoftwareToInstall.Add([PSCustomObject]@{
            Name           = "Notepad++"
            DownloadLink   = $item.browser_download_url
            InstallerPath  = "$SetupLocation\$($item.browser_download_url.Split("/")[-1])"
            ArgumentList   = @("/S" )
            Msiexec        = $false
        })
        break
    }
}
#endregion Notepad++

#region Git
# https://github.com/git-for-windows/git/wiki/Silent-or-Unattended-Installation
$Resp = Invoke-RestMethod -Uri "https://api.github.com/repos/git-for-windows/git/releases/latest"
foreach ($item in $Resp.assets) {
    if ($item.browser_download_url -like "*-64-bit.exe") {
        $InstallerPath = "$SetupLocation\$($item.browser_download_url.Split("/")[-1])"
        $GitInfPath = "$SetupLocation\git_options.ini"
        $GitInf = @"
[Setup]
Lang=default
Dir=C:\Program Files\Git
Group=Git
NoIcons=0
SetupType=default
Components=gitlfs,assoc,assoc_sh,windowsterminal
Tasks=
EditorOption=VIM
CustomEditorPath=
DefaultBranchOption=main
PathOption=Cmd
SSHOption=OpenSSH
TortoiseOption=false
CURLOption=WinSSL
CRLFOption=CRLFCommitAsIs
BashTerminalOption=MinTTY
GitPullBehaviorOption=Merge
UseCredentialManager=Enabled
PerformanceTweaksFSCache=Enabled
EnableSymlinks=Disabled
EnablePseudoConsoleSupport=Disabled
EnableFSMonitor=Disabled
"@
        $GitInf | Out-File -FilePath $GitInfPath

        $SoftwareToInstall.Add([PSCustomObject]@{
            Name           = "Git"
            DownloadLink   = $item.browser_download_url
            InstallerPath  = "$SetupLocation\$($item.browser_download_url.Split("/")[-1])"
            ArgumentList   = @("/VERYSILENT","/NORESTART","/NOCANCEL","/LOADINF=$GitInfPath")
            Msiexec        = $false
        })
        break
    }
}
#endregion Git

#region Mozilla Firefox
$SoftwareToInstall.Add([PSCustomObject]@{
    Name           = "Mozilla Firefox"
    DownloadLink   = "https://download.mozilla.org/?product=firefox-latest&os=win64"
    InstallerPath  = "$SetupLocation\FirefoxSetup.exe"
    ArgumentList   = @("/S")
    Msiexec        = $false
})
#endregion Mozilla Firefox

#region WinDbg
$SoftwareToInstall.Add([PSCustomObject]@{
    Name           = "WinDbg"
    DownloadLink   = "https://go.microsoft.com/fwlink/?linkid=2237387"
    InstallerPath  = "$SetupLocation\winsdksetup.exe"
    ArgumentList   = @("/features OptionId.WindowsDesktopDebuggers OptionId.WindowsPerformanceToolkit","/ceip off","/norestart", "/quiet")
    Msiexec        = $false
})
#endregion WinDbg

#region Download and Install Software
foreach ($Software in $SoftwareToInstall) {
    Write-ConsoleMessage -Message "Setup $($Software.Name)"
    Write-ConsoleMessage -Url $Software.DownloadLink -Installer $Software.InstallerPath
    Invoke-WebRequest -Uri $Software.DownloadLink -OutFile $Software.InstallerPath -UseBasicParsing

    if (Test-path $Software.InstallerPath) {

        Write-ConsoleMessage -Installer $Software.InstallerPath

        $CommandParam = @{
            Wait = $true
        }
        if ($Software.ArgumentList) { $CommandParam.Add("ArgumentList", $Software.ArgumentList) }
        if ($Software.Msiexec) { $CommandParam.Add("FilePath", "msiexec.exe") }
        else { $CommandParam.Add("FilePath", $Software.InstallerPath) }

        Start-Process @CommandParam

    } else {
        Write-Error "Missing installer file: $($Software.InstallerPath)"
    }
}
#endregion Download and Install Software

#region HxD
Write-ConsoleMessage -Message "Setup HxD"
$DownloadLink = "https://mh-nexus.de/downloads/HxDSetup.zip"
$ZipPath = "$SetupLocation\HxDSetup.zip"
$ZipExtractPath = "$SetupLocation\HxDSetup"
$InstallerPath = "$ZipExtractPath\HxDSetup.exe"

Write-ConsoleMessage -Url $DownloadLink -Installer $ZipPath
Invoke-WebRequest -Uri $DownloadLink -OutFile $ZipPath -UseBasicParsing

Write-ConsoleMessage -Message "Extract archive $ZipPath to $ZipExtractPath"
if (Test-Path $ZipExtractPath) { Remove-Item $ZipExtractPath -Recurse -Force }
New-Item $ZipExtractPath -ItemType Directory
Expand-Archive -Path $ZipPath -DestinationPath $ZipExtractPath

if ($InstallerPath) {
    Write-ConsoleMessage -Installer $InstallerPath
    Start-Process -FilePath $InstallerPath -ArgumentList "/SILENT","/NORESTART" -Wait
} else {
    Write-Error "Missing installer file: $InstallerPath"
}
#endregion HxD

#region SysinternalsSuite
Write-ConsoleMessage -Message "Setup Sysinternals"
$DownloadLink = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$ZipPath = "$SetupLocation\SysinternalsSuite.zip"
$ZipExtractPath = "$SetupLocation\SysinternalsSuite"
$SysinternalsPath = "C:\Program Files\SysinternalsSuite"

Write-ConsoleMessage -Url $DownloadLink -Installer $ZipPath
Invoke-WebRequest -Uri $DownloadLink -OutFile $ZipPath -UseBasicParsing

Write-ConsoleMessage -Message "Extract archive $ZipPath to $ZipExtractPath"
if (-not (Test-Path $ZipExtractPath)) { New-Item $ZipExtractPath -ItemType Directory }
Expand-Archive -Path $ZipPath -DestinationPath $ZipExtractPath

if (Test-Path $SysinternalsPath) { Remove-Item -Path $SysinternalsPath -Recurse -Force}
New-Item $SysinternalsPath -ItemType Directory
Move-Item "$ZipExtractPath\*" -Destination $SysinternalsPath

$SystemPath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($SystemPath.Split(";") -notcontains $SysinternalsPath) {
    Write-ConsoleMessage -Message "Add path: $SysinternalsPath to SYSTEM PATH"
    $SystemPath += ";$SysinternalsPath"
    [Environment]::SetEnvironmentVariable('Path', $SystemPath, 'Machine')
} else {
    Write-ConsoleMessage -Message "Path: $SysinternalsPath path is already present in SYSTEM PATH"
}

# https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbols
$SymbolsLocalPath = "c:\symbols"
Write-ConsoleMessage -Message "Setup symbols path: $SymbolsLocalPath"
if (-not (Test-Path $SymbolsLocalPath)) { New-Item $SymbolsLocalPath -ItemType Directory }
[Environment]::SetEnvironmentVariable('_NT_SYMBOL_PATH', "SRV*$SymbolsLocalPath*http://msdl.microsoft.com/download/symbols", 'Machine')
#endregion SysinternalsSuite

#region Firewall Rules
if ($ClearInboundFwRules) {
    Write-ConsoleMessage -Message "Remove unnecessary firewall inbound rules"
    Get-NetFirewallRule -Direction Inbound | Where-Object { $_.Name -ne "CoreNet-DHCP-In" } | Remove-NetFirewallRule
}
#endregion Firewall Rules
