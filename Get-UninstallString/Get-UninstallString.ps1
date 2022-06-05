<#
.SYNOPSIS

    Simple script to get uninstlall string of installed applications.

.PARAMETER ComputerName

    List of computers from which information will be collected.

.PARAMETER SoftwareName

    List of software for which we want to get uninstall string.
    If not specified, the uninstall string will be returned for all applications.

.PARAMETER OutputFilePath

    The output csv file with the collected information.

.EXAMPLE

    PS C:\> .\Get-UninstallString.ps1 -SoftwareName 'Notepad++ (64-bit x64)','Microsoft Visual*'

.EXAMPLE

    PS C:\> .\Get-UninstallString.ps1 -ComputerName 'SRV01','SRV02' -SoftwareName 'Notepad++ (64-bit x64)','Microsoft Visual*'

.NOTES

    Kazimierz Biskup

.LINK

    https://github.com/kazikb/powershell

#>
Param(
    [String[]]$ComputerName,

    [String[]]$SoftwareName,

    [ValidateScript({
            if (Test-Path $_ -IsValid) {
                $true
            }
            else {
                Throw "Invalid path"
            }
        })]
    [String]$OutputFilePath
)

#region script block
$ScriptBlock = {

    Param(
        [String[]]$SoftwareName
    )

    $RegOutputInfo = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -Recurse

    $OutputInfo = @()

    foreach ($RegOutput in $RegOutputInfo) {

        $DisplayName = $RegOutput.GetValue("DisplayName")
        $UninstallString = $RegOutput.GetValue("UninstallString")

        if ($SoftwareName) {

            foreach ($item in $SoftwareName) {

                if ($DisplayName -like $item) {

                    $OutputInfo += [PSCustomObject]@{
                        DisplayName     = $DisplayName
                        UninstallString = $UninstallString
                    }

                }

            }

        }
        else {

            $OutputInfo += [PSCustomObject]@{
                DisplayName     = $DisplayName
                UninstallString = $UninstallString
            }

        }

    }

    Write-Output $OutputInfo

}
#endregion script block

$CommandParam = @{
    ScriptBlock = $ScriptBlock
}
if ($ComputerName) { $CommandParam.Add('ComputerName', $ComputerName) }
$Output = Invoke-Command @CommandParam -ArgumentList (,$SoftwareName) | Select-Object DisplayName,UninstallString,PSComputerName

if ($OutputFilePath) {
    $Output | Export-Csv -Path $OutputFilePath -NoTypeInformation -Encoding UTF8 -Force
}

Write-Output $Output
