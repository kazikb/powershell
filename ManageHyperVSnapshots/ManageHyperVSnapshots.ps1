#Requires -RunAsAdministrator
#Requires -Modules Hyper-V

# The script contains collections of 4 functions to manage snapshots of several virtual machines at once.
# It is intended to use in a lab environment.
#
# Kazimierz Biskup
# https://github.com/kazikb/powershell

function Get-HVLabSnapshot {
    <#
    .SYNOPSIS
        Function that displays snapshots associated with a virtual machines.
    .EXAMPLE
        PS C:\> Get-HVLabSnapshot -VMName win-dc, win-srv
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String[]]$VMName
    )

    Get-VM $VMName | Get-VMSnapshot

}

function New-HVLabSnapshot {
    <#
    .SYNOPSIS
        Function to create snapshot of multiple virtual machines at once.
    .EXAMPLE
        PS C:\> New-HVLabSnapshot -VMName win-dc, win-srv
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String[]]$VMName,

        [String]$SnapshotName = "HVLab"
    )

    Stop-VM -Name $VMName
    Checkpoint-VM -Name $VMName -SnapshotName "$SnapshotName-$(Get-Date -UFormat "%d.%m.%Y %H:%M:%S")"
    Start-VM -Name $VMName

}

function Restore-HVLabSnapshot {
    <#
    .SYNOPSIS
        Function to restore snapshot of multiple virtual machines at once.
    .EXAMPLE
        PS C:\> Restore-HVLabSnapshot -VMName win-srv, win-dc -SnapshotName 'HVLab-19.02.2022 00:51:22'
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String[]]$VMName,

        [Parameter(Mandatory = $true)]
        [String]$SnapshotName
    )

    Stop-VM -Name $VMName
    Get-VM -Name $VMName | Foreach-Object { $_ | Get-VMSnapshot | Where-Object { $_.Name -eq $SnapshotName } | Restore-VMSnapshot -Confirm:$false }
    Start-VM -Name $VMName

}

function Remove-HVLabSnapshot {
    <#
    .SYNOPSIS
        Function to remove snapshot of multiple virtual machines at once.
    .EXAMPLE
        PS C:\> Remove-HVLabSnapshot -VMName win-srv, win-dc -SnapshotName 'HVLab-19.02.2022 00:51:22'
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String[]]$VMName,

        [Parameter(Mandatory = $true)]
        [String]$SnapshotName
    )

    Stop-VM -Name $VMName
    Get-VM -Name $VMName | Foreach-Object { $_ | Get-VMSnapshot | Where-Object { $_.Name -eq $SnapshotName } | Remove-VMSnapshot }
    Start-VM -Name $VMName

}
